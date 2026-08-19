package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/asm-tool/asm-go/internal/dashboard"
	"github.com/asm-tool/asm-go/internal/target"
)

var (
	dashboardPort      int
	dashboardHost      string
	dashboardEnableOps bool
	dashboardOpsToken  string
)

type dashboardOptions struct {
	host      string
	port      int
	enableOps bool
	token     string
}

// DashboardCmd creates the dashboard command
func DashboardCmd(deps *Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start the web dashboard server",
		Long:  "Start an HTTP server that serves the ASM dashboard for visualizing attack surface data.",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := resolveDashboardOptions(cmd, deps)
			if err != nil {
				return err
			}
			return runDashboard(deps, opts)
		},
	}

	cmd.Flags().IntVarP(&dashboardPort, "port", "p", 8080, "port to listen on")
	cmd.Flags().StringVar(&dashboardHost, "host", "127.0.0.1", "host to bind to")
	cmd.Flags().BoolVar(&dashboardEnableOps, "enable-ops", false, "Enable the Operations page and run API (disabled by default)")
	cmd.Flags().StringVar(&dashboardOpsToken, "ops-token", "", "Shared secret for Operations (ASM_DASHBOARD_TOKEN preferred)")

	return cmd
}

func resolveDashboardOptions(cmd *cobra.Command, deps *Deps) (dashboardOptions, error) {
	opts := dashboardOptions{
		host:      dashboardHost,
		port:      dashboardPort,
		enableOps: dashboardEnableOps,
		token:     dashboardOpsToken,
	}
	if deps != nil && deps.Cfg != nil {
		if !cmd.Flags().Changed("host") && deps.Cfg.Dashboard.Host != "" {
			opts.host = deps.Cfg.Dashboard.Host
		}
		if !cmd.Flags().Changed("port") && deps.Cfg.Dashboard.Port > 0 {
			opts.port = deps.Cfg.Dashboard.Port
		}
		if !cmd.Flags().Changed("enable-ops") {
			opts.enableOps = deps.Cfg.Dashboard.EnableOps
		}
		if !cmd.Flags().Changed("ops-token") && strings.TrimSpace(opts.token) == "" {
			opts.token = deps.Cfg.Dashboard.Token
		}
	}
	opts.token = strings.TrimSpace(opts.token)

	if opts.enableOps && !isLoopbackHost(opts.host) && opts.token == "" {
		return opts, fmt.Errorf("operations require a token when binding to %s; set ASM_DASHBOARD_TOKEN or --ops-token", opts.host)
	}
	return opts, nil
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func runDashboard(deps *Deps, opts dashboardOptions) error {
	addr, err := findAvailableAddr(opts.host, opts.port)
	if err != nil {
		return err
	}

	// Create router
	mux := http.NewServeMux()
	ops := newDashboardOps(deps)
	ops.enabled = opts.enableOps
	ops.token = opts.token

	// Register routes
	mux.HandleFunc("/", makeIndexHandler(deps))
	mux.HandleFunc("/domains", makeDomainsHandler(deps))
	mux.HandleFunc("/domains/", makeDomainDetailHandler(deps))
	mux.HandleFunc("/operations", makeOperationsHandler(deps, ops))
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/stats", makeStatsHandler(deps))
	mux.HandleFunc("/api/runs", ops.handleRunsJSON)
	mux.HandleFunc("/api/runs/start", ops.handleStartRun)
	mux.HandleFunc("/partials/stats", makeStatsPartialHandler(deps))
	mux.HandleFunc("/partials/domains", makeDomainsPartialHandler(deps))
	mux.HandleFunc("/partials/runs", ops.handleRunsPartial)

	// Asset list pages
	for _, route := range []struct{ path, page, title string }{
		{"/subdomains", "subdomains", "Subdomains"},
		{"/ports", "ports", "Open Ports"},
		{"/certificates", "certificates", "Certificates"},
		{"/urls", "urls", "URLs"},
		{"/apis", "apis", "API Endpoints"},
		{"/emails", "emails", "Email Addresses"},
		{"/cloud", "cloud", "Cloud Storage"},
		{"/findings", "findings", "Findings"},
		{"/takeovers", "takeovers", "Takeovers"},
	} {
		mux.HandleFunc(route.path, makeListHandler(deps, route.page, route.title))
	}

	// Create server
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for errors
	serverErrors := make(chan error, 1)

	// Start server
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	// Print startup message
	fmt.Println()
	fmt.Println(titleStyle.Render("ASM Dashboard"))
	fmt.Println()
	fmt.Printf("  %s %s\n",
		labelStyle.Render("Server:"),
		valueStyle.Render(fmt.Sprintf("http://%s", addr)))
	if addr != fmt.Sprintf("%s:%d", opts.host, opts.port) {
		fmt.Printf("  %s %s\n",
			labelStyle.Render("Note:"),
			valueStyle.Render(fmt.Sprintf("Port %d was in use, using %s instead", opts.port, addr)))
	}
	opsStatus := "disabled"
	if opts.enableOps {
		opsStatus = "enabled"
		if opts.token != "" {
			opsStatus = "enabled (token required)"
		}
	}
	fmt.Printf("  %s %s\n",
		labelStyle.Render("Operations:"),
		valueStyle.Render(opsStatus))
	fmt.Printf("  %s %s\n",
		labelStyle.Render("Status:"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("40")).Render("Running"))
	fmt.Println()
	fmt.Println(labelStyle.Render("Press Ctrl+C to stop"))
	fmt.Println()

	// Wait for interrupt signal or server error
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	case <-shutdown:
		fmt.Println()
		fmt.Println(labelStyle.Render("Shutting down..."))

		// Create context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			// Force close if graceful shutdown fails
			server.Close()
			return fmt.Errorf("shutdown error: %w", err)
		}
	}

	fmt.Println(labelStyle.Render("Server stopped"))
	return nil
}

// findAvailableAddr returns the address for the requested host and port.
// If the requested port is already in use, it scans upward for the next
// available port.
func findAvailableAddr(host string, port int) (string, error) {
	for p := port; p <= port+100; p++ {
		addr := fmt.Sprintf("%s:%d", host, p)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		ln.Close()
		return addr, nil
	}
	return "", fmt.Errorf("no available port found starting from %d", port)
}

// getPageData fetches data from the database and returns PageData for templates
func getPageData(deps *Deps, activePage string) dashboard.PageData {
	data := dashboard.PageData{
		ActivePage: activePage,
	}

	stats, err := deps.DB.GetStats()
	if err != nil {
		data.Warning = "Failed to load dashboard statistics"
	} else {
		data.Stats = dashboard.Stats{
			Domains:      stats.Domains,
			Subdomains:   stats.Subdomains,
			Ports:        stats.Ports,
			Certificates: stats.Certificates,
			URLs:         stats.URLs,
			APIs:         stats.APIs,
			Emails:       stats.Emails,
			CloudBuckets: stats.CloudBuckets,
			Takeovers:    stats.Takeovers,
		}
	}

	findings, err := deps.DB.GetFindingSeverityCounts()
	if err != nil {
		if data.Warning == "" {
			data.Warning = "Failed to load finding counts"
		}
	} else {
		data.Findings = dashboard.FindingCounts{
			Critical: findings.Critical,
			High:     findings.High,
			Medium:   findings.Medium,
			Low:      findings.Low,
			Info:     findings.Info,
			Total:    findings.Critical + findings.High + findings.Medium + findings.Low + findings.Info,
		}
	}

	// Get domains with stats for the landing page
	domains, err := deps.DB.GetDomainsWithStats()
	if err == nil {
		data.Domains = make([]dashboard.DomainStats, len(domains))
		for i, d := range domains {
			data.Domains[i] = dashboard.DomainStats{
				ID:             d.ID,
				Domain:         d.Domain,
				AddedAt:        d.AddedAt,
				LastScanned:    d.LastScanned,
				SubdomainCount: d.SubdomainCount,
				PortCount:      d.PortCount,
				CriticalCount:  d.CriticalCount,
				HighCount:      d.HighCount,
			}
		}
	}

	// Recent change events across all domains
	changes, err := deps.DB.GetChangeEvents("", 50)
	if err == nil {
		data.ChangeEvents = make([]dashboard.ChangeEventView, len(changes))
		for i, c := range changes {
			data.ChangeEvents[i] = dashboard.ChangeEventView{
				Domain:      c.Domain,
				ChangeType:  c.ChangeType,
				Severity:    c.Severity,
				Description: c.Description,
				OldValue:    c.OldValue,
				NewValue:    c.NewValue,
				Timestamp:   c.Timestamp,
			}
		}
	}

	return data
}

func makeIndexHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := getPageData(deps, "dashboard")
		if data.Warning != "" {
			data.Error = data.Warning
		}

		if err := dashboard.RenderPage(w, "base", data); err != nil {
			http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func makeDomainsHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domains" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := getPageData(deps, "domains")

		if err := dashboard.RenderPage(w, "domains-base", data); err != nil {
			http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func makeStatsPartialHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := getPageData(deps, "dashboard")

		if err := dashboard.RenderPartial(w, "stats-content", data); err != nil {
			http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func makeDomainsPartialHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// Parse query params for filtering
		query := r.URL.Query()
		searchTerm := strings.TrimSpace(query.Get("q"))
		dateFrom := query.Get("from")
		dateTo := query.Get("to")
		if dateFrom != "" {
			if _, err := time.Parse("2006-01-02", dateFrom); err != nil {
				http.Error(w, "invalid from date", http.StatusBadRequest)
				return
			}
		}
		if dateTo != "" {
			if _, err := time.Parse("2006-01-02", dateTo); err != nil {
				http.Error(w, "invalid to date", http.StatusBadRequest)
				return
			}
		}

		// Get all domains with stats
		domains, err := deps.DB.GetDomainsWithStats()
		if err != nil {
			http.Error(w, "Failed to get domains: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Apply filters
		filteredDomains := make([]dashboard.DomainStats, 0)
		for _, d := range domains {
			// Search filter (case-insensitive domain name match)
			if searchTerm != "" && !strings.Contains(strings.ToLower(d.Domain), strings.ToLower(searchTerm)) {
				continue
			}

			// Date from filter (scanned after)
			if dateFrom != "" && d.LastScanned != nil {
				fromDate, err := time.Parse("2006-01-02", dateFrom)
				if err == nil && d.LastScanned.Before(fromDate) {
					continue
				}
			}

			// Date to filter (scanned before)
			if dateTo != "" && d.LastScanned != nil {
				toDate, err := time.Parse("2006-01-02", dateTo)
				if err == nil && d.LastScanned.After(toDate.Add(24*time.Hour)) {
					continue
				}
			}

			// If no LastScanned and date filters are set, skip domains that have never been scanned
			if (dateFrom != "" || dateTo != "") && d.LastScanned == nil {
				continue
			}

			filteredDomains = append(filteredDomains, dashboard.DomainStats{
				ID:             d.ID,
				Domain:         d.Domain,
				AddedAt:        d.AddedAt,
				LastScanned:    d.LastScanned,
				SubdomainCount: d.SubdomainCount,
				PortCount:      d.PortCount,
				CriticalCount:  d.CriticalCount,
				HighCount:      d.HighCount,
			})
		}

		data := dashboard.PageData{
			Domains: filteredDomains,
		}

		if err := dashboard.RenderPartial(w, "domains-table-rows", data); err != nil {
			http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func makeListHandler(deps *Deps, activePage, title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := getPageData(deps, activePage)
		list := &dashboard.GlobalListData{Title: title}

		switch activePage {
		case "subdomains":
			rows, err := deps.DB.GetAllSubdomains()
			if err != nil {
				http.Error(w, "Failed to load subdomains: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, s := range rows {
				list.Subdomains = append(list.Subdomains, dashboard.SubdomainView{
					Subdomain:    s.Subdomain,
					DiscoveredAt: s.DiscoveredAt,
					LastSeen:     s.LastSeen,
				})
			}
		case "ports":
			rows, err := deps.DB.GetAllPorts()
			if err != nil {
				http.Error(w, "Failed to load ports: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, p := range rows {
				list.Ports = append(list.Ports, dashboard.PortView{
					Host:         p.Host,
					Port:         p.Port,
					Protocol:     p.Protocol,
					Service:      p.Service,
					Version:      p.Version,
					Banner:       p.Banner,
					State:        p.State,
					DiscoveredAt: p.DiscoveredAt,
				})
			}
		case "certificates":
			rows, err := deps.DB.GetAllCertificates()
			if err != nil {
				http.Error(w, "Failed to load certificates: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, c := range rows {
				list.Certificates = append(list.Certificates, dashboard.CertificateView{
					Host:            c.Host,
					Port:            c.Port,
					Subject:         c.Subject,
					Issuer:          c.Issuer,
					NotAfter:        c.NotAfter,
					DaysUntilExpiry: c.DaysUntilExpiry,
					SAN:             c.SAN,
				})
			}
		case "urls":
			rows, err := deps.DB.GetAllURLs()
			if err != nil {
				http.Error(w, "Failed to load URLs: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, u := range rows {
				list.URLs = append(list.URLs, dashboard.URLView{
					URL:          u.URL,
					Domain:       u.Domain,
					Category:     u.Category,
					Interesting:  u.Interesting > 0,
					Source:       u.Source,
					DiscoveredAt: u.DiscoveredAt,
				})
			}
		case "apis":
			rows, err := deps.DB.GetAllAPIs()
			if err != nil {
				http.Error(w, "Failed to load APIs: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, a := range rows {
				list.APIs = append(list.APIs, dashboard.APIView{
					URL:          a.URL,
					Type:         a.Type,
					Title:        a.Title,
					Version:      a.Version,
					DiscoveredAt: a.DiscoveredAt,
				})
			}
		case "emails":
			rows, err := deps.DB.GetAllEmails()
			if err != nil {
				http.Error(w, "Failed to load emails: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, e := range rows {
				list.Emails = append(list.Emails, dashboard.EmailView{
					Address:      e.Address,
					Source:       e.Source,
					DiscoveredAt: e.DiscoveredAt,
				})
			}
		case "cloud":
			rows, err := deps.DB.GetAllCloudStorage()
			if err != nil {
				http.Error(w, "Failed to load cloud storage: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, c := range rows {
				list.CloudStorage = append(list.CloudStorage, dashboard.CloudStorageView{
					Provider:    c.Provider,
					BucketName:  c.BucketName,
					URL:         c.URL,
					AccessLevel: c.AccessLevel,
					Severity:    c.Severity,
					Evidence:    c.Evidence,
					Status:      c.Status,
				})
			}
		case "findings":
			rows, err := deps.DB.GetAllFindings()
			if err != nil {
				http.Error(w, "Failed to load findings: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, f := range rows {
				list.Findings = append(list.Findings, dashboard.FindingView{
					ID:           f.ID,
					Name:         f.Name,
					Severity:     f.Severity,
					Description:  f.Description,
					Host:         f.Host,
					MatchedAt:    f.MatchedAt,
					Tags:         f.Tags,
					DiscoveredAt: f.DiscoveredAt,
				})
			}
		case "takeovers":
			rows, err := deps.DB.GetAllTakeovers()
			if err != nil {
				http.Error(w, "Failed to load takeovers: "+err.Error(), http.StatusInternalServerError)
				return
			}
			for _, t := range rows {
				list.Takeovers = append(list.Takeovers, dashboard.TakeoverView{
					Subdomain:    t.Subdomain,
					CNAME:        t.CNAME,
					Service:      t.Service,
					TakeoverType: t.TakeoverType,
					Confidence:   t.Confidence,
					Evidence:     t.Evidence,
					DiscoveredAt: t.DiscoveredAt,
				})
			}
		}

		data.GlobalList = list
		if err := dashboard.RenderPage(w, "list-base", data); err != nil {
			http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"status":"error","message":"failed to encode response"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func makeStatsHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := deps.DB.GetStats()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "failed to load stats",
			})
			return
		}

		findings, err := deps.DB.GetFindingSeverityCounts()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"status":  "error",
				"message": "failed to load finding counts",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":        "ok",
			"domains":       stats.Domains,
			"subdomains":    stats.Subdomains,
			"ports":         stats.Ports,
			"certificates":  stats.Certificates,
			"urls":          stats.URLs,
			"apis":          stats.APIs,
			"emails":        stats.Emails,
			"cloud_buckets": stats.CloudBuckets,
			"findings": map[string]int{
				"total":    findings.Critical + findings.High + findings.Medium + findings.Low + findings.Info,
				"critical": findings.Critical,
				"high":     findings.High,
				"medium":   findings.Medium,
				"low":      findings.Low,
				"info":     findings.Info,
			},
			"takeovers": stats.Takeovers,
		})
	}
}

const (
	domainDetailPreviewLimit = 25
	domainModalURLLimit      = 500
)

var domainModalTemplates = map[string]string{
	"subdomains":      "subdomains-modal-body",
	"ports":           "ports-modal-body",
	"certificates":    "certificates-modal-body",
	"technologies":    "technologies-modal-body",
	"dns":             "dns-modal-body",
	"vulnerabilities": "vulnerabilities-modal-body",
	"urls":            "urls-modal-body",
	"apis":            "apis-modal-body",
	"emails":          "emails-modal-body",
	"cloud":           "cloud-modal-body",
	"takeovers":       "takeovers-modal-body",
}

type domainDetailRoute struct {
	domain string
	action string // "", "refresh", or a modal kind
}

func parseDomainDetailPath(path string) (domainDetailRoute, bool) {
	rest := strings.Trim(strings.TrimPrefix(path, "/domains/"), "/")
	if rest == "" {
		return domainDetailRoute{}, false
	}
	parts := strings.Split(rest, "/")
	switch len(parts) {
	case 1:
		return domainDetailRoute{domain: parts[0]}, true
	case 2:
		if parts[1] == "refresh" {
			return domainDetailRoute{domain: parts[0], action: "refresh"}, true
		}
		if parts[1] == "host" {
			return domainDetailRoute{domain: parts[0], action: "host"}, true
		}
	case 3:
		if parts[1] == "modal" {
			if _, ok := domainModalTemplates[parts[2]]; ok {
				return domainDetailRoute{domain: parts[0], action: parts[2]}, true
			}
		}
	}
	return domainDetailRoute{}, false
}

func makeDomainDetailHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		route, ok := parseDomainDetailPath(r.URL.Path)
		if !ok {
			if strings.Trim(strings.TrimPrefix(r.URL.Path, "/domains/"), "/") == "" {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			http.NotFound(w, r)
			return
		}

		decoded, err := url.PathUnescape(route.domain)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		normalized, err := target.NormalizeTarget(decoded)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		switch {
		case route.action == "":
			data := loadDomainDetailPageData(deps, normalized, "", domainDetailPreviewLimit, domainDetailPreviewLimit)
			if err := dashboard.RenderPage(w, "domain-base", data); err != nil {
				http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			}
		case route.action == "refresh":
			data := loadDomainDetailPageData(deps, normalized, "", domainDetailPreviewLimit, domainDetailPreviewLimit)
			if err := dashboard.RenderPartial(w, "domain-detail-content", data); err != nil {
				http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			}
		case route.action == "host":
			host := target.NormalizeSubdomain(r.URL.Query().Get("name"), normalized)
			if host == "" {
				http.NotFound(w, r)
				return
			}
			data := loadHostDetailPageData(deps, normalized, host)
			if data.Error != "" || data.DomainDetail == nil {
				http.NotFound(w, r)
				return
			}
			if err := dashboard.RenderPartial(w, "host-modal-body", data); err != nil {
				http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			}
		default:
			urlLimit := 0
			if route.action == "urls" {
				urlLimit = domainModalURLLimit
			}
			data := loadDomainDetailPageData(deps, normalized, route.action, 0, urlLimit)
			if data.Error != "" || data.DomainDetail == nil {
				http.NotFound(w, r)
				return
			}
			if err := dashboard.RenderPartial(w, domainModalTemplates[route.action], data); err != nil {
				http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func wantDomainAsset(only, kind string) bool {
	return only == "" || only == kind
}

func previewList[T any](items []T, n int) []T {
	if n <= 0 || len(items) <= n {
		return items
	}
	return items[:n]
}

func addPageWarning(data *dashboard.PageData, msg string) {
	if data.Warning == "" {
		data.Warning = msg
		return
	}
	data.Warning += "; " + msg
}

// loadDomainDetailPageData fetches domain-specific data for the detail view or one modal.
// only limits loading to a single asset kind (empty means all). previewLimit slices
// inline tables; urlLimit caps URL queries (0 means no SQL limit).
func loadDomainDetailPageData(deps *Deps, domainName, only string, previewLimit, urlLimit int) dashboard.PageData {
	data := dashboard.PageData{
		ActivePage: "domains",
	}

	domain, err := deps.DB.Domains.GetByName(domainName)
	if err != nil {
		data.Error = "Domain not found"
		return data
	}

	detail := &dashboard.DomainDetailData{
		Domain:      domain.Domain,
		AddedAt:     domain.AddedAt,
		LastScanned: domain.LastScanned,
	}

	stats, err := deps.DB.GetDomainDetailStats(domainName)
	if err != nil {
		addPageWarning(&data, "Failed to load domain statistics")
	} else if stats != nil {
		detail.Stats = dashboard.DomainDetailStats{
			SubdomainCount:   stats.SubdomainCount,
			PortCount:        stats.PortCount,
			CertificateCount: stats.CertificateCount,
			TechnologyCount:  stats.TechnologyCount,
			DNSRecordCount:   stats.DNSRecordCount,
			VulnCount:        stats.VulnCount,
			URLCount:         stats.URLCount,
			APICount:         stats.APICount,
			EmailCount:       stats.EmailCount,
			CloudCount:       stats.CloudCount,
			TakeoverCount:    stats.TakeoverCount,
		}
	}

	if wantDomainAsset(only, "subdomains") {
		subs, err := deps.DB.GetSubdomainsForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load subdomains")
		} else {
			detail.Subdomains = make([]dashboard.SubdomainView, len(subs))
			for i, s := range subs {
				detail.Subdomains[i] = dashboard.SubdomainView{
					Subdomain:    s.Subdomain,
					DiscoveredAt: s.DiscoveredAt,
					LastSeen:     s.LastSeen,
				}
			}
			detail.Subdomains = previewList(detail.Subdomains, previewLimit)
		}
	}

	if wantDomainAsset(only, "ports") {
		ports, err := deps.DB.GetPortsForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load open ports")
		} else {
			detail.Ports = make([]dashboard.PortView, len(ports))
			for i, p := range ports {
				detail.Ports[i] = dashboard.PortView{
					Host:         p.Host,
					Port:         p.Port,
					Protocol:     p.Protocol,
					Service:      p.Service,
					Version:      p.Version,
					Product:      p.Product,
					State:        p.State,
					Banner:       p.Banner,
					DiscoveredAt: p.DiscoveredAt,
				}
			}
			detail.Ports = previewList(detail.Ports, previewLimit)
		}
	}

	if wantDomainAsset(only, "certificates") {
		certs, err := deps.DB.GetCertificatesForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load certificates")
		} else {
			detail.Certificates = make([]dashboard.CertificateView, len(certs))
			for i, c := range certs {
				detail.Certificates[i] = dashboard.CertificateView{
					Host:            c.Host,
					Port:            c.Port,
					Subject:         c.Subject,
					Issuer:          c.Issuer,
					NotAfter:        c.NotAfter,
					DaysUntilExpiry: c.DaysUntilExpiry,
					SAN:             c.SAN,
				}
			}
			detail.Certificates = previewList(detail.Certificates, previewLimit)
		}
	}

	if wantDomainAsset(only, "technologies") {
		techs, err := deps.DB.GetTechnologiesForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load technologies")
		} else {
			detail.Technologies = make([]dashboard.TechnologyView, len(techs))
			for i, t := range techs {
				detail.Technologies[i] = dashboard.TechnologyView{
					Host:         t.Host,
					StatusCode:   t.StatusCode,
					Title:        t.Title,
					Server:       t.Server,
					Technologies: t.Technologies,
					CheckedAt:    t.CheckedAt,
				}
			}
			detail.Technologies = previewList(detail.Technologies, previewLimit)
		}
	}

	if wantDomainAsset(only, "dns") {
		dns, err := deps.DB.GetDNSRecordsForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load DNS records")
		} else {
			detail.DNSRecords = make([]dashboard.DNSRecordView, len(dns))
			for i, d := range dns {
				detail.DNSRecords[i] = dashboard.DNSRecordView{
					Domain:    d.Domain,
					Records:   d.Records,
					CheckedAt: d.CheckedAt,
				}
			}
			detail.DNSRecords = previewList(detail.DNSRecords, previewLimit)
		}
	}

	if wantDomainAsset(only, "vulnerabilities") {
		findings, err := deps.DB.GetVulnerabilitiesForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load vulnerabilities")
		} else {
			detail.Findings = make([]dashboard.FindingView, len(findings))
			for i, f := range findings {
				detail.Findings[i] = dashboard.FindingView{
					ID:           f.ID,
					Name:         f.Name,
					Severity:     f.Severity,
					Description:  f.Description,
					Host:         f.Host,
					MatchedAt:    f.MatchedAt,
					Tags:         f.Tags,
					DiscoveredAt: f.DiscoveredAt,
				}
			}
			detail.Findings = previewList(detail.Findings, previewLimit)
		}
	}

	if wantDomainAsset(only, "urls") {
		urls, err := deps.DB.GetURLsForDomainLimit(domainName, urlLimit)
		if err != nil {
			addPageWarning(&data, "Failed to load URLs")
		} else {
			detail.URLs = make([]dashboard.URLView, len(urls))
			for i, u := range urls {
				detail.URLs[i] = dashboard.URLView{
					URL:          u.URL,
					Domain:       u.Domain,
					Category:     u.Category,
					Interesting:  u.Interesting > 0,
					Source:       u.Source,
					DiscoveredAt: u.DiscoveredAt,
				}
			}
			detail.URLs = previewList(detail.URLs, previewLimit)
		}
	}

	if wantDomainAsset(only, "apis") {
		apis, err := deps.DB.GetAPIsForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load APIs")
		} else {
			detail.APIs = make([]dashboard.APIView, len(apis))
			for i, a := range apis {
				detail.APIs[i] = dashboard.APIView{
					URL:          a.URL,
					Type:         a.Type,
					Title:        a.Title,
					Version:      a.Version,
					DiscoveredAt: a.DiscoveredAt,
				}
			}
			detail.APIs = previewList(detail.APIs, previewLimit)
		}
	}

	if wantDomainAsset(only, "emails") {
		emails, err := deps.DB.GetEmailsForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load emails")
		} else {
			detail.Emails = make([]dashboard.EmailView, len(emails))
			for i, e := range emails {
				detail.Emails[i] = dashboard.EmailView{
					Address:      e.Address,
					Source:       e.Source,
					DiscoveredAt: e.DiscoveredAt,
				}
			}
			detail.Emails = previewList(detail.Emails, previewLimit)
		}
	}

	if wantDomainAsset(only, "cloud") {
		cloud, err := deps.DB.GetCloudStorageForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load cloud storage")
		} else {
			detail.CloudStorage = make([]dashboard.CloudStorageView, len(cloud))
			for i, c := range cloud {
				detail.CloudStorage[i] = dashboard.CloudStorageView{
					Provider:    c.Provider,
					BucketName:  c.BucketName,
					URL:         c.URL,
					AccessLevel: c.AccessLevel,
					Severity:    c.Severity,
					Evidence:    c.Evidence,
					Status:      c.Status,
				}
			}
			detail.CloudStorage = previewList(detail.CloudStorage, previewLimit)
		}
	}

	if wantDomainAsset(only, "takeovers") {
		takeovers, err := deps.DB.GetTakeoversForDomain(domainName)
		if err != nil {
			addPageWarning(&data, "Failed to load takeovers")
		} else {
			detail.Takeovers = make([]dashboard.TakeoverView, len(takeovers))
			for i, t := range takeovers {
				detail.Takeovers[i] = dashboard.TakeoverView{
					Subdomain:    t.Subdomain,
					CNAME:        t.CNAME,
					Service:      t.Service,
					TakeoverType: t.TakeoverType,
					Confidence:   t.Confidence,
					Evidence:     t.Evidence,
					DiscoveredAt: t.DiscoveredAt,
				}
			}
			detail.Takeovers = previewList(detail.Takeovers, previewLimit)
		}
	}

	if only == "" {
		changes, err := deps.DB.GetChangeEvents(domainName, 100)
		if err != nil {
			addPageWarning(&data, "Failed to load change events")
		} else {
			detail.ChangeEvents = make([]dashboard.ChangeEventView, len(changes))
			for i, c := range changes {
				detail.ChangeEvents[i] = dashboard.ChangeEventView{
					Domain:      c.Domain,
					ChangeType:  c.ChangeType,
					Severity:    c.Severity,
					Description: c.Description,
					OldValue:    c.OldValue,
					NewValue:    c.NewValue,
					Timestamp:   c.Timestamp,
				}
			}
		}
	}

	data.DomainDetail = detail
	return data
}

func loadHostDetailPageData(deps *Deps, domainName, host string) dashboard.PageData {
	data := dashboard.PageData{
		ActivePage: "domains",
	}

	domain, err := deps.DB.Domains.GetByName(domainName)
	if err != nil {
		data.Error = "Domain not found"
		return data
	}

	detail := &dashboard.DomainDetailData{
		Domain:       domain.Domain,
		AddedAt:      domain.AddedAt,
		LastScanned:  domain.LastScanned,
		SelectedHost: host,
	}

	ports, err := deps.DB.GetPortsForHost(host)
	if err != nil {
		addPageWarning(&data, "Failed to load open ports")
	} else {
		detail.Ports = make([]dashboard.PortView, len(ports))
		for i, p := range ports {
			detail.Ports[i] = dashboard.PortView{
				Host:         p.Host,
				Port:         p.Port,
				Protocol:     p.Protocol,
				Service:      p.Service,
				Version:      p.Version,
				Product:      p.Product,
				State:        p.State,
				Banner:       p.Banner,
				DiscoveredAt: p.DiscoveredAt,
			}
		}
	}

	certs, err := deps.DB.GetCertificatesForHost(host)
	if err != nil {
		addPageWarning(&data, "Failed to load certificates")
	} else {
		detail.Certificates = make([]dashboard.CertificateView, len(certs))
		for i, c := range certs {
			detail.Certificates[i] = dashboard.CertificateView{
				Host:            c.Host,
				Port:            c.Port,
				Subject:         c.Subject,
				Issuer:          c.Issuer,
				NotAfter:        c.NotAfter,
				DaysUntilExpiry: c.DaysUntilExpiry,
				SAN:             c.SAN,
			}
		}
	}

	techs, err := deps.DB.GetTechnologiesForHost(host)
	if err != nil {
		addPageWarning(&data, "Failed to load technologies")
	} else {
		detail.Technologies = make([]dashboard.TechnologyView, len(techs))
		for i, t := range techs {
			detail.Technologies[i] = dashboard.TechnologyView{
				Host:         t.Host,
				StatusCode:   t.StatusCode,
				Title:        t.Title,
				Server:       t.Server,
				Technologies: t.Technologies,
				CheckedAt:    t.CheckedAt,
			}
		}
	}

	dns, err := deps.DB.GetDNSRecordsForHost(host)
	if err != nil {
		addPageWarning(&data, "Failed to load DNS records")
	} else {
		detail.DNSRecords = make([]dashboard.DNSRecordView, len(dns))
		for i, d := range dns {
			detail.DNSRecords[i] = dashboard.DNSRecordView{
				Domain:    d.Domain,
				Records:   d.Records,
				CheckedAt: d.CheckedAt,
			}
		}
	}

	data.DomainDetail = detail
	return data
}
