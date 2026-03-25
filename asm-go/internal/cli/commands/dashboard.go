package commands

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/asm-tool/asm-go/internal/dashboard"
)

var (
	dashboardPort int
	dashboardHost string
)

// DashboardCmd creates the dashboard command
func DashboardCmd(deps *Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start the web dashboard server",
		Long:  "Start an HTTP server that serves the ASM dashboard for visualizing attack surface data.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDashboard(deps, dashboardHost, dashboardPort)
		},
	}

	cmd.Flags().IntVarP(&dashboardPort, "port", "p", 8080, "port to listen on")
	cmd.Flags().StringVar(&dashboardHost, "host", "127.0.0.1", "host to bind to")

	return cmd
}

func runDashboard(deps *Deps, host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Create router
	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("/", makeIndexHandler(deps))
	mux.HandleFunc("/domains", makeIndexHandler(deps))
	mux.HandleFunc("/domains/", makeDomainDetailHandler(deps))
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/stats", makeStatsHandler(deps))
	mux.HandleFunc("/partials/stats", makeStatsPartialHandler(deps))
	mux.HandleFunc("/partials/domains", makeDomainsPartialHandler(deps))

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

// getPageData fetches data from the database and returns PageData for templates
func getPageData(deps *Deps, activePage string) dashboard.PageData {
	data := dashboard.PageData{
		ActivePage: activePage,
	}

	// Get stats from database
	stats, err := deps.DB.GetStats()
	if err == nil {
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

	// Get finding counts
	findings, err := deps.DB.GetFindingSeverityCounts()
	if err == nil {
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

		if err := dashboard.RenderPage(w, "base", data); err != nil {
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
			rows, _ := deps.DB.GetAllSubdomains()
			for _, s := range rows {
				list.Subdomains = append(list.Subdomains, dashboard.SubdomainView{
					Subdomain:    s.Subdomain,
					DiscoveredAt: s.DiscoveredAt,
					LastSeen:     s.LastSeen,
				})
			}
		case "ports":
			rows, _ := deps.DB.GetAllPorts()
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
			rows, _ := deps.DB.GetAllCertificates()
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
			rows, _ := deps.DB.GetAllURLs()
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
			rows, _ := deps.DB.GetAllAPIs()
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
			rows, _ := deps.DB.GetAllEmails()
			for _, e := range rows {
				list.Emails = append(list.Emails, dashboard.EmailView{
					Address:      e.Address,
					Source:       e.Source,
					DiscoveredAt: e.DiscoveredAt,
				})
			}
		case "cloud":
			rows, _ := deps.DB.GetAllCloudStorage()
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
			rows, _ := deps.DB.GetAllFindings()
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
			rows, _ := deps.DB.GetAllTakeovers()
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func makeStatsHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		stats, err := deps.DB.GetStats()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		findings, _ := deps.DB.GetFindingSeverityCounts()

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
  "domains": %d,
  "subdomains": %d,
  "ports": %d,
  "certificates": %d,
  "urls": %d,
  "apis": %d,
  "emails": %d,
  "cloud_buckets": %d,
  "findings": {
    "total": %d,
    "critical": %d,
    "high": %d,
    "medium": %d,
    "low": %d,
    "info": %d
  },
  "takeovers": %d
}`,
			stats.Domains,
			stats.Subdomains,
			stats.Ports,
			stats.Certificates,
			stats.URLs,
			stats.APIs,
			stats.Emails,
			stats.CloudBuckets,
			findings.Critical+findings.High+findings.Medium+findings.Low+findings.Info,
			findings.Critical,
			findings.High,
			findings.Medium,
			findings.Low,
			findings.Info,
			stats.Takeovers)
	}
}

func makeDomainDetailHandler(deps *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract domain from URL path: /domains/{domain}
		path := r.URL.Path
		domain := strings.TrimPrefix(path, "/domains/")
		domain = strings.TrimSuffix(domain, "/")
		domain = strings.TrimSuffix(domain, "/refresh")

		if domain == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		data := getDomainDetailPageData(deps, domain)

		// Check if this is a refresh request (htmx partial)
		if strings.HasSuffix(r.URL.Path, "/refresh") {
			if err := dashboard.RenderPartial(w, "domain-detail-content", data); err != nil {
				http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Full page render
		if err := dashboard.RenderPage(w, "domain-base", data); err != nil {
			http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// getDomainDetailPageData fetches all domain-specific data for the detail view
func getDomainDetailPageData(deps *Deps, domainName string) dashboard.PageData {
	data := dashboard.PageData{
		ActivePage: "domains",
	}

	// Get domain info
	domain, err := deps.DB.Domains.GetByName(domainName)
	if err != nil {
		data.Error = "Domain not found"
		return data
	}

	// Initialize domain detail data
	detail := &dashboard.DomainDetailData{
		Domain:      domain.Domain,
		AddedAt:     domain.AddedAt,
		LastScanned: domain.LastScanned,
	}

	// Get stats
	stats, _ := deps.DB.GetDomainDetailStats(domainName)
	if stats != nil {
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

	// Get subdomains
	subs, _ := deps.DB.GetSubdomainsForDomain(domainName)
	detail.Subdomains = make([]dashboard.SubdomainView, len(subs))
	for i, s := range subs {
		detail.Subdomains[i] = dashboard.SubdomainView{
			Subdomain:    s.Subdomain,
			DiscoveredAt: s.DiscoveredAt,
			LastSeen:     s.LastSeen,
		}
	}

	// Get ports
	ports, _ := deps.DB.GetPortsForDomain(domainName)
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

	// Get certificates
	certs, _ := deps.DB.GetCertificatesForDomain(domainName)
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

	// Get technologies
	techs, _ := deps.DB.GetTechnologiesForDomain(domainName)
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

	// Get DNS records
	dns, _ := deps.DB.GetDNSRecordsForDomain(domainName)
	detail.DNSRecords = make([]dashboard.DNSRecordView, len(dns))
	for i, d := range dns {
		detail.DNSRecords[i] = dashboard.DNSRecordView{
			Domain:    d.Domain,
			Records:   d.Records,
			CheckedAt: d.CheckedAt,
		}
	}

	// Get findings/vulnerabilities
	findings, _ := deps.DB.GetVulnerabilitiesForDomain(domainName)
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

	// Get URLs
	urls, _ := deps.DB.GetURLsForDomain(domainName)
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

	// Get APIs
	apis, _ := deps.DB.GetAPIsForDomain(domainName)
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

	// Get emails
	emails, _ := deps.DB.GetEmailsForDomain(domainName)
	detail.Emails = make([]dashboard.EmailView, len(emails))
	for i, e := range emails {
		detail.Emails[i] = dashboard.EmailView{
			Address:      e.Address,
			Source:       e.Source,
			DiscoveredAt: e.DiscoveredAt,
		}
	}

	// Get cloud storage
	cloud, _ := deps.DB.GetCloudStorageForDomain(domainName)
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

	// Get takeovers
	takeovers, _ := deps.DB.GetTakeoversForDomain(domainName)
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

	// Get change events for this domain
	changes, _ := deps.DB.GetChangeEvents(domainName, 100)
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

	data.DomainDetail = detail
	return data
}
