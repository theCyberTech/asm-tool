package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	dashboardPort     int
	dashboardHost     string
	dashboardOpsToken string
)

type dashboardOptions struct {
	host  string
	port  int
	token string
}

type statsAPIResponse struct {
	Status string `json:"status"`
	dashboard.Stats
	Findings dashboard.FindingCounts `json:"findings"`
}

// DashboardCmd creates the dashboard command
func DashboardCmd(deps *Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start the web dashboard server",
		Long:  "Start an HTTP server that serves the ASM dashboard and Operations scan runner.",
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
	cmd.Flags().StringVar(&dashboardOpsToken, "ops-token", "", "Optional shared secret for Operations (ASM_DASHBOARD_TOKEN preferred)")

	return cmd
}

func resolveDashboardOptions(cmd *cobra.Command, deps *Deps) (dashboardOptions, error) {
	opts := dashboardOptions{
		host:  dashboardHost,
		port:  dashboardPort,
		token: dashboardOpsToken,
	}
	if deps != nil && deps.Cfg != nil {
		if !cmd.Flags().Changed("host") && deps.Cfg.Dashboard.Host != "" {
			opts.host = deps.Cfg.Dashboard.Host
		}
		if !cmd.Flags().Changed("port") && deps.Cfg.Dashboard.Port > 0 {
			opts.port = deps.Cfg.Dashboard.Port
		}
		if !cmd.Flags().Changed("ops-token") && strings.TrimSpace(opts.token) == "" {
			opts.token = deps.Cfg.Dashboard.Token
		}
	}
	opts.token = strings.TrimSpace(opts.token)
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

	ops := newDashboardOps(deps)
	ops.token = opts.token

	server := &http.Server{
		Addr:         addr,
		Handler:      newDashboardMux(deps, ops),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErrors := make(chan error, 1)

	go func() {
		serverErrors <- server.ListenAndServe()
	}()

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
	opsStatus := "enabled"
	if opts.token != "" {
		opsStatus = "enabled (token required)"
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

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			server.Close()
			return fmt.Errorf("shutdown error: %w", err)
		}
	}

	fmt.Println(labelStyle.Render("Server stopped"))
	return nil
}

func newDashboardMux(deps *Deps, ops *dashboardOps) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/stats", makeStatsHandler(deps))
	mux.HandleFunc("/api/overview", makeOverviewHandler(deps))
	mux.HandleFunc("/api/domains", makeDomainsJSONHandler(deps))
	mux.HandleFunc("/api/domains/", makeDomainAPIHandler(deps))
	mux.HandleFunc("/api/assets/", makeAssetsJSONHandler(deps))
	mux.HandleFunc("/api/operations", ops.handleOperationsJSON)
	mux.HandleFunc("/api/runs", ops.handleRunsJSON)
	mux.HandleFunc("/api/runs/start", ops.handleStartRun)
	mux.HandleFunc("/", dashboard.ServeSPA)

	return mux
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

		writeJSON(w, http.StatusOK, statsAPIResponse{
			Status:   "ok",
			Stats:    statsView(stats),
			Findings: findingCountsView(findings),
		})
	}
}
