package commands

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
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
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/stats", makeStatsHandler(deps))

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

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>ASM Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0d1117; color: #c9d1d9; }
        h1 { color: #58a6ff; }
        .status { color: #3fb950; }
    </style>
</head>
<body>
    <h1>ASM Dashboard</h1>
    <p class="status">Server is running</p>
    <p>API endpoints:</p>
    <ul>
        <li><a href="/health" style="color: #58a6ff;">/health</a> - Health check</li>
        <li><a href="/api/stats" style="color: #58a6ff;">/api/stats</a> - Database statistics</li>
    </ul>
</body>
</html>`)
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
