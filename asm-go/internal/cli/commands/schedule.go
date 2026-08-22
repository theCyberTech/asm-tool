package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/asm-tool/asm-go/internal/persistence"
	"github.com/asm-tool/asm-go/internal/scheduler"
	"github.com/asm-tool/asm-go/internal/target"
	"github.com/spf13/cobra"
)

// ScheduleCmd creates the schedule command with subcommands.
func ScheduleCmd(deps *Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage scheduled scans",
		Long: `View, start, and manage scheduled scan jobs.

Jobs are configured via cron expressions in config.yaml under 'schedule:'.
The scheduler reads domains from the 'domains:' config key.

Examples:
  asm schedule                    # Show schedule status and recent runs
  asm schedule start              # Start the scheduler daemon (foreground)
  asm schedule run full_scan      # Run a full scan immediately for all domains
  asm schedule run cert_check     # Run a cert check immediately for all domains
  asm schedule run full_scan crewai.com  # Run a full scan for one domain
  asm schedule history            # Show recent run history`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showScheduleStatus(deps)
		},
	}

	// Start subcommand — runs the scheduler daemon in foreground
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the scheduler daemon (foreground)",
		Long:  "Start the cron scheduler. Runs in the foreground — use systemd, screen, or nohup to background it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return startScheduler(deps)
		},
	}

	// Run subcommand — execute a job immediately
	runCmd := &cobra.Command{
		Use:   "run <full_scan|cert_check> [domain]",
		Short: "Run a scheduled job immediately",
		Long:  "Execute a job type immediately. If no domain is specified, runs for all configured domains.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			jobType := scheduler.JobType(args[0])
			if jobType != scheduler.JobFullScan && jobType != scheduler.JobCertCheck {
				return fmt.Errorf("unknown job type %q — use 'full_scan' or 'cert_check'", args[0])
			}
			domains := deps.Cfg.Domains
			if len(args) > 1 {
				normalized, err := target.NormalizeScanTarget(args[1])
				if err != nil {
					return err
				}
				domains = []string{normalized}
			}
			return runScheduleOnce(deps, jobType, domains)
		},
	}

	// History subcommand
	historyCmd := &cobra.Command{
		Use:   "history",
		Short: "Show recent scheduled run history",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showScheduleHistory(deps)
		},
	}

	cmd.AddCommand(startCmd)
	cmd.AddCommand(runCmd)
	cmd.AddCommand(historyCmd)

	return cmd
}

// showScheduleStatus displays the current schedule configuration and next run times.
func showScheduleStatus(deps *Deps) error {
	cfg := deps.Cfg

	fmt.Printf("\n%s Schedule Status\n", titleStyle.Render("[*]"))
	fmt.Println(strings.Repeat("=", 60))

	// Domains
	domains := cfg.Domains
	if len(domains) == 0 {
		fmt.Printf("  %s No domains configured — add 'domains:' to config.yaml\n", highStyle.Render("[!]"))
	} else {
		fmt.Printf("  %s %s\n", labelStyle.Render("Domains:"), strings.Join(domains, ", "))
	}

	// Schedule config
	fmt.Printf("  %s %s\n", labelStyle.Render("Full Scan:"), formatCron(cfg.Schedule.FullScan))
	fmt.Printf("  %s %s\n", labelStyle.Render("Cert Check:"), formatCron(cfg.Schedule.CertCheck))

	// Show next runs if schedule is active
	if cfg.Schedule.FullScan != "" || cfg.Schedule.CertCheck != "" {
		fmt.Printf("\n  %s\n", labelStyle.Render("Next Runs:"))
		if cfg.Schedule.FullScan != "" {
			next := nextRun(cfg.Schedule.FullScan)
			fmt.Printf("    full_scan:   %s\n", valueStyle.Render(next))
		}
		if cfg.Schedule.CertCheck != "" {
			next := nextRun(cfg.Schedule.CertCheck)
			fmt.Printf("    cert_check:  %s\n", valueStyle.Render(next))
		}
	}

	// Recent runs
	fmt.Printf("\n  %s\n", labelStyle.Render("Recent Runs:"))
	runs, err := scheduler.New(cfg, deps.DB, persistence.NewStore(deps.DB), log.New(os.Stderr, "", 0)).RecentRuns(10)
	if err != nil {
		fmt.Printf("    %s Error reading history: %v\n", highStyle.Render("[!]"), err)
	} else if len(runs) == 0 {
		fmt.Printf("    No runs recorded yet.\n")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "    %s\t%s\t%s\t%s\t%s\n", "TIME", "JOB", "DOMAIN", "STATUS", "DURATION")
		for _, r := range runs {
			statusStyle := lowStyle
			if r.Status == "failed" {
				statusStyle = highStyle
			} else if r.Status == "running" {
				statusStyle = valueStyle
			}
			fmt.Fprintf(w, "    %s\t%s\t%s\t%s\t%s\n",
				r.StartedAt.Format("Jan 02 15:04"),
				r.JobType,
				r.Domain,
				statusStyle.Render(r.Status),
				time.Duration(r.Duration*int64(time.Millisecond)).Round(time.Second),
			)
		}
		w.Flush()
	}

	fmt.Println(strings.Repeat("=", 60))
	return nil
}

// startScheduler starts the cron scheduler daemon.
func startScheduler(deps *Deps) error {
	logger := log.New(os.Stderr, "[scheduler] ", log.LstdFlags)

	s := scheduler.New(deps.Cfg, deps.DB, persistence.NewStore(deps.DB), logger)
	if err := s.RegisterJobs(); err != nil {
		return fmt.Errorf("registering jobs: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Printf("received %s, shutting down...", sig)
		cancel()
	}()

	fmt.Printf("\n%s Scheduler started\n", titleStyle.Render("[*]"))
	fmt.Printf("  %s %s\n", labelStyle.Render("Full Scan:"), formatCron(deps.Cfg.Schedule.FullScan))
	fmt.Printf("  %s %s\n", labelStyle.Render("Cert Check:"), formatCron(deps.Cfg.Schedule.CertCheck))
	fmt.Printf("  %s %d configured\n", labelStyle.Render("Domains:"), len(deps.Cfg.Domains))
	fmt.Printf("\n  Press Ctrl+C to stop.\n\n")

	// This blocks until ctx is cancelled
	s.Start(ctx)

	return nil
}

// runScheduleOnce executes a job immediately.
func runScheduleOnce(deps *Deps, jobType scheduler.JobType, domains []string) error {
	logger := log.New(os.Stderr, "[scheduler] ", log.LstdFlags)

	if len(domains) == 0 {
		return fmt.Errorf("no domains configured — specify a domain or add 'domains:' to config.yaml")
	}

	fmt.Printf("\n%s Running %s for %s\n", titleStyle.Render("[*]"),
		valueStyle.Render(string(jobType)),
		valueStyle.Render(strings.Join(domains, ", ")))
	fmt.Println(strings.Repeat("-", 60))

	s := scheduler.New(deps.Cfg, deps.DB, persistence.NewStore(deps.DB), logger)
	err := s.RunOnce(jobType, domains)

	fmt.Println(strings.Repeat("-", 60))
	if err != nil {
		return fmt.Errorf("scheduled %s run failed: %w", jobType, err)
	}
	fmt.Printf("%s Done\n", lowStyle.Render("[+]"))
	return nil
}

// showScheduleHistory displays recent run history.
func showScheduleHistory(deps *Deps) error {
	s := scheduler.New(deps.Cfg, deps.DB, persistence.NewStore(deps.DB), log.New(os.Stderr, "", 0))
	runs, err := s.RecentRuns(50)
	if err != nil {
		return fmt.Errorf("reading run history: %w", err)
	}

	fmt.Printf("\n%s Scheduled Run History (last 50)\n", titleStyle.Render("[*]"))
	fmt.Println(strings.Repeat("=", 80))

	if len(runs) == 0 {
		fmt.Printf("  No runs recorded yet.\n")
		fmt.Println(strings.Repeat("=", 80))
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n", "ID", "TIME", "JOB", "DOMAIN", "STATUS", "DURATION")
	for _, r := range runs {
		statusStyle := lowStyle
		if r.Status == "failed" {
			statusStyle = highStyle
		} else if r.Status == "running" {
			statusStyle = valueStyle
		}
		fmt.Fprintf(w, "  %d\t%s\t%s\t%s\t%s\t%s\n",
			r.ID,
			r.StartedAt.Format("Jan 02 15:04:05"),
			r.JobType,
			r.Domain,
			statusStyle.Render(r.Status),
			time.Duration(r.Duration*int64(time.Millisecond)).Round(time.Second),
		)
	}
	w.Flush()

	// Show errors for failed runs
	failedCount := 0
	for _, r := range runs {
		if r.Status == "failed" && r.Error != "" {
			if failedCount == 0 {
				fmt.Printf("\n%s Failed Run Errors:\n", highStyle.Render("[!]"))
			}
			fmt.Printf("  [%d] %s: %s\n", r.ID, r.Domain, r.Error)
			failedCount++
		}
	}

	fmt.Println(strings.Repeat("=", 80))
	return nil
}

// formatCron formats a cron expression for display.
func formatCron(expr string) string {
	if expr == "" {
		return labelStyle.Render("disabled")
	}
	return valueStyle.Render(expr)
}

// nextRun calculates the next run time for a cron expression.
func nextRun(expr string) string {
	sched, err := scheduler.ParseCron(expr)
	if err != nil {
		return fmt.Sprintf("(invalid cron: %v)", err)
	}
	next := sched.Next(time.Now())
	return next.Format("Mon Jan 02 15:04:05 MST")
}
