package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/persistence"
	"github.com/asm-tool/asm-go/internal/scanner/takeover"
	"github.com/spf13/cobra"
)

// TakeoverCmd creates the takeover command
func TakeoverCmd(deps *Deps) *cobra.Command {
	var (
		allKnown bool
		workers  int
		timeout  int
	)

	cmd := &cobra.Command{
		Use:   "takeover [domain]",
		Short: "Detect subdomain takeover vulnerabilities",
		Long: `Check subdomains for takeover vulnerabilities by analyzing:
- CNAME records pointing to unclaimed services
- HTTP response fingerprints indicating abandoned resources
- NXDOMAIN responses for claimed CNAMEs

Supports 30+ services including AWS S3, GitHub Pages, Heroku, Azure, etc.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			subdomains, err := resolveScanHosts(deps.DB, args, allKnown)
			if err != nil {
				return err
			}
			if len(subdomains) == 0 {
				fmt.Println("No subdomains to check")
				return nil
			}

			return runTakeover(deps.DB, subdomains, workers, time.Duration(timeout)*time.Second)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Check all known subdomains")
	cmd.Flags().IntVarP(&workers, "workers", "w", 20, "Number of concurrent workers")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "HTTP timeout in seconds")

	return cmd
}

func runTakeover(db *database.Database, subdomains []string, workers int, timeout time.Duration) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	detector := takeover.DefaultDetector()
	detector.Workers = workers
	detector.Timeout = timeout

	fmt.Printf("\n%s Checking %d subdomains for takeover vulnerabilities\n",
		titleStyle.Render("[*]"),
		len(subdomains))
	fmt.Printf("%s Workers: %d, Fingerprints: %d services\n",
		labelStyle.Render("   "),
		workers,
		len(detector.Fingerprints))
	fmt.Println(strings.Repeat("-", 50))

	result := detector.CheckBatch(ctx, subdomains)

	// Print vulnerable findings
	if len(result.Findings) > 0 {
		fmt.Printf("\n%s VULNERABLE SUBDOMAINS:\n", criticalStyle.Render("[!]"))

		for _, finding := range result.Findings {
			confidenceStyle := mediumStyle
			if finding.Confidence == "HIGH" {
				confidenceStyle = criticalStyle
			} else if finding.Confidence == "LOW" {
				confidenceStyle = labelStyle
			}

			fmt.Printf("\n  %s\n", criticalStyle.Render(finding.Subdomain))
			fmt.Printf("    %s %s\n", labelStyle.Render(padRight("Service:", 14)), finding.Service)
			fmt.Printf("    %s %s\n", labelStyle.Render(padRight("CNAME:", 14)), finding.CNAME)
			fmt.Printf("    %s %s\n", labelStyle.Render(padRight("Type:", 14)), finding.Type)
			fmt.Printf("    %s %s\n", labelStyle.Render(padRight("Confidence:", 14)), confidenceStyle.Render(finding.Confidence))
			fmt.Printf("    %s %s\n", labelStyle.Render(padRight("Evidence:", 14)), finding.Evidence)
			if finding.Documentation != "" {
				fmt.Printf("    %s %s\n", labelStyle.Render(padRight("Docs:", 14)), infoStyle.Render(finding.Documentation))
			}
		}
	} else {
		fmt.Printf("\n%s No takeover vulnerabilities found\n", lowStyle.Render("[+]"))
	}

	// Print summary
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("\n%s Takeover Check Summary\n", titleStyle.Render("[*]"))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Checked:", 16)), result.Checked)
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Vulnerable:", 16)),
		func() string {
			if result.VulnerableCount() > 0 {
				return criticalStyle.Render(fmt.Sprintf("%d", result.VulnerableCount()))
			}
			return lowStyle.Render("0")
		}())
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("High Confidence:", 16)),
		func() string {
			if result.HighConfidenceCount() > 0 {
				return criticalStyle.Render(fmt.Sprintf("%d", result.HighConfidenceCount()))
			}
			return "0"
		}())
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Duration:", 16)), result.Duration.Round(time.Millisecond))

	toSave := make([]persistence.TakeoverFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		toSave = append(toSave, persistence.TakeoverFinding{
			Subdomain:  finding.Subdomain,
			CNAME:      finding.CNAME,
			Service:    finding.Service,
			Confidence: finding.Confidence,
			Evidence:   finding.Evidence,
			Vulnerable: finding.Vulnerable,
		})
	}
	saved, err := persistence.SaveTakeovers(db, toSave)
	if err != nil {
		return err
	}
	fmt.Printf("%s Saved %d takeover findings to database\n", lowStyle.Render("[+]"), saved)

	return nil
}
