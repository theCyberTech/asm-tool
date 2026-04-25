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
	"github.com/asm-tool/asm-go/internal/scanner/subdomains"
	"github.com/spf13/cobra"
)

// DiscoverCmd creates the discover command
func DiscoverCmd(deps *Deps) *cobra.Command {
	var allKnown bool

	cmd := &cobra.Command{
		Use:   "discover [domain]",
		Short: "Enumerate subdomains for a domain",
		Long: `Enumerate subdomains using multiple passive sources including:
- Certificate Transparency logs (crt.sh)
- HackerTarget API
- URLScan.io

Results are saved to the database for future reference.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get target domains
			var domains []string
			if len(args) > 0 {
				domains = []string{args[0]}
			} else if allKnown {
				dbDomains, err := deps.DB.Domains.List()
				if err != nil {
					return fmt.Errorf("listing domains: %w", err)
				}
				for _, d := range dbDomains {
					domains = append(domains, d.Domain)
				}
			} else {
				return fmt.Errorf("specify a domain or use --all-known")
			}

			if len(domains) == 0 {
				fmt.Println("No domains to scan")
				return nil
			}

			rateLimit := 0
			if deps.Cfg != nil {
				rateLimit = deps.Cfg.Scanning.RateLimit
			}
			return runDiscover(deps.DB, domains, rateLimit)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Scan all known domains")

	return cmd
}

func runDiscover(db *database.Database, domains []string, rateLimit int) error {
	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	enum := subdomains.NewEnumeratorWithRateLimit(rateLimit)

	for _, domain := range domains {
		fmt.Printf("\n%s Discovering subdomains for %s\n", titleStyle.Render("[*]"), valueStyle.Render(domain))
		fmt.Println(strings.Repeat("-", 50))

		result := enum.Enumerate(ctx, domain)

		// Print source results
		fmt.Println("\nSources:")
		for source, count := range result.Sources {
			fmt.Printf("  %s %d\n", labelStyle.Render(padRight(source+":", 16)), count)
		}

		// Print errors if any
		if len(result.Errors) > 0 {
			fmt.Println("\nWarnings:")
			for _, err := range result.Errors {
				fmt.Printf("  %s %s\n", highStyle.Render("[!]"), err)
			}
		}

		// Print summary
		fmt.Printf("\n%s Found %s unique subdomains in %s\n",
			titleStyle.Render("[+]"),
			valueStyle.Render(fmt.Sprintf("%d", len(result.Subdomains))),
			labelStyle.Render(result.Duration.Round(time.Millisecond).String()))

		// Save to database
		if len(result.Subdomains) > 0 {
			// Ensure domain exists
			domainRecord, err := db.Domains.Add(domain)
			if err != nil {
				return fmt.Errorf("adding domain: %w", err)
			}

			// Add subdomains
			saved := 0
			for _, sub := range result.Subdomains {
				if err := db.Domains.AddSubdomain(domainRecord.ID, sub); err == nil {
					saved++
				}
			}

			fmt.Printf("%s Saved %d subdomains to database\n",
				lowStyle.Render("[+]"), saved)
		}

		// Print sample of subdomains
		if len(result.Subdomains) > 0 {
			fmt.Println("\nSubdomains:")
			limit := 20
			if len(result.Subdomains) < limit {
				limit = len(result.Subdomains)
			}
			for i := 0; i < limit; i++ {
				fmt.Printf("  %s\n", result.Subdomains[i])
			}
			if len(result.Subdomains) > 20 {
				fmt.Printf("  ... and %d more\n", len(result.Subdomains)-20)
			}
		}
	}

	return nil
}
