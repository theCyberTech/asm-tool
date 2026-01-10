package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/scanner/urls"
	"github.com/spf13/cobra"
)

// URLsCmd creates the urls command
func URLsCmd(db **database.Database, cfg **config.Config) *cobra.Command {
	var (
		allKnown    bool
		showAll     bool
		interesting bool
	)

	cmd := &cobra.Command{
		Use:   "urls [domain]",
		Short: "Enumerate URLs from web archives",
		Long: `Discover historical URLs from multiple sources including:
- Wayback Machine (Internet Archive)
- Common Crawl
- URLScan.io
- AlienVault OTX

URLs are categorized by type (API, JS, config, backup, etc.) and
flagged if potentially interesting for security testing.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var domains []string
			if len(args) > 0 {
				domains = []string{args[0]}
			} else if allKnown {
				dbDomains, err := (*db).Domains.List()
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
				fmt.Println("No domains to enumerate")
				return nil
			}

			return runURLs(*db, domains, showAll, interesting)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Enumerate URLs for all known domains")
	cmd.Flags().BoolVar(&showAll, "all", false, "Show all URLs (not just interesting)")
	cmd.Flags().BoolVar(&interesting, "interesting", true, "Focus on interesting URLs")

	return cmd
}

func runURLs(db *database.Database, domains []string, showAll, interesting bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	enum := urls.DefaultEnumerator()

	for _, domain := range domains {
		fmt.Printf("\n%s Enumerating URLs for %s\n", titleStyle.Render("[*]"), valueStyle.Render(domain))
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

		// Print categories
		if len(result.Categories) > 0 {
			fmt.Println("\nCategories:")
			for cat, count := range result.Categories {
				fmt.Printf("  %s %d\n", labelStyle.Render(padRight(cat+":", 16)), count)
			}
		}

		// Print interesting URLs
		interestingURLs := result.GetInteresting()
		if len(interestingURLs) > 0 {
			fmt.Printf("\n%s Interesting URLs (%d):\n", titleStyle.Render("[+]"), len(interestingURLs))

			limit := 30
			if showAll || len(interestingURLs) <= limit {
				limit = len(interestingURLs)
			}

			for i := 0; i < limit; i++ {
				u := interestingURLs[i]
				catStyle := labelStyle
				switch u.Category {
				case "api":
					catStyle = infoStyle
				case "config", "backup", "archive":
					catStyle = highStyle
				case "admin":
					catStyle = criticalStyle
				}
				fmt.Printf("  %s %s\n",
					catStyle.Render(padRight("["+u.Category+"]", 12)),
					truncateURL(u.URL, 80))
			}

			if len(interestingURLs) > limit {
				fmt.Printf("  ... and %d more\n", len(interestingURLs)-limit)
			}
		}

		// Print summary
		fmt.Printf("\n%s Found %s URLs (%d interesting) in %s\n",
			titleStyle.Render("[+]"),
			valueStyle.Render(fmt.Sprintf("%d", len(result.URLs))),
			len(interestingURLs),
			labelStyle.Render(result.Duration.Round(time.Millisecond).String()))
	}

	return nil
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen-3] + "..."
}
