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
	"github.com/asm-tool/asm-go/internal/scanner/urls"
	"github.com/spf13/cobra"
)

// URLsCmd creates the urls command
func URLsCmd(deps *Deps) *cobra.Command {
	var (
		allKnown    bool
		showAll     bool
		interesting bool
		probe       bool
		probeAll    bool
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
flagged if potentially interesting for security testing.

Use --probe to actively check which discovered URLs are still live.
Use --probe-all to probe every URL (not just interesting ones).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domains, err := resolveScanDomains(deps.DB, args, allKnown)
			if err != nil {
				return err
			}
			if len(domains) == 0 {
				fmt.Println("No domains to enumerate")
				return nil
			}

			rateLimit := 0
			if deps.Cfg != nil {
				rateLimit = deps.Cfg.Scanning.RateLimit
			}
			return runURLs(deps.DB, domains, showAll, interesting, probe, probeAll, rateLimit)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Enumerate URLs for all known domains")
	cmd.Flags().BoolVar(&showAll, "all", false, "Show all URLs (not just interesting)")
	cmd.Flags().BoolVar(&interesting, "interesting", true, "Focus on interesting URLs")
	cmd.Flags().BoolVar(&probe, "probe", false, "Actively probe interesting URLs for liveness")
	cmd.Flags().BoolVar(&probeAll, "probe-all", false, "Actively probe all discovered URLs for liveness")

	return cmd
}

func runURLs(db *database.Database, domains []string, showAll, interesting, probe, probeAll bool, rateLimit int) error {
	normalizedDomains, err := normalizeDomainList(domains)
	if err != nil {
		return err
	}
	domains = normalizedDomains

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	enum := urls.NewEnumeratorWithRateLimit(rateLimit)

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

		// Liveness probing
		interestingURLs := result.GetInteresting()

		if probeAll || probe {
			toProbe := interestingURLs
			if probeAll {
				toProbe = result.URLs
			}
			fmt.Printf("\n%s Probing %d URLs for liveness...\n", titleStyle.Render("[*]"), len(toProbe))
			toProbe = enum.ProbeURLs(ctx, toProbe, 20)

			if probeAll {
				result.URLs = toProbe
				// Rebuild interesting list from probed results
				interestingURLs = result.GetInteresting()
			} else {
				// Merge probed interesting back into result
				interestingURLs = toProbe
			}
		}

		// Print interesting URLs
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

				statusPart := ""
				if u.Live {
					statusPart = " " + formatStatusCode(u.StatusCode)
				} else if probe || probeAll {
					statusPart = " " + highStyle.Render("[dead]")
				}

				fmt.Printf("  %s%s %s\n",
					catStyle.Render(padRight("["+u.Category+"]", 12)),
					statusPart,
					truncateURL(u.URL, 70))

				if u.Redirects != "" {
					fmt.Printf("    %s %s\n", labelStyle.Render("→"), truncateURL(u.Redirects, 70))
				}
			}

			if len(interestingURLs) > limit {
				fmt.Printf("  ... and %d more\n", len(interestingURLs)-limit)
			}
		}

		// Print summary
		liveCount := 0
		for _, u := range result.URLs {
			if u.Live {
				liveCount++
			}
		}
		summary := fmt.Sprintf("%d interesting", len(interestingURLs))
		if probe || probeAll {
			summary += fmt.Sprintf(", %d live", liveCount)
		}
		fmt.Printf("\n%s Found %s URLs (%s) in %s\n",
			titleStyle.Render("[+]"),
			valueStyle.Render(fmt.Sprintf("%d", len(result.URLs))),
			summary,
			labelStyle.Render(result.Duration.Round(time.Millisecond).String()))

		saved, err := persistence.SaveURLs(db, result.URLs)
		if err != nil {
			return err
		}
		if err := persistence.MarkDomainScanned(db, domain); err != nil {
			return err
		}
		fmt.Printf("%s Saved %d URLs to database\n", lowStyle.Render("[+]"), saved)
	}

	return nil
}

func formatStatusCode(code int) string {
	s := fmt.Sprintf("[%d]", code)
	switch {
	case code >= 200 && code < 300:
		return lowStyle.Render(s)
	case code >= 300 && code < 400:
		return infoStyle.Render(s)
	case code >= 400 && code < 500:
		return mediumStyle.Render(s)
	case code >= 500:
		return highStyle.Render(s)
	default:
		return labelStyle.Render(s)
	}
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen-3] + "..."
}
