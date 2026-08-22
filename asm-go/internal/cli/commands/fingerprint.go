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
	"github.com/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/spf13/cobra"
)

// FingerprintCmd creates the fingerprint command
func FingerprintCmd(deps *Deps) *cobra.Command {
	var (
		allKnown bool
		workers  int
		timeout  int
	)

	cmd := &cobra.Command{
		Use:   "fingerprint [domain|host]",
		Short: "Detect technologies and frameworks",
		Long: `Fingerprint web servers to detect technologies including:
- Web servers (Nginx, Apache, IIS, etc.)
- Frameworks (React, Vue, Angular, Django, etc.)
- CMS platforms (WordPress, Drupal, Joomla)
- CDNs (Cloudflare, CloudFront, Fastly)
- Security headers and configurations

Results are saved to the database for tracking.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hosts, err := resolveScanHosts(deps.DB, args, allKnown)
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				fmt.Println("No hosts to fingerprint")
				return nil
			}

			return runFingerprint(deps.DB, hosts, workers, time.Duration(timeout)*time.Second)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Fingerprint all known subdomains")
	cmd.Flags().IntVarP(&workers, "workers", "w", 30, "Number of concurrent workers")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "HTTP timeout in seconds")

	return cmd
}

func runFingerprint(db *database.Database, hosts []string, workers int, timeout time.Duration) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	fp := technologies.DefaultFingerprinter()
	fp.Workers = workers
	fp.Timeout = timeout

	fmt.Printf("\n%s Fingerprinting %d hosts\n",
		titleStyle.Render("[*]"),
		len(hosts))
	fmt.Printf("%s Workers: %d, Signatures: %d\n",
		labelStyle.Render("   "),
		workers,
		len(fp.Signatures))
	fmt.Println(strings.Repeat("-", 50))

	start := time.Now()
	results := fp.FingerprintBatch(ctx, hosts)

	// Collect stats
	successCount := 0
	errorCount := 0
	techCounts := make(map[string]int)

	for _, result := range results {
		if result.Error != "" {
			errorCount++
			continue
		}
		successCount++

		// Print result
		fmt.Printf("\n%s %s", lowStyle.Render("[+]"), valueStyle.Render(result.Host))
		if result.StatusCode > 0 {
			statusStyle := lowStyle
			if result.StatusCode >= 400 {
				statusStyle = highStyle
			} else if result.StatusCode >= 300 {
				statusStyle = mediumStyle
			}
			fmt.Printf(" %s", statusStyle.Render(fmt.Sprintf("[%d]", result.StatusCode)))
		}
		fmt.Println()

		if result.Title != "" {
			fmt.Printf("    %s %s\n", labelStyle.Render(padRight("Title:", 12)), result.Title)
		}
		if result.Server != "" {
			fmt.Printf("    %s %s\n", labelStyle.Render(padRight("Server:", 12)), result.Server)
		}

		if len(result.Technologies) > 0 {
			fmt.Printf("    %s", labelStyle.Render(padRight("Tech:", 12)))

			// Group by category
			categories := make(map[string][]string)
			for _, tech := range result.Technologies {
				categories[tech.Category] = append(categories[tech.Category], tech.Name)
				techCounts[tech.Name]++
			}

			// Print technologies
			techNames := result.TechnologyNames()
			if len(techNames) <= 5 {
				fmt.Printf("%s\n", strings.Join(techNames, ", "))
			} else {
				fmt.Printf("%s (+%d more)\n", strings.Join(techNames[:5], ", "), len(techNames)-5)
			}
		}

		if result.ResponseTime > 0 {
			fmt.Printf("    %s %s\n", labelStyle.Render(padRight("Response:", 12)), result.ResponseTime.Round(time.Millisecond))
		}
	}

	// Print errors summary
	if errorCount > 0 {
		fmt.Printf("\n%s %d hosts failed to respond\n", labelStyle.Render("[?]"), errorCount)
	}

	// Print summary
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("\n%s Fingerprint Summary\n", titleStyle.Render("[*]"))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Scanned:", 16)), len(hosts))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Successful:", 16)), successCount)
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Errors:", 16)), errorCount)

	// Top technologies
	if len(techCounts) > 0 {
		fmt.Printf("\n  %s\n", labelStyle.Render("Top Technologies:"))

		// Sort by count
		type techCount struct {
			name  string
			count int
		}
		var sorted []techCount
		for name, count := range techCounts {
			sorted = append(sorted, techCount{name, count})
		}
		for i := 0; i < len(sorted)-1; i++ {
			for j := i + 1; j < len(sorted); j++ {
				if sorted[j].count > sorted[i].count {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}

		limit := 10
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("    %s %d hosts\n",
				labelStyle.Render(padRight(sorted[i].name+":", 20)),
				sorted[i].count)
		}
	}

	fmt.Printf("\n  %s %s\n", labelStyle.Render(padRight("Duration:", 16)), time.Since(start).Round(time.Millisecond))

	saved, err := persistence.SaveTechnologies(db, results)
	if err != nil {
		return err
	}
	fmt.Printf("%s Saved %d technology fingerprints to database\n", lowStyle.Render("[+]"), saved)

	return nil
}
