package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/spf13/cobra"
)

// CloudStorageCmd creates the cloudstorage command
func CloudStorageCmd(db **database.Database, cfg **config.Config) *cobra.Command {
	var (
		allKnown bool
		probe    bool
		workers  int
	)

	cmd := &cobra.Command{
		Use:   "cloudstorage [domain]",
		Short: "Detect cloud storage buckets",
		Long: `Discover cloud storage buckets (S3, Azure, GCS) associated with a domain.

Detection methods:
- URL extraction: Find bucket references in discovered URLs
- Active probing: Test common bucket naming patterns

Checks bucket access levels:
- listing_enabled: Directory listing publicly accessible (CRITICAL)
- public_read: Files publicly readable (HIGH)
- authenticated_only: Exists but requires auth (LOW)`,
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
				fmt.Println("No domains to check")
				return nil
			}

			return runCloudStorage(*db, domains, probe, workers)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Check all known domains")
	cmd.Flags().BoolVar(&probe, "probe", true, "Actively probe for common bucket names")
	cmd.Flags().IntVarP(&workers, "workers", "w", 20, "Number of concurrent workers")

	return cmd
}

func runCloudStorage(db *database.Database, domains []string, probe bool, workers int) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	detector := cloud.DefaultDetector()
	detector.Workers = workers

	for _, domain := range domains {
		fmt.Printf("\n%s Detecting cloud storage for %s\n", titleStyle.Render("[*]"), valueStyle.Render(domain))
		fmt.Println(strings.Repeat("-", 50))

		var allBuckets []cloud.Bucket

		// Active probing for common bucket names
		if probe {
			fmt.Printf("\n%s Probing common bucket names...\n", labelStyle.Render("[*]"))

			result := detector.ProbeCommonBuckets(ctx, domain)

			if len(result.Buckets) > 0 {
				fmt.Printf("%s Found %d buckets via active probing\n",
					lowStyle.Render("[+]"),
					len(result.Buckets))
				allBuckets = append(allBuckets, result.Buckets...)
			} else {
				fmt.Printf("%s No buckets found via probing (checked %d names)\n",
					labelStyle.Render("[*]"),
					result.Checked/3) // Divided by 3 providers
			}
		}

		// Print discovered buckets
		if len(allBuckets) > 0 {
			// Group by severity
			critical := []cloud.Bucket{}
			high := []cloud.Bucket{}
			medium := []cloud.Bucket{}
			low := []cloud.Bucket{}

			for _, b := range allBuckets {
				switch b.Severity {
				case "critical":
					critical = append(critical, b)
				case "high":
					high = append(high, b)
				case "medium":
					medium = append(medium, b)
				default:
					low = append(low, b)
				}
			}

			// Print critical first
			if len(critical) > 0 {
				fmt.Printf("\n%s CRITICAL - Public Listing Enabled:\n", criticalStyle.Render("[!]"))
				for _, b := range critical {
					printBucket(b)
				}
			}

			if len(high) > 0 {
				fmt.Printf("\n%s HIGH - Public Read Access:\n", highStyle.Render("[!]"))
				for _, b := range high {
					printBucket(b)
				}
			}

			if len(medium) > 0 {
				fmt.Printf("\n%s MEDIUM - Potentially Sensitive:\n", mediumStyle.Render("[!]"))
				for _, b := range medium {
					printBucket(b)
				}
			}

			if len(low) > 0 {
				fmt.Printf("\n%s LOW - Exists (Auth Required):\n", labelStyle.Render("[*]"))
				for _, b := range low {
					printBucket(b)
				}
			}
		}

		// Print summary
		fmt.Println(strings.Repeat("-", 50))
		fmt.Printf("\n%s Cloud Storage Summary\n", titleStyle.Render("[*]"))

		publicBuckets := 0
		for _, b := range allBuckets {
			if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
				publicBuckets++
			}
		}

		fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Total Found:", 18)), len(allBuckets))
		if publicBuckets > 0 {
			fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Publicly Accessible:", 18)),
				criticalStyle.Render(fmt.Sprintf("%d", publicBuckets)))
		} else {
			fmt.Printf("  %s 0\n", labelStyle.Render(padRight("Publicly Accessible:", 18)))
		}

		// Provider breakdown
		providers := make(map[string]int)
		for _, b := range allBuckets {
			providers[b.Provider]++
		}
		if len(providers) > 0 {
			fmt.Printf("  %s", labelStyle.Render(padRight("Providers:", 18)))
			parts := []string{}
			for p, c := range providers {
				parts = append(parts, fmt.Sprintf("%s:%d", strings.ToUpper(p), c))
			}
			fmt.Printf("%s\n", strings.Join(parts, ", "))
		}
	}

	return nil
}

func printBucket(b cloud.Bucket) {
	providerStyle := infoStyle
	switch b.Provider {
	case "s3":
		providerStyle = mediumStyle
	case "azure":
		providerStyle = infoStyle
	case "gcs":
		providerStyle = lowStyle
	}

	fmt.Printf("  %s %s\n",
		providerStyle.Render(padRight("["+strings.ToUpper(b.Provider)+"]", 8)),
		b.BucketName)
	fmt.Printf("  %s URL: %s\n",
		labelStyle.Render(padRight("", 8)),
		b.URL)
	if b.Evidence != "" {
		fmt.Printf("  %s %s\n",
			labelStyle.Render(padRight("", 8)),
			b.Evidence)
	}
}
