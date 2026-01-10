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
	"github.com/asm-tool/asm-go/internal/scanner/dns"
	"github.com/spf13/cobra"
)

// DNSCmd creates the dns command
func DNSCmd(db **database.Database, cfg **config.Config) *cobra.Command {
	var (
		allKnown bool
		timeout  int
	)

	cmd := &cobra.Command{
		Use:   "dns [domain]",
		Short: "Query DNS records for domains",
		Long: `Query and monitor DNS records for domains including:
- A, AAAA, CNAME, MX, NS, TXT records
- SPF and DMARC analysis
- Email security configuration

Results are saved to the database for change tracking.`,
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

			return runDNS(*db, domains, time.Duration(timeout)*time.Second)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Check all known domains")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 5, "DNS query timeout in seconds")

	return cmd
}

func runDNS(db *database.Database, domains []string, timeout time.Duration) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	monitor := dns.DefaultMonitor()
	monitor.Timeout = timeout

	fmt.Printf("\n%s Querying DNS records for %d domains\n",
		titleStyle.Render("[*]"),
		len(domains))
	fmt.Println(strings.Repeat("-", 50))

	start := time.Now()

	for _, domain := range domains {
		result := monitor.Lookup(ctx, domain)

		fmt.Printf("\n%s %s\n", titleStyle.Render("[+]"), valueStyle.Render(result.Domain))

		if result.Error != "" {
			fmt.Printf("  %s %s\n", highStyle.Render("Error:"), result.Error)
			continue
		}

		// Print records by type
		recordOrder := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
		for _, recordType := range recordOrder {
			records, ok := result.Records[recordType]
			if !ok || len(records) == 0 {
				continue
			}

			fmt.Printf("  %s\n", labelStyle.Render(recordType+" Records:"))
			for _, r := range records {
				if r.Priority > 0 {
					fmt.Printf("    %d %s\n", r.Priority, r.Value)
				} else {
					// Truncate long TXT records
					val := r.Value
					if len(val) > 70 {
						val = val[:67] + "..."
					}
					fmt.Printf("    %s\n", val)
				}
			}
		}

		// SPF Analysis
		if result.SPF != nil {
			fmt.Printf("  %s\n", labelStyle.Render("SPF Analysis:"))
			if result.SPF.Valid {
				fmt.Printf("    %s\n", lowStyle.Render("Valid SPF record"))
			} else {
				fmt.Printf("    %s\n", highStyle.Render("SPF issues detected"))
			}
			for _, warning := range result.SPF.Warnings {
				fmt.Printf("    %s %s\n", highStyle.Render("[!]"), warning)
			}
		} else {
			fmt.Printf("  %s %s\n", labelStyle.Render("SPF:"), highStyle.Render("Not configured"))
		}

		// DMARC Analysis
		if result.DMARC != nil {
			fmt.Printf("  %s\n", labelStyle.Render("DMARC Analysis:"))
			policyStyle := lowStyle
			if result.DMARC.Policy == "none" {
				policyStyle = highStyle
			} else if result.DMARC.Policy == "quarantine" {
				policyStyle = mediumStyle
			}
			fmt.Printf("    Policy: %s\n", policyStyle.Render(result.DMARC.Policy))
			for _, warning := range result.DMARC.Warnings {
				fmt.Printf("    %s %s\n", highStyle.Render("[!]"), warning)
			}
		} else {
			fmt.Printf("  %s %s\n", labelStyle.Render("DMARC:"), highStyle.Render("Not configured"))
		}

		fmt.Printf("  %s %s (%d records)\n",
			labelStyle.Render("Checked in:"),
			result.Duration.Round(time.Millisecond),
			result.RecordCount())
	}

	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("\n%s DNS check complete in %s\n",
		titleStyle.Render("[+]"),
		time.Since(start).Round(time.Millisecond))

	return nil
}
