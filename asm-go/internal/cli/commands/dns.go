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
	"github.com/asm-tool/asm-go/internal/scanner/dns"
	"github.com/spf13/cobra"
)

// DNSCmd creates the dns command
func DNSCmd(deps *Deps) *cobra.Command {
	var (
		allKnown bool
		timeout  int
	)

	cmd := &cobra.Command{
		Use:   "dns [domain]",
		Short: "Query DNS records for domains",
		Long: `Query and monitor DNS records for domains including:
- A, AAAA, CNAME, MX, NS, TXT records
- SOA record (serial tracking for change detection)
- CAA records (certificate authority restrictions)
- DNSSEC validation status
- SPF and DMARC analysis
- Change detection vs. previous scan

Results are saved to the database and changes are logged automatically.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domains, err := resolveScanDomains(deps.DB, args, allKnown)
			if err != nil {
				return err
			}
			if len(domains) == 0 {
				fmt.Println("No domains to check")
				return nil
			}

			return runDNS(deps.DB, domains, time.Duration(timeout)*time.Second)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Check all known domains")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 5, "DNS query timeout in seconds")

	return cmd
}

func runDNS(db *database.Database, domains []string, timeout time.Duration) error {
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

	monitor := dns.DefaultMonitor()
	monitor.Timeout = timeout

	fmt.Printf("\n%s Querying DNS records for %d domains\n",
		titleStyle.Render("[*]"),
		len(domains))
	fmt.Println(strings.Repeat("-", 50))

	start := time.Now()

	for _, domain := range domains {
		result := monitor.Lookup(ctx, domain)

		// Persist and detect changes before printing
		if db != nil {
			if err := persistence.SaveDNSResult(db, result); err != nil {
				return err
			}
			if err := persistence.MarkDomainScanned(db, domain); err != nil {
				return err
			}
		}

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
				ttl := labelStyle.Render(fmt.Sprintf(" TTL=%d", r.TTL))
				if r.Priority > 0 {
					fmt.Printf("    %d %s%s\n", r.Priority, r.Value, ttl)
				} else {
					// Truncate long TXT records
					val := r.Value
					if len(val) > 70 {
						val = val[:67] + "..."
					}
					fmt.Printf("    %s%s\n", val, ttl)
				}
			}
		}

		// SOA Record
		if result.SOA != nil {
			fmt.Printf("  %s\n", labelStyle.Render("SOA:"))
			fmt.Printf("    Primary NS:  %s\n", result.SOA.PrimaryNS)
			fmt.Printf("    Admin:       %s\n", result.SOA.AdminEmail)
			fmt.Printf("    Serial:      %d\n", result.SOA.Serial)
			fmt.Printf("    Refresh/Retry/Expire: %ds / %ds / %ds\n",
				result.SOA.Refresh, result.SOA.Retry, result.SOA.Expire)
		}

		// CAA Records
		if len(result.CAA) > 0 {
			fmt.Printf("  %s\n", labelStyle.Render("CAA Records:"))
			for _, caa := range result.CAA {
				fmt.Printf("    %d %s %q\n", caa.Flags, caa.Tag, caa.Value)
			}
		} else {
			fmt.Printf("  %s %s\n", labelStyle.Render("CAA:"), highStyle.Render("Not configured (any CA may issue certs)"))
		}

		// DNSSEC
		if result.DNSSEC != nil {
			fmt.Printf("  %s\n", labelStyle.Render("DNSSEC:"))
			if result.DNSSEC.Signed {
				fmt.Printf("    %s Chain of trust validated by resolver\n", lowStyle.Render("[✓]"))
			} else {
				fmt.Printf("    %s Not signed\n", highStyle.Render("[!]"))
			}
			if result.DNSSEC.HasDNSKEY {
				fmt.Printf("    DNSKEY: present\n")
			}
			if result.DNSSEC.HasDS {
				fmt.Printf("    DS record: present at parent zone\n")
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
