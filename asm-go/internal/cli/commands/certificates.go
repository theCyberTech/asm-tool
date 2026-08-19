package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/theCyberTech/asm-tool/asm-go/internal/database"
	"github.com/theCyberTech/asm-tool/asm-go/internal/persistence"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/certificates"
	"github.com/spf13/cobra"
)

// CertificatesCmd creates the certificates command
func CertificatesCmd(deps *Deps) *cobra.Command {
	var (
		allKnown bool
		port     int
		workers  int
		timeout  int
		warnDays int
		insecure bool
	)

	cmd := &cobra.Command{
		Use:   "certificates [domain|host]",
		Short: "Check TLS certificates",
		Long: `Check TLS/SSL certificates for hosts and report on expiration status.

By default, checks certificates for all discovered subdomains of the specified domain.
Highlights certificates that are expired or expiring soon.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get target hosts
			var hosts []string
			if len(args) > 0 {
				target := args[0]
				// Check if it's a domain with known subdomains
				subs, err := deps.DB.Domains.GetSubdomainsByDomainName(target)
				if err == nil && len(subs) > 0 {
					hosts = subs
				} else {
					hosts = []string{target}
				}
			} else if allKnown {
				// Get all subdomains from all domains
				dbDomains, err := deps.DB.Domains.List()
				if err != nil {
					return fmt.Errorf("listing domains: %w", err)
				}
				for _, d := range dbDomains {
					subs, _ := deps.DB.Domains.GetSubdomainsByDomainName(d.Domain)
					hosts = append(hosts, subs...)
				}
			} else {
				return fmt.Errorf("specify a target or use --all-known")
			}

			if len(hosts) == 0 {
				fmt.Println("No hosts to check")
				return nil
			}

			return runCertificates(deps.DB, hosts, port, workers, time.Duration(timeout)*time.Second, warnDays, insecure)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Check all known subdomains")
	cmd.Flags().IntVar(&port, "port", 443, "TLS port to check")
	cmd.Flags().IntVarP(&workers, "workers", "w", 50, "Number of concurrent connections")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "Connection timeout in seconds")
	cmd.Flags().IntVar(&warnDays, "warn-days", 30, "Days before expiry to warn")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Skip certificate verification")

	return cmd
}

func runCertificates(db *database.Database, hosts []string, port, workers int, timeout time.Duration, warnDays int, insecure bool) error {
	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	monitor := certificates.NewMonitor(workers, timeout)
	monitor.ExpiryWarnDays = warnDays
	monitor.InsecureSkipVerify = insecure

	fmt.Printf("\n%s Checking certificates for %d hosts\n",
		titleStyle.Render("[*]"),
		len(hosts))
	fmt.Printf("%s Port: %d, Workers: %d, Timeout: %s\n",
		labelStyle.Render("   "),
		port,
		workers,
		timeout)
	fmt.Println(strings.Repeat("-", 50))

	result := monitor.CheckBatch(ctx, hosts, port)
	summary := result.GetSummary()

	// Print expired certificates first
	expired := result.GetExpired()
	if len(expired) > 0 {
		fmt.Printf("\n%s EXPIRED Certificates:\n", criticalStyle.Render("[!]"))
		for _, cert := range expired {
			printCertificate(cert, true)
		}
	}

	// Print expiring soon certificates
	expiring := result.GetExpiring(warnDays)
	if len(expiring) > 0 {
		fmt.Printf("\n%s Expiring Soon (within %d days):\n", highStyle.Render("[!]"), warnDays)
		for _, cert := range expiring {
			printCertificate(cert, true)
		}
	}

	// Print valid certificates
	validCount := 0
	fmt.Printf("\n%s Valid Certificates:\n", lowStyle.Render("[+]"))
	for _, cert := range result.Certificates {
		if cert.Error == "" && !cert.IsExpired && cert.DaysUntilExpiry > warnDays {
			printCertificate(cert, false)
			validCount++
		}
	}
	if validCount == 0 {
		fmt.Println("  (none)")
	}

	// Print errors if any
	if len(result.Errors) > 0 {
		fmt.Printf("\n%s Connection Errors:\n", labelStyle.Render("[?]"))
		for _, err := range result.Errors {
			if len(err) > 80 {
				err = err[:77] + "..."
			}
			fmt.Printf("  %s\n", err)
		}
	}

	// Print summary
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("\n%s Certificate Check Summary\n", titleStyle.Render("[*]"))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Total:", 16)), summary.Total)
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Valid:", 16)), lowStyle.Render(fmt.Sprintf("%d", summary.Valid)))
	if summary.Expired > 0 {
		fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Expired:", 16)), criticalStyle.Render(fmt.Sprintf("%d", summary.Expired)))
	}
	if summary.Expiring7 > 0 {
		fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Expiring <7d:", 16)), criticalStyle.Render(fmt.Sprintf("%d", summary.Expiring7)))
	}
	if summary.Expiring30 > 0 {
		fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Expiring <30d:", 16)), highStyle.Render(fmt.Sprintf("%d", summary.Expiring30)))
	}
	if summary.Errors > 0 {
		fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Errors:", 16)), summary.Errors)
	}
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Duration:", 16)), result.Duration.Round(time.Millisecond))

	saved, err := persistence.SaveCertificates(db, result.Certificates)
	if err != nil {
		return err
	}
	fmt.Printf("\n%s Saved %d certificates to database\n", lowStyle.Render("[+]"), saved)

	return nil
}

func printCertificate(cert *certificates.Certificate, showDetails bool) {
	// Determine style based on expiry
	var expiryStyle = valueStyle
	if cert.IsExpired {
		expiryStyle = criticalStyle
	} else if cert.DaysUntilExpiry <= 7 {
		expiryStyle = criticalStyle
	} else if cert.DaysUntilExpiry <= 30 {
		expiryStyle = highStyle
	}

	fmt.Printf("  %s\n", valueStyle.Render(cert.Host))
	fmt.Printf("    %s %s\n",
		labelStyle.Render(padRight("Subject:", 12)),
		cert.Subject)
	fmt.Printf("    %s %s\n",
		labelStyle.Render(padRight("Issuer:", 12)),
		cert.Issuer)
	fmt.Printf("    %s %s\n",
		labelStyle.Render(padRight("Expires:", 12)),
		expiryStyle.Render(cert.FormatExpiry()))

	if showDetails {
		fmt.Printf("    %s %s\n",
			labelStyle.Render(padRight("Not After:", 12)),
			cert.NotAfter.Format("2006-01-02"))
		if len(cert.SAN) > 0 && len(cert.SAN) <= 5 {
			fmt.Printf("    %s %s\n",
				labelStyle.Render(padRight("SANs:", 12)),
				strings.Join(cert.SAN, ", "))
		} else if len(cert.SAN) > 5 {
			fmt.Printf("    %s %s (+%d more)\n",
				labelStyle.Render(padRight("SANs:", 12)),
				strings.Join(cert.SAN[:5], ", "),
				len(cert.SAN)-5)
		}
	}
}
