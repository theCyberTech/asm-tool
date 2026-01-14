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
	"github.com/asm-tool/asm-go/internal/scanner/emails"
	"github.com/spf13/cobra"
)

// EmailsCmd creates the emails command
func EmailsCmd(deps *Deps) *cobra.Command {
	var allKnown bool

	cmd := &cobra.Command{
		Use:   "emails [domain]",
		Short: "Enumerate email addresses",
		Long: `Discover email addresses associated with a domain from multiple sources.

Emails are classified as:
- personal: Individual employee emails
- role: Role-based addresses (info@, support@, etc.)
- generic: System/automated addresses (noreply@, etc.)

Note: Some sources require API keys for full functionality.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
				fmt.Println("No domains to enumerate")
				return nil
			}

			return runEmails(deps.DB, domains)
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Enumerate emails for all known domains")

	return cmd
}

func runEmails(db *database.Database, domains []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	enum := emails.DefaultEnumerator()

	for _, domain := range domains {
		fmt.Printf("\n%s Enumerating emails for %s\n", titleStyle.Render("[*]"), valueStyle.Render(domain))
		fmt.Println(strings.Repeat("-", 50))

		result := enum.Enumerate(ctx, domain)

		// Print source results
		fmt.Println("\nSources:")
		for source, count := range result.Sources {
			fmt.Printf("  %s %d\n", labelStyle.Render(padRight(source+":", 16)), count)
		}

		// Print errors/warnings
		if len(result.Errors) > 0 {
			fmt.Println("\nWarnings:")
			for _, err := range result.Errors {
				fmt.Printf("  %s %s\n", labelStyle.Render("[?]"), err)
			}
		}

		// Print emails by type
		personalEmails := result.GetByType("personal")
		roleEmails := result.GetByType("role")
		genericEmails := result.GetByType("generic")

		if len(personalEmails) > 0 {
			fmt.Printf("\n%s Personal Emails (%d):\n", titleStyle.Render("[+]"), len(personalEmails))
			limit := 20
			if len(personalEmails) < limit {
				limit = len(personalEmails)
			}
			for i := 0; i < limit; i++ {
				fmt.Printf("  %s\n", personalEmails[i].Address)
			}
			if len(personalEmails) > 20 {
				fmt.Printf("  ... and %d more\n", len(personalEmails)-20)
			}
		}

		if len(roleEmails) > 0 {
			fmt.Printf("\n%s Role-Based Emails (%d):\n", infoStyle.Render("[+]"), len(roleEmails))
			for _, e := range roleEmails {
				fmt.Printf("  %s\n", e.Address)
			}
		}

		if len(genericEmails) > 0 {
			fmt.Printf("\n%s Generic Emails (%d):\n", labelStyle.Render("[+]"), len(genericEmails))
			for _, e := range genericEmails {
				fmt.Printf("  %s\n", e.Address)
			}
		}

		// Print summary
		fmt.Printf("\n%s Found %s emails in %s\n",
			titleStyle.Render("[+]"),
			valueStyle.Render(fmt.Sprintf("%d", len(result.Emails))),
			labelStyle.Render(result.Duration.Round(time.Millisecond).String()))

		// Type breakdown
		if len(result.Emails) > 0 {
			fmt.Printf("  Personal: %d, Role: %d, Generic: %d\n",
				len(personalEmails),
				len(roleEmails),
				len(genericEmails))
		}
	}

	return nil
}
