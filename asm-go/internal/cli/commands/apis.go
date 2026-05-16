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
	"github.com/asm-tool/asm-go/internal/scanner/apis"
	"github.com/spf13/cobra"
)

// APIsCmd creates the apis command
func APIsCmd(deps *Deps) *cobra.Command {
	var (
		allKnown bool
		workers  int
		timeout  int
	)

	cmd := &cobra.Command{
		Use:   "apis [domain|host]",
		Short: "Discover API endpoints and documentation",
		Long: `Discover API endpoints and documentation including:
- Swagger/OpenAPI specifications
- GraphQL endpoints (with introspection check)
- REST API documentation pages
- Common API paths

Checks for publicly accessible API documentation that may
reveal internal endpoints and data structures.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var hosts []string
			if len(args) > 0 {
				target := args[0]
				subs, err := deps.DB.Domains.GetSubdomainsByDomainName(target)
				if err == nil && len(subs) > 0 {
					hosts = subs
				} else {
					hosts = []string{target}
				}
			} else if allKnown {
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

			insecure := deps.Cfg != nil && deps.Cfg.Scanning.InsecureSkipVerify
			if err := runAPIs(deps.DB, hosts, workers, time.Duration(timeout)*time.Second, insecure); err != nil {
				return err
			}
			if len(args) > 0 {
				return persistence.MarkDomainScanned(deps.DB, args[0])
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Check all known subdomains")
	cmd.Flags().IntVarP(&workers, "workers", "w", 30, "Number of concurrent workers")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "HTTP timeout in seconds")

	return cmd
}

func runAPIs(db *database.Database, hosts []string, workers int, timeout time.Duration, insecureSkipVerify bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	discovery := apis.NewDiscovery(insecureSkipVerify)
	discovery.Workers = workers
	discovery.Timeout = timeout

	fmt.Printf("\n%s Discovering APIs on %d hosts\n",
		titleStyle.Render("[*]"),
		len(hosts))
	fmt.Printf("%s Workers: %d, Paths: %d\n",
		labelStyle.Render("   "),
		workers,
		len(discovery.Paths))
	fmt.Println(strings.Repeat("-", 50))

	batch := discovery.DiscoverBatch(ctx, hosts)

	// Print discovered APIs
	totalAPIs := 0
	var allAPIs []apis.API
	for _, result := range batch.Results {
		if len(result.APIs) == 0 {
			continue
		}

		fmt.Printf("\n%s %s\n", lowStyle.Render("[+]"), valueStyle.Render(result.Host))

		for _, api := range result.APIs {
			totalAPIs++
			allAPIs = append(allAPIs, api)

			typeStyle := infoStyle
			if api.Type == "graphql" && api.IntrospectionEnabled {
				typeStyle = highStyle
			} else if api.Type == "swagger" || api.Type == "openapi" {
				typeStyle = mediumStyle
			}

			fmt.Printf("    %s %s\n",
				typeStyle.Render(padRight("["+api.Type+"]", 14)),
				api.URL)

			if api.Title != "" {
				fmt.Printf("    %s %s\n",
					labelStyle.Render(padRight("", 14)),
					api.Title)
			}

			if api.Version != "" {
				fmt.Printf("    %s Version: %s\n",
					labelStyle.Render(padRight("", 14)),
					api.Version)
			}

			if api.EndpointsCount > 0 {
				fmt.Printf("    %s Endpoints: %d\n",
					labelStyle.Render(padRight("", 14)),
					api.EndpointsCount)
			}

			if api.Type == "graphql" {
				if api.IntrospectionEnabled {
					fmt.Printf("    %s %s\n",
						labelStyle.Render(padRight("", 14)),
						highStyle.Render("Introspection ENABLED"))
				} else {
					fmt.Printf("    %s Introspection disabled\n",
						labelStyle.Render(padRight("", 14)))
				}
			}

			if len(api.SecuritySchemes) > 0 {
				fmt.Printf("    %s Auth: %s\n",
					labelStyle.Render(padRight("", 14)),
					strings.Join(api.SecuritySchemes, ", "))
			}
		}
	}

	// Print summary
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("\n%s API Discovery Summary\n", titleStyle.Render("[*]"))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Hosts Checked:", 18)), batch.Total)
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Hosts with APIs:", 18)), batch.Found)
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Total APIs Found:", 18)), totalAPIs)
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Duration:", 18)), batch.Duration.Round(time.Millisecond))

	saved, err := persistence.SaveAPIs(db, allAPIs)
	if err != nil {
		return err
	}
	fmt.Printf("\n%s Saved %d APIs to database\n", lowStyle.Render("[+]"), saved)

	return nil
}
