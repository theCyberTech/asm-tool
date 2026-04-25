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
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/spf13/cobra"
)

// NucleiCmd creates the nuclei command for vulnerability scanning
func NucleiCmd(deps *Deps) *cobra.Command {
	var (
		allKnown        bool
		severities      []string
		tags            []string
		excludeTags     []string
		templates       []string
		rateLimit       int
		concurrency     int
		updateTemplates bool
		outputDir       string
	)

	cmd := &cobra.Command{
		Use:   "nuclei [target...]",
		Short: "Scan for vulnerabilities using Nuclei",
		Long: `Run vulnerability scans using Nuclei templates.

Nuclei is a fast vulnerability scanner that uses templates to detect
security issues. Templates cover:
- CVEs and known vulnerabilities
- Misconfigurations
- Exposed panels and dashboards
- Default credentials
- Information disclosure
- Technology detection

Requires nuclei to be installed:
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

Examples:
  asm nuclei example.com
  asm nuclei example.com --severity critical,high
  asm nuclei --all-known --tags cve
  asm nuclei example.com --templates cves/2024/`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle template update
			if updateTemplates {
				return runNucleiUpdate()
			}

			var targets []string
			if len(args) > 0 {
				targets = args
			} else if allKnown {
				// Get all subdomains from database
				dbDomains, err := deps.DB.Domains.List()
				if err != nil {
					return fmt.Errorf("listing domains: %w", err)
				}
				for _, d := range dbDomains {
					subs, _ := deps.DB.Domains.GetSubdomainsByDomainName(d.Domain)
					targets = append(targets, subs...)
				}
			} else {
				return fmt.Errorf("specify targets or use --all-known")
			}

			if len(targets) == 0 {
				fmt.Println("No targets to scan")
				return nil
			}

			return runNuclei(deps.DB, targets, nucleiOptions{
				severities:  severities,
				tags:        tags,
				excludeTags: excludeTags,
				templates:   templates,
				rateLimit:   rateLimit,
				concurrency: concurrency,
				outputDir:   outputDir,
			})
		},
	}

	cmd.Flags().BoolVar(&allKnown, "all-known", false, "Scan all known subdomains")
	cmd.Flags().StringSliceVarP(&severities, "severity", "s", []string{"critical", "high", "medium"}, "Severity levels to scan for")
	cmd.Flags().StringSliceVarP(&tags, "tags", "t", nil, "Template tags to include (e.g., cve, rce, sqli)")
	cmd.Flags().StringSliceVar(&excludeTags, "exclude-tags", nil, "Template tags to exclude")
	cmd.Flags().StringSliceVar(&templates, "templates", nil, "Specific template paths or IDs")
	cmd.Flags().IntVarP(&rateLimit, "rate-limit", "r", 150, "Maximum requests per second")
	cmd.Flags().IntVar(&concurrency, "concurrency", 25, "Number of concurrent templates")
	cmd.Flags().BoolVar(&updateTemplates, "update", false, "Update nuclei templates")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for detailed results")

	return cmd
}

type nucleiOptions struct {
	severities  []string
	tags        []string
	excludeTags []string
	templates   []string
	rateLimit   int
	concurrency int
	outputDir   string
}

func runNucleiUpdate() error {
	fmt.Printf("\n%s Updating Nuclei templates...\n", titleStyle.Render("[*]"))

	scanner := nuclei.DefaultScanner()
	if !scanner.IsInstalled() {
		return fmt.Errorf("nuclei not found - install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := scanner.UpdateTemplates(ctx); err != nil {
		return fmt.Errorf("updating templates: %w", err)
	}

	fmt.Printf("%s Templates updated successfully\n", lowStyle.Render("[+]"))
	return nil
}

func runNuclei(db *database.Database, targets []string, opts nucleiOptions) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, stopping scan...")
		cancel()
	}()

	// Create scanner
	scanner := nuclei.DefaultScanner()

	// Check if nuclei is installed
	if !scanner.IsInstalled() {
		return fmt.Errorf("nuclei not found in PATH\n\nInstall with:\n  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	}

	// Get version
	version, _ := scanner.GetVersion()

	// Configure scanner
	scanner.Severities = opts.severities
	scanner.Tags = opts.tags
	scanner.ExcludeTags = opts.excludeTags
	scanner.Templates = opts.templates
	scanner.RateLimit = opts.rateLimit
	scanner.Concurrency = opts.concurrency
	scanner.OutputDir = opts.outputDir

	// Print header
	fmt.Printf("\n%s Nuclei Vulnerability Scan\n", titleStyle.Render("[*]"))
	fmt.Println(strings.Repeat("=", 60))
	if version != "" {
		fmt.Printf("%s Version: %s\n", labelStyle.Render("   "), version)
	}
	fmt.Printf("%s Targets: %d\n", labelStyle.Render("   "), len(targets))
	fmt.Printf("%s Severities: %s\n", labelStyle.Render("   "), strings.Join(opts.severities, ", "))
	if len(opts.tags) > 0 {
		fmt.Printf("%s Tags: %s\n", labelStyle.Render("   "), strings.Join(opts.tags, ", "))
	}
	fmt.Printf("%s Rate Limit: %d req/s\n", labelStyle.Render("   "), opts.rateLimit)
	fmt.Println(strings.Repeat("-", 60))

	fmt.Printf("\n%s Scanning for vulnerabilities...\n\n", titleStyle.Render("[*]"))

	// Track findings by severity for live output
	findingCount := 0

	// Run scan with callback for live output and DB persistence
	result, err := scanner.ScanWithCallback(ctx, targets, func(f *nuclei.Finding) {
		findingCount++
		printFinding(f, findingCount)
		if db != nil {
			if err := persistFinding(db, f); err != nil {
				fmt.Printf("    %s %v\n", highStyle.Render("DB save failed:"), err)
			}
		}
	})

	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	// Print summary
	fmt.Println(strings.Repeat("-", 60))
	printNucleiSummary(result)

	return nil
}

func printFinding(f *nuclei.Finding, num int) {
	// Determine severity style and print header
	sevLabel := fmt.Sprintf("[%s]", strings.ToUpper(f.Info.Severity))
	var styledSev string
	switch strings.ToLower(f.Info.Severity) {
	case "critical":
		styledSev = criticalStyle.Render(sevLabel)
	case "high":
		styledSev = highStyle.Render(sevLabel)
	case "medium":
		styledSev = mediumStyle.Render(sevLabel)
	case "low":
		styledSev = lowStyle.Render(sevLabel)
	default:
		styledSev = infoStyle.Render(sevLabel)
	}

	// Print finding header
	fmt.Printf("%s [%s] %s\n",
		styledSev,
		f.TemplateID,
		f.Info.Name)

	// Print host
	fmt.Printf("    %s %s\n", labelStyle.Render("Host:"), f.Host)

	// Print matched URL if different from host
	if f.Matched != "" && f.Matched != f.Host {
		fmt.Printf("    %s %s\n", labelStyle.Render("URL:"), f.Matched)
	}

	// Print CVE if present
	if f.Info.Classification.CVEID != "" {
		fmt.Printf("    %s %s", labelStyle.Render("CVE:"), f.Info.Classification.CVEID)
		if f.Info.Classification.CVSSScore > 0 {
			fmt.Printf(" (CVSS: %.1f)", f.Info.Classification.CVSSScore)
		}
		fmt.Println()
	}

	// Print description if short enough
	if f.Info.Description != "" && len(f.Info.Description) < 100 {
		fmt.Printf("    %s %s\n", labelStyle.Render("Info:"), f.Info.Description)
	}

	// Print references (first 2)
	if len(f.Info.Reference) > 0 {
		fmt.Printf("    %s", labelStyle.Render("Refs:"))
		for i, ref := range f.Info.Reference {
			if i >= 2 {
				fmt.Printf(" (+%d more)", len(f.Info.Reference)-2)
				break
			}
			if i > 0 {
				fmt.Printf(",")
			}
			fmt.Printf(" %s", ref)
		}
		fmt.Println()
	}

	// Print extracted results if any
	if len(f.ExtractedResults) > 0 {
		fmt.Printf("    %s %s\n", labelStyle.Render("Data:"), strings.Join(f.ExtractedResults, ", "))
	}

	fmt.Println()
}

func printNucleiSummary(result *nuclei.Result) {
	fmt.Printf("\n%s Scan Summary\n", titleStyle.Render("[*]"))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Targets Scanned:", 20)), result.Stats.TargetsScanned)
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Total Findings:", 20)), result.Stats.FindingsTotal)
	fmt.Printf("  %s %s\n", labelStyle.Render(padRight("Duration:", 20)), result.Duration.Round(time.Second))

	// Severity breakdown
	if result.Stats.FindingsTotal > 0 {
		fmt.Printf("\n  %s\n", labelStyle.Render("Findings by Severity:"))
		if result.Stats.FindingsCritical > 0 {
			fmt.Printf("    %s %d\n", criticalStyle.Render(padRight("Critical:", 12)), result.Stats.FindingsCritical)
		}
		if result.Stats.FindingsHigh > 0 {
			fmt.Printf("    %s %d\n", highStyle.Render(padRight("High:", 12)), result.Stats.FindingsHigh)
		}
		if result.Stats.FindingsMedium > 0 {
			fmt.Printf("    %s %d\n", mediumStyle.Render(padRight("Medium:", 12)), result.Stats.FindingsMedium)
		}
		if result.Stats.FindingsLow > 0 {
			fmt.Printf("    %s %d\n", lowStyle.Render(padRight("Low:", 12)), result.Stats.FindingsLow)
		}
		if result.Stats.FindingsInfo > 0 {
			fmt.Printf("    %s %d\n", infoStyle.Render(padRight("Info:", 12)), result.Stats.FindingsInfo)
		}
	}

	// Unique vulnerabilities
	unique := result.GetUniqueVulnerabilities()
	if len(unique) != result.Stats.FindingsTotal {
		fmt.Printf("\n  %s %d\n", labelStyle.Render(padRight("Unique Issues:", 20)), len(unique))
	}

	// Print errors if any
	if len(result.Errors) > 0 {
		fmt.Printf("\n  %s\n", highStyle.Render("Errors:"))
		for _, e := range result.Errors {
			fmt.Printf("    - %s\n", e)
		}
	}
}

// persistFinding converts a nuclei.Finding to a database.Finding and stores it.
// The DB schema enforces severity ∈ {critical,high,medium,low,info}; anything
// else (e.g. nuclei's "unknown") is coerced to "info".
func persistFinding(db *database.Database, f *nuclei.Finding) error {
	severity := strings.ToLower(strings.TrimSpace(f.Info.Severity))
	switch severity {
	case "critical", "high", "medium", "low", "info":
	default:
		severity = "info"
	}

	return db.Findings.Add(&database.Finding{
		TemplateID:  f.TemplateID,
		Name:        f.Info.Name,
		Severity:    severity,
		Description: f.Info.Description,
		Host:        f.Host,
		MatchedAt:   f.Matched,
		MatcherName: f.MatcherName,
		Evidence:    strings.Join(f.ExtractedResults, ", "),
		Refs:        strings.Join(f.Info.Reference, "\n"),
		Tags:        f.Info.Tags,
		Type:        f.Type,
		Status:      "open",
	})
}
