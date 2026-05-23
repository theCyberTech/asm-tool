package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/pathsafe"
	"github.com/asm-tool/asm-go/internal/parallel"
	"github.com/asm-tool/asm-go/internal/reporter"
	"github.com/spf13/cobra"
)

// ReportCmd creates the report command for generating reports
func ReportCmd(deps *Deps) *cobra.Command {
	var (
		domain       string
		inputFile    string
		outputFormat string
		outputDir    string
	)

	cmd := &cobra.Command{
		Use:   "report [domain]",
		Short: "Generate a report from the database or a JSON file",
		Long: `Generate a report in various formats from the database or a JSON file.

Supported formats:
- json: Machine-readable JSON format
- markdown: Human-readable Markdown format
- html: Styled HTML report

Examples:
  # Generate report for a domain from the database
  asm report example.com
  asm report example.com --format html

  # Convert an existing JSON report to another format
  asm report --input scan-result.json --format html`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// If input file provided, convert it
			if inputFile != "" {
				return runReportConvert(inputFile, outputFormat, outputDir)
			}

			// Otherwise generate from database
			if len(args) > 0 {
				domain = args[0]
			}
			if domain == "" {
				return fmt.Errorf("please specify a domain or use --input with a JSON file\n\nExamples:\n  asm report example.com\n  asm report example.com --format html")
			}

			return runReportFromDB(deps.DB, domain, outputFormat, outputDir)
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to generate report for")
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input JSON scan result file (optional)")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "markdown", "Output format: json, markdown, html")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "reports", "Output directory")

	return cmd
}

func runReportFromDB(db *database.Database, domain, outputFormat, outputDir string) error {
	fmt.Printf("\n%s Generating report for %s\n", titleStyle.Render("[*]"), valueStyle.Render(domain))
	fmt.Println(strings.Repeat("-", 50))

	// Get domain from database
	domainRecord, err := db.Domains.GetByName(domain)
	if err != nil {
		return fmt.Errorf("domain not found in database: %s", domain)
	}

	// Build scan result from database
	result := &parallel.ScanResult{
		Domain:    domain,
		StartTime: time.Now(),
		Errors:    make(map[parallel.ModuleType]error),
	}

	// Get subdomains
	subs, err := db.Domains.GetSubdomains(domainRecord.ID)
	if err == nil {
		for _, sub := range subs {
			result.Subdomains = append(result.Subdomains, sub.Subdomain)
		}
	}
	fmt.Printf("  %s %d subdomains\n", labelStyle.Render("Loaded:"), len(result.Subdomains))

	// Get ports for all subdomains
	for _, sub := range result.Subdomains {
		ports, err := db.Ports.GetByHost(sub)
		if err == nil {
			for _, p := range ports {
				result.Ports = append(result.Ports, parallel.PortResult{
					Host:    p.Host,
					Port:    p.Port,
					State:   p.State,
					Service: p.Service,
					Banner:  p.Banner,
				})
			}
		}
	}
	// Also get ports for the main domain
	ports, err := db.Ports.GetByHost(domain)
	if err == nil {
		for _, p := range ports {
			result.Ports = append(result.Ports, parallel.PortResult{
				Host:    p.Host,
				Port:    p.Port,
				State:   p.State,
				Service: p.Service,
				Banner:  p.Banner,
			})
		}
	}
	fmt.Printf("  %s %d open ports\n", labelStyle.Render("Loaded:"), len(result.Ports))

	// Get certificates
	certs, err := db.GetCertificatesForDomain(domain)
	if err == nil {
		for _, c := range certs {
			result.Certificates = append(result.Certificates, &parallel.Certificate{
				Host:            c.Host,
				Subject:         c.Subject,
				Issuer:          c.Issuer,
				NotAfter:        c.NotAfter,
				DaysUntilExpiry: c.DaysUntilExpiry,
			})
		}
	}
	fmt.Printf("  %s %d certificates\n", labelStyle.Render("Loaded:"), len(result.Certificates))

	// Get takeovers
	takeovers, err := db.GetTakeoversForDomain(domain)
	if err == nil {
		for _, t := range takeovers {
			result.Takeovers = append(result.Takeovers, parallel.TakeoverResult{
				Host:       t.Subdomain,
				Vulnerable: t.Status == "open",
				Service:    t.Service,
				Confidence: t.Confidence,
				Evidence:   t.Evidence,
			})
		}
	}
	fmt.Printf("  %s %d takeovers\n", labelStyle.Render("Loaded:"), len(result.Takeovers))

	// Get URLs
	dbUrls, err := db.GetURLsForDomain(domain)
	if err == nil {
		for _, u := range dbUrls {
			result.URLs = append(result.URLs, parallel.URLResult{
				URL:         u.URL,
				Domain:      u.Domain,
				Category:    u.Category.String,
				Interesting: u.Interesting != 0,
			})
		}
	}
	fmt.Printf("  %s %d URLs\n", labelStyle.Render("Loaded:"), len(result.URLs))

	// Get APIs
	dbApis, err := db.GetAPIsForDomain(domain)
	if err == nil {
		for _, a := range dbApis {
			result.APIs = append(result.APIs, parallel.APIResult{
				URL:     a.URL,
				Type:    a.Type.String,
				Title:   a.Title.String,
				Version: a.Version.String,
			})
		}
	}
	fmt.Printf("  %s %d APIs\n", labelStyle.Render("Loaded:"), len(result.APIs))

	// Get emails
	dbEmails, err := db.GetEmailsForDomain(domain)
	if err == nil {
		for _, e := range dbEmails {
			result.Emails = append(result.Emails, parallel.EmailResult{
				Address: e.Address,
				Domain:  e.Domain,
				Source:  e.Source,
			})
		}
	}
	fmt.Printf("  %s %d emails\n", labelStyle.Render("Loaded:"), len(result.Emails))

	// Get cloud storage
	buckets, err := db.GetCloudStorageForDomain(domain)
	if err == nil {
		for _, b := range buckets {
			result.CloudStorage = append(result.CloudStorage, parallel.CloudBucket{
				Provider:    b.Provider,
				BucketName:  b.BucketName,
				URL:         b.URL,
				AccessLevel: b.AccessLevel,
				Severity:    b.Severity,
			})
		}
	}
	fmt.Printf("  %s %d cloud buckets\n", labelStyle.Render("Loaded:"), len(result.CloudStorage))

	// Get vulnerabilities
	vulns, err := db.GetVulnerabilitiesForDomain(domain)
	if err == nil {
		for _, v := range vulns {
			result.Vulnerabilities = append(result.Vulnerabilities, &parallel.VulnFinding{
				TemplateID: v.TemplateID,
				Host:       v.Host,
				Matched:    v.MatchedAt,
				Info: parallel.VulnInfo{
					Name:        v.Name,
					Severity:    v.Severity,
					Description: v.Description,
				},
			})
		}
	}
	fmt.Printf("  %s %d vulnerabilities\n", labelStyle.Render("Loaded:"), len(result.Vulnerabilities))

	// Generate report
	rep := reporter.DefaultReporter()
	rep.OutputDir = outputDir

	var format reporter.Format
	switch strings.ToLower(outputFormat) {
	case "json":
		format = reporter.FormatJSON
	case "markdown", "md":
		format = reporter.FormatMarkdown
	case "html":
		format = reporter.FormatHTML
	default:
		return fmt.Errorf("unsupported format: %s", outputFormat)
	}

	fmt.Println(strings.Repeat("-", 50))
	path, err := rep.Generate(result, format)
	if err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	fmt.Printf("%s Report saved: %s\n", lowStyle.Render("[+]"), path)
	return nil
}

func runReportConvert(inputFile, outputFormat, outputDir string) error {
	fmt.Printf("\n%s Converting report from %s\n", titleStyle.Render("[*]"), valueStyle.Render(inputFile))
	fmt.Println(strings.Repeat("-", 50))

	// Read JSON file (bounded, confined to working directory)
	data, err := pathsafe.ReadFile(inputFile, pathsafe.MaxReportJSONBytes)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	// Parse JSON into report structure
	var jsonReport reporter.JSONReport
	if err := json.Unmarshal(data, &jsonReport); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}

	// Convert to ScanResult
	result := &parallel.ScanResult{
		Domain:     jsonReport.Domain,
		StartTime:  jsonReport.ScanTime,
		Subdomains: jsonReport.Subdomains,
		Errors:     make(map[parallel.ModuleType]error),
	}

	// Convert ports
	for _, p := range jsonReport.Ports {
		result.Ports = append(result.Ports, parallel.PortResult{
			Host:    p.Host,
			Port:    p.Port,
			State:   p.State,
			Service: p.Service,
			Banner:  p.Banner,
		})
	}

	// Convert takeovers
	for _, t := range jsonReport.Takeovers {
		result.Takeovers = append(result.Takeovers, parallel.TakeoverResult{
			Host:       t.Host,
			Vulnerable: t.Vulnerable,
			Service:    t.Service,
			Confidence: t.Confidence,
			Evidence:   t.Evidence,
		})
	}

	// Convert cloud storage
	for _, b := range jsonReport.CloudStorage {
		result.CloudStorage = append(result.CloudStorage, parallel.CloudBucket{
			Provider:    b.Provider,
			BucketName:  b.BucketName,
			URL:         b.URL,
			AccessLevel: b.AccessLevel,
			Severity:    b.Severity,
		})
	}

	fmt.Printf("  %s Domain: %s\n", labelStyle.Render("Loaded:"), result.Domain)
	fmt.Printf("  %s Subdomains: %d\n", labelStyle.Render("Loaded:"), len(result.Subdomains))
	fmt.Printf("  %s Ports: %d\n", labelStyle.Render("Loaded:"), len(result.Ports))

	// Generate report
	rep := reporter.DefaultReporter()
	rep.OutputDir = outputDir

	var format reporter.Format
	switch strings.ToLower(outputFormat) {
	case "json":
		format = reporter.FormatJSON
	case "markdown", "md":
		format = reporter.FormatMarkdown
	case "html":
		format = reporter.FormatHTML
	default:
		return fmt.Errorf("unsupported format: %s", outputFormat)
	}

	fmt.Println(strings.Repeat("-", 50))
	path, err := rep.Generate(result, format)
	if err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	fmt.Printf("%s Report saved: %s\n", lowStyle.Render("[+]"), path)
	return nil
}
