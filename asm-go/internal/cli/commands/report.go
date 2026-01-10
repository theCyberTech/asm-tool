package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/parallel"
	"github.com/asm-tool/asm-go/internal/reporter"
	"github.com/spf13/cobra"
)

// ReportCmd creates the report command for generating reports
func ReportCmd(db **database.Database, cfg **config.Config) *cobra.Command {
	var (
		inputFile    string
		outputFormat string
		outputDir    string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a report from a JSON scan result",
		Long: `Generate a report in various formats from a JSON scan result file.

Supported formats:
- json: Machine-readable JSON format
- markdown: Human-readable Markdown format
- html: Styled HTML report

To generate a report during a scan, use: asm scan <domain> --output <format>

To convert an existing JSON report to another format, provide the JSON file:
  asm report --input scan-result.json --format html`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("please specify --input with a JSON scan result file\n\nTo generate a report during scanning, use:\n  asm scan <domain> --output <format>")
			}
			return runReportConvert(inputFile, outputFormat, outputDir)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input JSON scan result file")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "markdown", "Output format: json, markdown, html")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "reports", "Output directory")

	return cmd
}

func runReportConvert(inputFile, outputFormat, outputDir string) error {
	fmt.Printf("\n%s Converting report from %s\n", titleStyle.Render("[*]"), valueStyle.Render(inputFile))
	fmt.Println(strings.Repeat("-", 50))

	// Read JSON file
	data, err := os.ReadFile(inputFile)
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

	// Note: URLs, APIs, and Emails would need similar conversion
	// For now, just the basic fields are converted

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
