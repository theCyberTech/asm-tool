package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asm-tool/asm-go/internal/parallel"
	"github.com/asm-tool/asm-go/internal/target"
)

// Format represents the report output format
type Format string

const (
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// Reporter generates reports from scan results
type Reporter struct {
	OutputDir string
}

// DefaultReporter creates a reporter with default settings
func DefaultReporter() *Reporter {
	return &Reporter{
		OutputDir: "reports",
	}
}

// Generate creates a report in the specified format
func (r *Reporter) Generate(result *parallel.ScanResult, format Format) (string, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(r.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("creating output directory: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	filenameDomain := target.SafeFilenamePart(result.Domain)
	var filename string
	var content string
	var err error

	switch format {
	case FormatJSON:
		filename = fmt.Sprintf("%s-%s.json", filenameDomain, timestamp)
		content, err = r.generateJSON(result)
	case FormatMarkdown:
		filename = fmt.Sprintf("%s-%s.md", filenameDomain, timestamp)
		content, err = r.generateMarkdown(result)
	case FormatHTML:
		filename = fmt.Sprintf("%s-%s.html", filenameDomain, timestamp)
		content, err = r.generateHTML(result)
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return "", err
	}

	outputPath := filepath.Join(r.OutputDir, filename)
	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("writing report: %w", err)
	}

	return outputPath, nil
}

// JSONReport is the structure for JSON output
type JSONReport struct {
	Domain          string              `json:"domain"`
	ScanTime        time.Time           `json:"scan_time"`
	Duration        string              `json:"duration"`
	Summary         ReportSummary       `json:"summary"`
	Subdomains      []string            `json:"subdomains,omitempty"`
	Ports           []PortEntry         `json:"ports,omitempty"`
	Certificates    []CertEntry         `json:"certificates,omitempty"`
	DNS             []DNSEntry          `json:"dns,omitempty"`
	Takeovers       []TakeoverEntry     `json:"takeovers,omitempty"`
	Technologies    []TechEntry         `json:"technologies,omitempty"`
	URLs            []URLEntry          `json:"urls,omitempty"`
	APIs            []APIEntry          `json:"apis,omitempty"`
	Emails          []EmailEntry        `json:"emails,omitempty"`
	CloudStorage    []CloudStorageEntry `json:"cloud_storage,omitempty"`
	Vulnerabilities []VulnEntry         `json:"vulnerabilities,omitempty"`
	Errors          map[string]string   `json:"errors,omitempty"`
}

type ReportSummary struct {
	SubdomainCount   int `json:"subdomain_count"`
	OpenPortCount    int `json:"open_port_count"`
	CertificateCount int `json:"certificate_count"`
	TakeoverCount    int `json:"takeover_count"`
	TechCount        int `json:"technology_count"`
	URLCount         int `json:"url_count"`
	APICount         int `json:"api_count"`
	EmailCount       int `json:"email_count"`
	BucketCount      int `json:"bucket_count"`
	PublicBuckets    int `json:"public_buckets"`
	VulnCount        int `json:"vulnerability_count"`
	VulnCritical     int `json:"vuln_critical"`
	VulnHigh         int `json:"vuln_high"`
	VulnMedium       int `json:"vuln_medium"`
}

type PortEntry struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

type CertEntry struct {
	Host         string    `json:"host"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotAfter     time.Time `json:"not_after"`
	DaysToExpiry int       `json:"days_to_expiry"`
}

type DNSEntry struct {
	Host    string              `json:"host"`
	Records map[string][]string `json:"records"`
}

type TakeoverEntry struct {
	Host       string `json:"host"`
	Vulnerable bool   `json:"vulnerable"`
	Service    string `json:"service,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

type TechEntry struct {
	Host         string   `json:"host"`
	Technologies []string `json:"technologies"`
}

type URLEntry struct {
	URL         string `json:"url"`
	Category    string `json:"category"`
	Interesting bool   `json:"interesting"`
}

type APIEntry struct {
	URL     string `json:"url"`
	Type    string `json:"type"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version,omitempty"`
}

type EmailEntry struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Source  string `json:"source"`
}

type CloudStorageEntry struct {
	Provider    string `json:"provider"`
	BucketName  string `json:"bucket_name"`
	URL         string `json:"url"`
	AccessLevel string `json:"access_level"`
	Severity    string `json:"severity"`
}

type VulnEntry struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched_at,omitempty"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
	CVEID       string   `json:"cve_id,omitempty"`
	CVSSScore   float64  `json:"cvss_score,omitempty"`
	Tags        string   `json:"tags,omitempty"`
}

func (r *Reporter) generateJSON(result *parallel.ScanResult) (string, error) {
	groupedVulns := groupVulnerabilitiesBySeverity(result)
	report := JSONReport{
		Domain:   result.Domain,
		ScanTime: result.StartTime,
		Duration: result.Duration.Round(time.Millisecond).String(),
		Summary: ReportSummary{
			SubdomainCount:   len(result.Subdomains),
			OpenPortCount:    len(result.Ports),
			CertificateCount: len(result.Certificates),
			TakeoverCount:    countVulnerableTakeovers(result),
			TechCount:        countTechnologies(result),
			URLCount:         len(result.URLs),
			APICount:         len(result.APIs),
			EmailCount:       len(result.Emails),
			BucketCount:      len(result.CloudStorage),
			PublicBuckets:    countPublicBuckets(result),
			VulnCount:        groupedVulns.Total,
			VulnCritical:     len(groupedVulns.Critical),
			VulnHigh:         len(groupedVulns.High),
			VulnMedium:       len(groupedVulns.Medium),
		},
		Subdomains: result.Subdomains,
		Errors:     make(map[string]string),
	}

	// Convert ports
	for _, p := range result.Ports {
		report.Ports = append(report.Ports, PortEntry{
			Host:    p.Host,
			Port:    p.Port,
			State:   p.State,
			Service: p.Service,
			Banner:  p.Banner,
		})
	}

	// Convert certificates
	for _, c := range result.Certificates {
		report.Certificates = append(report.Certificates, CertEntry{
			Host:         c.Host,
			Subject:      c.Subject,
			Issuer:       c.Issuer,
			NotAfter:     c.NotAfter,
			DaysToExpiry: c.DaysUntilExpiry,
		})
	}

	// Convert DNS
	for _, d := range result.DNSRecords {
		entry := DNSEntry{
			Host:    d.Host,
			Records: make(map[string][]string),
		}
		for _, rec := range d.Records {
			entry.Records[rec.Type] = append(entry.Records[rec.Type], rec.Value)
		}
		report.DNS = append(report.DNS, entry)
	}

	// Convert takeovers
	for _, t := range result.Takeovers {
		report.Takeovers = append(report.Takeovers, TakeoverEntry{
			Host:       t.Host,
			Vulnerable: t.Vulnerable,
			Service:    t.Service,
			Confidence: t.Confidence,
			Evidence:   t.Evidence,
		})
	}

	// Convert technologies
	for _, t := range result.Technologies {
		var techs []string
		for _, tech := range t.Technologies {
			techs = append(techs, tech.Name)
		}
		report.Technologies = append(report.Technologies, TechEntry{
			Host:         t.Host,
			Technologies: techs,
		})
	}

	// Convert URLs
	for _, u := range result.URLs {
		report.URLs = append(report.URLs, URLEntry{
			URL:         u.URL,
			Category:    u.Category,
			Interesting: u.Interesting,
		})
	}

	// Convert APIs
	for _, a := range result.APIs {
		report.APIs = append(report.APIs, APIEntry{
			URL:     a.URL,
			Type:    a.Type,
			Title:   a.Title,
			Version: a.Version,
		})
	}

	// Convert emails
	for _, e := range result.Emails {
		report.Emails = append(report.Emails, EmailEntry{
			Address: e.Address,
			Type:    e.Type,
			Source:  e.Source,
		})
	}

	// Convert cloud storage
	for _, b := range result.CloudStorage {
		report.CloudStorage = append(report.CloudStorage, CloudStorageEntry{
			Provider:    b.Provider,
			BucketName:  b.BucketName,
			URL:         b.URL,
			AccessLevel: b.AccessLevel,
			Severity:    b.Severity,
		})
	}

	// Convert vulnerabilities
	for _, v := range result.Vulnerabilities {
		report.Vulnerabilities = append(report.Vulnerabilities, VulnEntry{
			TemplateID:  v.TemplateID,
			Name:        v.Info.Name,
			Severity:    v.Info.Severity,
			Host:        v.Host,
			MatchedAt:   v.Matched,
			Description: v.Info.Description,
			References:  v.Info.Reference,
			CVEID:       v.Info.Classification.CVEID,
			CVSSScore:   v.Info.Classification.CVSSScore,
			Tags:        v.Info.Tags,
		})
	}

	// Convert errors
	for module, err := range result.Errors {
		report.Errors[string(module)] = err.Error()
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *Reporter) generateMarkdown(result *parallel.ScanResult) (string, error) {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("# ASM Scan Report: %s\n\n", result.Domain))
	sb.WriteString(fmt.Sprintf("**Scan Time:** %s\n", result.StartTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", result.Duration.Round(time.Millisecond)))

	// Summary
	groupedVulns := groupVulnerabilitiesBySeverity(result)
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Subdomains | %d |\n", len(result.Subdomains)))
	sb.WriteString(fmt.Sprintf("| Open Ports | %d |\n", len(result.Ports)))
	sb.WriteString(fmt.Sprintf("| Certificates | %d |\n", len(result.Certificates)))
	sb.WriteString(fmt.Sprintf("| Takeover Vulnerabilities | %d |\n", countVulnerableTakeovers(result)))
	sb.WriteString(fmt.Sprintf("| Technologies | %d |\n", countTechnologies(result)))
	sb.WriteString(fmt.Sprintf("| URLs | %d |\n", len(result.URLs)))
	sb.WriteString(fmt.Sprintf("| APIs | %d |\n", len(result.APIs)))
	sb.WriteString(fmt.Sprintf("| Emails | %d |\n", len(result.Emails)))
	sb.WriteString(fmt.Sprintf("| Cloud Buckets | %d (public: %d) |\n", len(result.CloudStorage), countPublicBuckets(result)))
	if groupedVulns.Total > 0 {
		sb.WriteString(fmt.Sprintf("| **Vulnerabilities** | **%d** (critical: %d, high: %d, medium: %d) |\n", groupedVulns.Total, len(groupedVulns.Critical), len(groupedVulns.High), len(groupedVulns.Medium)))
	}
	sb.WriteString("\n")

	// Subdomains
	if len(result.Subdomains) > 0 {
		sb.WriteString("## Subdomains\n\n")
		for _, sub := range result.Subdomains {
			sb.WriteString(fmt.Sprintf("- %s\n", sub))
		}
		sb.WriteString("\n")
	}

	// Ports
	if len(result.Ports) > 0 {
		sb.WriteString("## Open Ports\n\n")
		sb.WriteString("| Host | Port | Service | Banner |\n")
		sb.WriteString("|------|------|---------|--------|\n")
		for _, p := range result.Ports {
			banner := p.Banner
			if len(banner) > 50 {
				banner = banner[:50] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s |\n", p.Host, p.Port, p.Service, banner))
		}
		sb.WriteString("\n")
	}

	// Certificates
	if len(result.Certificates) > 0 {
		sb.WriteString("## Certificates\n\n")
		sb.WriteString("| Host | Subject | Issuer | Days to Expiry |\n")
		sb.WriteString("|------|---------|--------|----------------|\n")
		for _, c := range result.Certificates {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %d |\n", c.Host, c.Subject, c.Issuer, c.DaysUntilExpiry))
		}
		sb.WriteString("\n")
	}

	// Takeovers
	vulnTakeovers := getVulnerableTakeovers(result)
	if len(vulnTakeovers) > 0 {
		sb.WriteString("## Subdomain Takeover Vulnerabilities\n\n")
		sb.WriteString("| Host | Service | Confidence | Evidence |\n")
		sb.WriteString("|------|---------|------------|----------|\n")
		for _, t := range vulnTakeovers {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", t.Host, t.Service, t.Confidence, t.Evidence))
		}
		sb.WriteString("\n")
	}

	// Technologies
	if len(result.Technologies) > 0 {
		sb.WriteString("## Technologies\n\n")
		for _, t := range result.Technologies {
			if len(t.Technologies) > 0 {
				var techs []string
				for _, tech := range t.Technologies {
					techs = append(techs, tech.Name)
				}
				sb.WriteString(fmt.Sprintf("**%s:** %s\n\n", t.Host, strings.Join(techs, ", ")))
			}
		}
	}

	// APIs
	if len(result.APIs) > 0 {
		sb.WriteString("## API Endpoints\n\n")
		sb.WriteString("| URL | Type | Title |\n")
		sb.WriteString("|-----|------|-------|\n")
		for _, a := range result.APIs {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", a.URL, a.Type, a.Title))
		}
		sb.WriteString("\n")
	}

	// Cloud Storage
	publicBuckets := getPublicBuckets(result)
	if len(publicBuckets) > 0 {
		sb.WriteString("## Public Cloud Storage\n\n")
		sb.WriteString("| Provider | Bucket | Access Level | Severity |\n")
		sb.WriteString("|----------|--------|--------------|----------|\n")
		for _, b := range publicBuckets {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", strings.ToUpper(b.Provider), b.BucketName, b.AccessLevel, strings.ToUpper(b.Severity)))
		}
		sb.WriteString("\n")
	}

	// Emails
	if len(result.Emails) > 0 {
		sb.WriteString("## Email Addresses\n\n")
		for _, e := range result.Emails {
			sb.WriteString(fmt.Sprintf("- %s (%s)\n", e.Address, e.Type))
		}
		sb.WriteString("\n")
	}

	// Vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		sb.WriteString("## Vulnerabilities\n\n")

		// Critical vulnerabilities
		if len(groupedVulns.Critical) > 0 {
			sb.WriteString("### Critical\n\n")
			sb.WriteString("| Template | Name | Host | CVE |\n")
			sb.WriteString("|----------|------|------|-----|\n")
			for _, v := range groupedVulns.Critical {
				cve := v.Info.Classification.CVEID
				if cve == "" {
					cve = "-"
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", v.TemplateID, v.Info.Name, v.Host, cve))
			}
			sb.WriteString("\n")
		}

		// High vulnerabilities
		if len(groupedVulns.High) > 0 {
			sb.WriteString("### High\n\n")
			sb.WriteString("| Template | Name | Host | CVE |\n")
			sb.WriteString("|----------|------|------|-----|\n")
			for _, v := range groupedVulns.High {
				cve := v.Info.Classification.CVEID
				if cve == "" {
					cve = "-"
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", v.TemplateID, v.Info.Name, v.Host, cve))
			}
			sb.WriteString("\n")
		}

		// Medium vulnerabilities
		if len(groupedVulns.Medium) > 0 {
			sb.WriteString("### Medium\n\n")
			sb.WriteString("| Template | Name | Host |\n")
			sb.WriteString("|----------|------|------|\n")
			for _, v := range groupedVulns.Medium {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", v.TemplateID, v.Info.Name, v.Host))
			}
			sb.WriteString("\n")
		}
	}

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString("## Errors\n\n")
		for module, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("- **%s:** %s\n", module, err))
		}
	}

	sb.WriteString("\n---\n*Generated by ASM Tool*\n")

	return sb.String(), nil
}

func (r *Reporter) generateHTML(result *parallel.ScanResult) (string, error) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASM Report: {{.Domain}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: #1a1a2e; color: white; padding: 30px; margin-bottom: 30px; border-radius: 8px; }
        h1 { margin-bottom: 10px; }
        .meta { opacity: 0.8; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { color: #1a1a2e; margin-bottom: 15px; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
        .summary-item { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }
        .summary-item .number { font-size: 2em; font-weight: bold; color: #1a1a2e; }
        .summary-item .label { color: #666; font-size: 0.9em; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; margin-right: 5px; }
        .tag-s3 { background: #ff9900; color: white; }
        .tag-azure { background: #0078d4; color: white; }
        .tag-gcs { background: #4285f4; color: white; }
        ul { list-style: none; }
        li { padding: 5px 0; }
        footer { text-align: center; padding: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>ASM Scan Report: {{.Domain}}</h1>
            <div class="meta">
                <p>Scan Time: {{.ScanTime}}</p>
                <p>Duration: {{.Duration}}</p>
            </div>
        </header>

        <div class="card">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="number">{{.SubdomainCount}}</div>
                    <div class="label">Subdomains</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{.PortCount}}</div>
                    <div class="label">Open Ports</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{.CertCount}}</div>
                    <div class="label">Certificates</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{.TakeoverCount}}</div>
                    <div class="label">Takeovers</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{.TechCount}}</div>
                    <div class="label">Technologies</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{.URLCount}}</div>
                    <div class="label">URLs</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{.APICount}}</div>
                    <div class="label">APIs</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{.EmailCount}}</div>
                    <div class="label">Emails</div>
                </div>
                <div class="summary-item">
                    <div class="number">{{.BucketCount}}</div>
                    <div class="label">Buckets</div>
                </div>
                {{if .VulnCount}}
                <div class="summary-item" style="background: #fff3cd;">
                    <div class="number">{{.VulnCount}}</div>
                    <div class="label">Vulnerabilities</div>
                </div>
                {{end}}
            </div>
        </div>

        {{if .Subdomains}}
        <div class="card">
            <h2>Subdomains ({{len .Subdomains}})</h2>
            <ul>
                {{range .Subdomains}}<li>{{.}}</li>{{end}}
            </ul>
        </div>
        {{end}}

        {{if .Ports}}
        <div class="card">
            <h2>Open Ports</h2>
            <table>
                <tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr>
                {{range .Ports}}
                <tr><td>{{.Host}}</td><td>{{.Port}}</td><td>{{.Service}}</td><td>{{.Banner}}</td></tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .Certificates}}
        <div class="card">
            <h2>Certificates</h2>
            <table>
                <tr><th>Host</th><th>Subject</th><th>Issuer</th><th>Days to Expiry</th></tr>
                {{range .Certificates}}
                <tr><td>{{.Host}}</td><td>{{.Subject}}</td><td>{{.Issuer}}</td><td>{{.DaysUntilExpiry}}</td></tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .VulnTakeovers}}
        <div class="card">
            <h2>Subdomain Takeover Vulnerabilities</h2>
            <table>
                <tr><th>Host</th><th>Service</th><th>Confidence</th><th>Evidence</th></tr>
                {{range .VulnTakeovers}}
                <tr><td>{{.Host}}</td><td>{{.Service}}</td><td>{{.Confidence}}</td><td>{{.Evidence}}</td></tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .PublicBuckets}}
        <div class="card">
            <h2>Public Cloud Storage</h2>
            <table>
                <tr><th>Provider</th><th>Bucket</th><th>Access Level</th><th>Severity</th></tr>
                {{range .PublicBuckets}}
                <tr>
                    <td><span class="tag tag-{{.Provider}}">{{.Provider | upper}}</span></td>
                    <td>{{.BucketName}}</td>
                    <td>{{.AccessLevel}}</td>
                    <td class="severity-{{.Severity}}">{{.Severity | upper}}</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .APIs}}
        <div class="card">
            <h2>API Endpoints</h2>
            <table>
                <tr><th>URL</th><th>Type</th><th>Title</th></tr>
                {{range .APIs}}
                <tr><td>{{.URL}}</td><td>{{.Type}}</td><td>{{.Title}}</td></tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .Emails}}
        <div class="card">
            <h2>Email Addresses</h2>
            <ul>
                {{range .Emails}}<li>{{.Address}} ({{.Type}})</li>{{end}}
            </ul>
        </div>
        {{end}}

        {{if .CriticalVulns}}
        <div class="card">
            <h2>Critical Vulnerabilities</h2>
            <table>
                <tr><th>Template</th><th>Name</th><th>Host</th><th>CVE</th></tr>
                {{range .CriticalVulns}}
                <tr>
                    <td>{{.TemplateID}}</td>
                    <td class="severity-critical">{{.Info.Name}}</td>
                    <td>{{.Host}}</td>
                    <td>{{if .Info.Classification.CVEID}}{{.Info.Classification.CVEID}}{{else}}-{{end}}</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .HighVulns}}
        <div class="card">
            <h2>High Vulnerabilities</h2>
            <table>
                <tr><th>Template</th><th>Name</th><th>Host</th><th>CVE</th></tr>
                {{range .HighVulns}}
                <tr>
                    <td>{{.TemplateID}}</td>
                    <td class="severity-high">{{.Info.Name}}</td>
                    <td>{{.Host}}</td>
                    <td>{{if .Info.Classification.CVEID}}{{.Info.Classification.CVEID}}{{else}}-{{end}}</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .MediumVulns}}
        <div class="card">
            <h2>Medium Vulnerabilities</h2>
            <table>
                <tr><th>Template</th><th>Name</th><th>Host</th></tr>
                {{range .MediumVulns}}
                <tr>
                    <td>{{.TemplateID}}</td>
                    <td class="severity-medium">{{.Info.Name}}</td>
                    <td>{{.Host}}</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        <footer>
            <p>Generated by ASM Tool</p>
        </footer>
    </div>
</body>
</html>`

	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return "", err
	}

	groupedVulns := groupVulnerabilitiesBySeverity(result)
	data := map[string]interface{}{
		"Domain":         result.Domain,
		"ScanTime":       result.StartTime.Format(time.RFC3339),
		"Duration":       result.Duration.Round(time.Millisecond).String(),
		"SubdomainCount": len(result.Subdomains),
		"PortCount":      len(result.Ports),
		"CertCount":      len(result.Certificates),
		"TakeoverCount":  countVulnerableTakeovers(result),
		"TechCount":      countTechnologies(result),
		"URLCount":       len(result.URLs),
		"APICount":       len(result.APIs),
		"EmailCount":     len(result.Emails),
		"BucketCount":    len(result.CloudStorage),
		"VulnCount":      groupedVulns.Total,
		"Subdomains":     result.Subdomains,
		"Ports":          result.Ports,
		"Certificates":   result.Certificates,
		"VulnTakeovers":  getVulnerableTakeovers(result),
		"PublicBuckets":  getPublicBuckets(result),
		"APIs":           result.APIs,
		"Emails":         result.Emails,
		"CriticalVulns":  groupedVulns.Critical,
		"HighVulns":      groupedVulns.High,
		"MediumVulns":    groupedVulns.Medium,
	}

	var sb strings.Builder
	if err := t.Execute(&sb, data); err != nil {
		return "", err
	}

	return sb.String(), nil
}

// Helper functions
func countVulnerableTakeovers(result *parallel.ScanResult) int {
	count := 0
	for _, t := range result.Takeovers {
		if t.Vulnerable {
			count++
		}
	}
	return count
}

func getVulnerableTakeovers(result *parallel.ScanResult) []parallel.TakeoverResult {
	var vulns []parallel.TakeoverResult
	for _, t := range result.Takeovers {
		if t.Vulnerable {
			vulns = append(vulns, t)
		}
	}
	return vulns
}

func countTechnologies(result *parallel.ScanResult) int {
	count := 0
	for _, t := range result.Technologies {
		count += len(t.Technologies)
	}
	return count
}

func countPublicBuckets(result *parallel.ScanResult) int {
	count := 0
	for _, b := range result.CloudStorage {
		if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
			count++
		}
	}
	return count
}

func getPublicBuckets(result *parallel.ScanResult) []parallel.CloudBucket {
	var buckets []parallel.CloudBucket
	for _, b := range result.CloudStorage {
		if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
			buckets = append(buckets, b)
		}
	}
	return buckets
}

type groupedVulnerabilities struct {
	Total    int
	Critical []*parallel.VulnFinding
	High     []*parallel.VulnFinding
	Medium   []*parallel.VulnFinding
	Low      []*parallel.VulnFinding
	Info     []*parallel.VulnFinding
}

func groupVulnerabilitiesBySeverity(result *parallel.ScanResult) groupedVulnerabilities {
	grouped := groupedVulnerabilities{}
	for _, v := range result.Vulnerabilities {
		grouped.Total++
		switch strings.ToLower(v.Info.Severity) {
		case "critical":
			grouped.Critical = append(grouped.Critical, v)
		case "high":
			grouped.High = append(grouped.High, v)
		case "medium":
			grouped.Medium = append(grouped.Medium, v)
		case "low":
			grouped.Low = append(grouped.Low, v)
		case "info":
			grouped.Info = append(grouped.Info, v)
		}
	}
	return grouped
}
