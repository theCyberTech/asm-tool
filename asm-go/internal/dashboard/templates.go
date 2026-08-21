package dashboard

import (
	"embed"
	"html/template"
	"io"
	"sync"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

var (
	templates     *template.Template
	templatesOnce sync.Once
	templateErr   error
)

// PageData represents the data passed to templates
type PageData struct {
	ActivePage   string
	Stats        Stats
	Findings     FindingCounts
	Domains      []DomainStats
	DomainDetail *DomainDetailData
	GlobalList   *GlobalListData
	Operations   *OperationsData
	ChangeEvents []ChangeEventView
	Error        string
	Warning      string
}

// OperationsData holds command runner state for the operations dashboard.
type OperationsData struct {
	Enabled      bool              `json:"enabled"`
	Actions      []OperationOption `json:"actions"`
	Runs         []RunRecord       `json:"runs"`
	RunningCount int               `json:"running_count"`
	BinaryPath   string            `json:"binary_path"`
	ConfigPath   string            `json:"config_path"`
	DatabasePath string            `json:"database_path"`
	LogPath      string            `json:"log_path"`
}

// OperationOption represents a safe tool workflow available from the dashboard.
type OperationOption struct {
	ID                   string `json:"id"`
	Label                string `json:"label"`
	RequiresTarget       bool   `json:"requires_target"`
	SupportsAllKnown     bool   `json:"supports_all_known"`
	SupportsPorts        bool   `json:"supports_ports"`
	SupportsOutputFormat bool   `json:"supports_output_format"`
	SupportsNuclei       bool   `json:"supports_nuclei"`
}

// RunRecord represents a command execution shown in the dashboard.
type RunRecord struct {
	ID         int64      `json:"id"`
	Action     string     `json:"action"`
	Label      string     `json:"label"`
	Command    string     `json:"command"`
	Target     string     `json:"target"`
	Status     string     `json:"status"`
	ExitCode   int        `json:"exit_code"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Duration   string     `json:"duration,omitempty"`
	Stdout     string     `json:"stdout"`
	Stderr     string     `json:"stderr"`
	Error      string     `json:"error,omitempty"`
	Truncated  bool       `json:"truncated"`
}

// GlobalListData holds data for the global asset list pages
type GlobalListData struct {
	Title        string
	Subdomains   []SubdomainView
	Ports        []PortView
	Certificates []CertificateView
	URLs         []URLView
	APIs         []APIView
	Emails       []EmailView
	CloudStorage []CloudStorageView
	Findings     []FindingView
	Takeovers    []TakeoverView
}

// DomainStats represents a domain with its aggregate statistics for display
type DomainStats struct {
	ID             int64      `json:"id"`
	Domain         string     `json:"domain"`
	AddedAt        time.Time  `json:"added_at"`
	LastScanned    *time.Time `json:"last_scanned,omitempty"`
	SubdomainCount int        `json:"subdomain_count"`
	PortCount      int        `json:"port_count"`
	CriticalCount  int        `json:"critical_count"`
	HighCount      int        `json:"high_count"`
}

// Stats represents asset counts
type Stats struct {
	Domains      int `json:"domains"`
	Subdomains   int `json:"subdomains"`
	Ports        int `json:"ports"`
	Certificates int `json:"certificates"`
	URLs         int `json:"urls"`
	APIs         int `json:"apis"`
	Emails       int `json:"emails"`
	CloudBuckets int `json:"cloud_buckets"`
	Takeovers    int `json:"takeovers"`
}

// FindingCounts represents finding severity counts
type FindingCounts struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// DomainDetailData holds all data for the domain detail page
type DomainDetailData struct {
	Domain       string             `json:"domain"`
	AddedAt      time.Time          `json:"added_at"`
	LastScanned  *time.Time         `json:"last_scanned,omitempty"`
	Stats        DomainDetailStats  `json:"stats"`
	Subdomains   []SubdomainView    `json:"subdomains"`
	Ports        []PortView         `json:"ports"`
	Certificates []CertificateView  `json:"certificates"`
	Technologies []TechnologyView   `json:"technologies"`
	DNSRecords   []DNSRecordView    `json:"dns_records"`
	Findings     []FindingView      `json:"findings"`
	URLs         []URLView          `json:"urls"`
	APIs         []APIView          `json:"apis"`
	Emails       []EmailView        `json:"emails"`
	CloudStorage []CloudStorageView `json:"cloud_storage"`
	Takeovers    []TakeoverView     `json:"takeovers"`
	ChangeEvents []ChangeEventView  `json:"change_events"`
}

// ChangeEventView represents a DNS change event for display
type ChangeEventView struct {
	Domain      string    `json:"domain"`
	ChangeType  string    `json:"change_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	OldValue    string    `json:"old_value"`
	NewValue    string    `json:"new_value"`
	Timestamp   time.Time `json:"timestamp"`
}

// DomainDetailStats holds counts for the domain detail page
type DomainDetailStats struct {
	SubdomainCount   int `json:"subdomain_count"`
	PortCount        int `json:"port_count"`
	CertificateCount int `json:"certificate_count"`
	TechnologyCount  int `json:"technology_count"`
	DNSRecordCount   int `json:"dns_record_count"`
	VulnCount        int `json:"vuln_count"`
	URLCount         int `json:"url_count"`
	APICount         int `json:"api_count"`
	EmailCount       int `json:"email_count"`
	CloudCount       int `json:"cloud_count"`
	TakeoverCount    int `json:"takeover_count"`
}

// SubdomainView represents a subdomain for display
type SubdomainView struct {
	Subdomain    string    `json:"subdomain"`
	DiscoveredAt time.Time `json:"discovered_at"`
	LastSeen     time.Time `json:"last_seen"`
}

// PortView represents a port for display
type PortView struct {
	Host         string    `json:"host"`
	Port         int       `json:"port"`
	Protocol     string    `json:"protocol"`
	Service      string    `json:"service"`
	Version      string    `json:"version"`
	Product      string    `json:"product"`
	State        string    `json:"state"`
	Banner       string    `json:"banner"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// CertificateView represents a certificate for display
type CertificateView struct {
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	SAN             string    `json:"san"`
}

// TechnologyView represents a technology fingerprint for display
type TechnologyView struct {
	Host         string    `json:"host"`
	StatusCode   int       `json:"status_code"`
	Title        string    `json:"title"`
	Server       string    `json:"server"`
	Technologies string    `json:"technologies"`
	CheckedAt    time.Time `json:"checked_at"`
}

// DNSRecordView represents DNS records for display
type DNSRecordView struct {
	Domain    string    `json:"domain"`
	Records   string    `json:"records"`
	CheckedAt time.Time `json:"checked_at"`
}

// FindingView represents a vulnerability finding for display
type FindingView struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Severity     string    `json:"severity"`
	Description  string    `json:"description"`
	Host         string    `json:"host"`
	MatchedAt    string    `json:"matched_at"`
	Tags         string    `json:"tags"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// URLView represents a URL for display
type URLView struct {
	URL          string    `json:"url"`
	Domain       string    `json:"domain"`
	Category     string    `json:"category,omitempty"`
	Interesting  bool      `json:"interesting"`
	Source       string    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// APIView represents an API endpoint for display
type APIView struct {
	URL          string    `json:"url"`
	Type         string    `json:"type,omitempty"`
	Title        string    `json:"title,omitempty"`
	Version      string    `json:"version,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// EmailView represents an email address for display
type EmailView struct {
	Address      string    `json:"address"`
	Source       string    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// CloudStorageView represents a cloud storage bucket for display
type CloudStorageView struct {
	Provider    string `json:"provider"`
	BucketName  string `json:"bucket_name"`
	URL         string `json:"url"`
	AccessLevel string `json:"access_level"`
	Severity    string `json:"severity"`
	Evidence    string `json:"evidence"`
	Status      string `json:"status"`
}

// TakeoverView represents a subdomain takeover for display
type TakeoverView struct {
	Subdomain    string    `json:"subdomain"`
	CNAME        string    `json:"cname"`
	Service      string    `json:"service"`
	TakeoverType string    `json:"takeover_type"`
	Confidence   string    `json:"confidence"`
	Evidence     string    `json:"evidence"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Templates returns the parsed template collection
func Templates() (*template.Template, error) {
	templatesOnce.Do(func() {
		templates, templateErr = template.ParseFS(templateFS, "templates/*.html")
	})
	return templates, templateErr
}

// RenderPage renders a page using the base template
func RenderPage(w io.Writer, name string, data PageData) error {
	tmpl, err := Templates()
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, name, data)
}

// RenderPartial renders a partial template (for htmx requests)
func RenderPartial(w io.Writer, name string, data interface{}) error {
	tmpl, err := Templates()
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, name, data)
}
