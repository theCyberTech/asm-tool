package dashboard

import (
	"database/sql"
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
	ActivePage    string
	Stats         Stats
	Findings      FindingCounts
	Domains       []DomainStats
	DomainDetail  *DomainDetailData
	GlobalList    *GlobalListData
	ChangeEvents  []ChangeEventView
	Error         string
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
	ID             int64
	Domain         string
	AddedAt        time.Time
	LastScanned    *time.Time
	SubdomainCount int
	PortCount      int
	CriticalCount  int
	HighCount      int
}

// Stats represents asset counts
type Stats struct {
	Domains      int
	Subdomains   int
	Ports        int
	Certificates int
	URLs         int
	APIs         int
	Emails       int
	CloudBuckets int
	Takeovers    int
}

// FindingCounts represents finding severity counts
type FindingCounts struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// DomainDetailData holds all data for the domain detail page
type DomainDetailData struct {
	Domain        string
	AddedAt       time.Time
	LastScanned   *time.Time
	Stats         DomainDetailStats
	Subdomains    []SubdomainView
	Ports         []PortView
	Certificates  []CertificateView
	Technologies  []TechnologyView
	DNSRecords    []DNSRecordView
	Findings      []FindingView
	URLs          []URLView
	APIs          []APIView
	Emails        []EmailView
	CloudStorage  []CloudStorageView
	Takeovers     []TakeoverView
	ChangeEvents  []ChangeEventView
}

// ChangeEventView represents a DNS change event for display
type ChangeEventView struct {
	Domain      string
	ChangeType  string
	Severity    string
	Description string
	OldValue    string
	NewValue    string
	Timestamp   time.Time
}

// DomainDetailStats holds counts for the domain detail page
type DomainDetailStats struct {
	SubdomainCount   int
	PortCount        int
	CertificateCount int
	TechnologyCount  int
	DNSRecordCount   int
	VulnCount        int
	URLCount         int
	APICount         int
	EmailCount       int
	CloudCount       int
	TakeoverCount    int
}

// SubdomainView represents a subdomain for display
type SubdomainView struct {
	Subdomain    string
	DiscoveredAt time.Time
	LastSeen     time.Time
}

// PortView represents a port for display
type PortView struct {
	Host         string
	Port         int
	Protocol     string
	Service      string
	Version      string
	Product      string
	State        string
	Banner       string
	DiscoveredAt time.Time
}

// CertificateView represents a certificate for display
type CertificateView struct {
	Host            string
	Port            int
	Subject         string
	Issuer          string
	NotAfter        time.Time
	DaysUntilExpiry int
	SAN             string
}

// TechnologyView represents a technology fingerprint for display
type TechnologyView struct {
	Host         string
	StatusCode   int
	Title        string
	Server       string
	Technologies string
	CheckedAt    time.Time
}

// DNSRecordView represents DNS records for display
type DNSRecordView struct {
	Domain    string
	Records   string
	CheckedAt time.Time
}

// FindingView represents a vulnerability finding for display
type FindingView struct {
	ID           int64
	Name         string
	Severity     string
	Description  string
	Host         string
	MatchedAt    string
	Tags         string
	DiscoveredAt time.Time
}

// URLView represents a URL for display
type URLView struct {
	URL          string
	Domain       string
	Category     sql.NullString
	Interesting  bool
	Source       string
	DiscoveredAt time.Time
}

// APIView represents an API endpoint for display
type APIView struct {
	URL          string
	Type         sql.NullString
	Title        sql.NullString
	Version      sql.NullString
	DiscoveredAt time.Time
}

// EmailView represents an email address for display
type EmailView struct {
	Address      string
	Source       string
	DiscoveredAt time.Time
}

// CloudStorageView represents a cloud storage bucket for display
type CloudStorageView struct {
	Provider    string
	BucketName  string
	URL         string
	AccessLevel string
	Severity    string
	Evidence    string
	Status      string
}

// TakeoverView represents a subdomain takeover for display
type TakeoverView struct {
	Subdomain    string
	CNAME        string
	Service      string
	TakeoverType string
	Confidence   string
	Evidence     string
	DiscoveredAt time.Time
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
