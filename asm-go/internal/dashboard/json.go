package dashboard

import (
	"database/sql"
	"time"
)

// JSONOverview is the payload for GET /api/overview.
type JSONOverview struct {
	Status       string            `json:"status"`
	Stats        JSONStats         `json:"stats"`
	Findings     JSONFindingCounts `json:"findings"`
	Domains      []JSONDomain      `json:"domains"`
	ChangeEvents []JSONChangeEvent `json:"change_events"`
	Warning      string            `json:"warning,omitempty"`
}

// JSONStats holds aggregate asset counts.
type JSONStats struct {
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

// JSONFindingCounts holds vulnerability totals by severity.
type JSONFindingCounts struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// JSONDomain is a monitored domain with summary stats.
type JSONDomain struct {
	ID             int64      `json:"id"`
	Domain         string     `json:"domain"`
	AddedAt        time.Time  `json:"added_at"`
	LastScanned    *time.Time `json:"last_scanned,omitempty"`
	SubdomainCount int        `json:"subdomain_count"`
	PortCount      int        `json:"port_count"`
	CriticalCount  int        `json:"critical_count"`
	HighCount      int        `json:"high_count"`
}

// JSONDomainDetail is the domain detail payload.
type JSONDomainDetail struct {
	Status       string                `json:"status"`
	Domain       string                `json:"domain"`
	AddedAt      time.Time             `json:"added_at"`
	LastScanned  *time.Time            `json:"last_scanned,omitempty"`
	Stats        JSONDomainDetailStats `json:"stats"`
	Subdomains   []JSONSubdomain       `json:"subdomains"`
	Ports        []JSONPort            `json:"ports"`
	Certificates []JSONCertificate     `json:"certificates"`
	Technologies []JSONTechnology      `json:"technologies"`
	DNSRecords   []JSONDNSRecord       `json:"dns_records"`
	Findings     []JSONFinding         `json:"findings"`
	URLs         []JSONURL             `json:"urls"`
	APIs         []JSONAPI             `json:"apis"`
	Emails       []JSONEmail           `json:"emails"`
	CloudStorage []JSONCloudStorage    `json:"cloud_storage"`
	Takeovers    []JSONTakeover        `json:"takeovers"`
	ChangeEvents []JSONChangeEvent     `json:"change_events"`
	Warning      string                `json:"warning,omitempty"`
}

// JSONDomainDetailStats holds per-module counts for one domain.
type JSONDomainDetailStats struct {
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

// JSONAssetList is a typed list of one finding kind.
type JSONAssetList struct {
	Status string `json:"status"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Count  int    `json:"count"`
	Items  any    `json:"items"`
}

// JSONOperations is the operations dashboard payload.
type JSONOperations struct {
	Status       string       `json:"status"`
	Enabled      bool         `json:"enabled"`
	Actions      []JSONAction `json:"actions"`
	Runs         []JSONRun    `json:"runs"`
	RunningCount int          `json:"running_count"`
	BinaryPath   string       `json:"binary_path"`
	ConfigPath   string       `json:"config_path"`
	DatabasePath string       `json:"database_path"`
	LogPath      string       `json:"log_path"`
}

// JSONAction describes a runnable operations workflow.
type JSONAction struct {
	ID                   string `json:"id"`
	Label                string `json:"label"`
	RequiresTarget       bool   `json:"requires_target"`
	SupportsAllKnown     bool   `json:"supports_all_known"`
	SupportsPorts        bool   `json:"supports_ports"`
	SupportsOutputFormat bool   `json:"supports_output_format"`
	SupportsNuclei       bool   `json:"supports_nuclei"`
}

// JSONRun is a recorded operations command.
type JSONRun struct {
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

// JSONChangeEvent is a recorded surface change.
type JSONChangeEvent struct {
	Domain      string    `json:"domain"`
	ChangeType  string    `json:"change_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	OldValue    string    `json:"old_value"`
	NewValue    string    `json:"new_value"`
	Timestamp   time.Time `json:"timestamp"`
}

// JSONSubdomain is a discovered hostname.
type JSONSubdomain struct {
	Subdomain    string    `json:"subdomain"`
	DiscoveredAt time.Time `json:"discovered_at"`
	LastSeen     time.Time `json:"last_seen"`
}

// JSONPort is an open port record.
type JSONPort struct {
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

// JSONCertificate is a TLS certificate record.
type JSONCertificate struct {
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	SAN             string    `json:"san"`
}

// JSONTechnology is a fingerprint record.
type JSONTechnology struct {
	Host         string    `json:"host"`
	StatusCode   int       `json:"status_code"`
	Title        string    `json:"title"`
	Server       string    `json:"server"`
	Technologies string    `json:"technologies"`
	CheckedAt    time.Time `json:"checked_at"`
}

// JSONDNSRecord is a DNS snapshot.
type JSONDNSRecord struct {
	Domain    string    `json:"domain"`
	Records   string    `json:"records"`
	CheckedAt time.Time `json:"checked_at"`
}

// JSONFinding is a vulnerability finding.
type JSONFinding struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Severity     string    `json:"severity"`
	Description  string    `json:"description"`
	Host         string    `json:"host"`
	MatchedAt    string    `json:"matched_at"`
	Tags         string    `json:"tags"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// JSONURL is a discovered URL.
type JSONURL struct {
	URL          string    `json:"url"`
	Domain       string    `json:"domain"`
	Category     *string   `json:"category,omitempty"`
	Interesting  bool      `json:"interesting"`
	Source       string    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// JSONAPI is a discovered API endpoint.
type JSONAPI struct {
	URL          string    `json:"url"`
	Type         *string   `json:"type,omitempty"`
	Title        *string   `json:"title,omitempty"`
	Version      *string   `json:"version,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// JSONEmail is a discovered email address.
type JSONEmail struct {
	Address      string    `json:"address"`
	Source       string    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// JSONCloudStorage is a cloud bucket finding.
type JSONCloudStorage struct {
	Provider    string `json:"provider"`
	BucketName  string `json:"bucket_name"`
	URL         string `json:"url"`
	AccessLevel string `json:"access_level"`
	Severity    string `json:"severity"`
	Evidence    string `json:"evidence"`
	Status      string `json:"status"`
}

// JSONTakeover is a subdomain takeover risk.
type JSONTakeover struct {
	Subdomain    string    `json:"subdomain"`
	CNAME        string    `json:"cname"`
	Service      string    `json:"service"`
	TakeoverType string    `json:"takeover_type"`
	Confidence   string    `json:"confidence"`
	Evidence     string    `json:"evidence"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// OverviewJSON converts page data into the overview API payload.
func OverviewJSON(data PageData) JSONOverview {
	status := "ok"
	if data.Error != "" {
		status = "error"
	}
	return JSONOverview{
		Status:       status,
		Stats:        StatsJSON(data.Stats),
		Findings:     FindingCountsJSON(data.Findings),
		Domains:      DomainsJSON(data.Domains),
		ChangeEvents: ChangeEventsJSON(data.ChangeEvents),
		Warning:      firstNonEmpty(data.Warning, data.Error),
	}
}

// StatsJSON converts template stats to JSON.
func StatsJSON(s Stats) JSONStats {
	return JSONStats{
		Domains:      s.Domains,
		Subdomains:   s.Subdomains,
		Ports:        s.Ports,
		Certificates: s.Certificates,
		URLs:         s.URLs,
		APIs:         s.APIs,
		Emails:       s.Emails,
		CloudBuckets: s.CloudBuckets,
		Takeovers:    s.Takeovers,
	}
}

// FindingCountsJSON converts template finding counts to JSON.
func FindingCountsJSON(f FindingCounts) JSONFindingCounts {
	return JSONFindingCounts{
		Total:    f.Total,
		Critical: f.Critical,
		High:     f.High,
		Medium:   f.Medium,
		Low:      f.Low,
		Info:     f.Info,
	}
}

// DomainsJSON converts domain cards to JSON.
func DomainsJSON(domains []DomainStats) []JSONDomain {
	out := make([]JSONDomain, len(domains))
	for i, d := range domains {
		out[i] = JSONDomain{
			ID:             d.ID,
			Domain:         d.Domain,
			AddedAt:        d.AddedAt,
			LastScanned:    d.LastScanned,
			SubdomainCount: d.SubdomainCount,
			PortCount:      d.PortCount,
			CriticalCount:  d.CriticalCount,
			HighCount:      d.HighCount,
		}
	}
	return out
}

// DomainDetailJSON converts a domain detail page to JSON.
func DomainDetailJSON(data PageData) JSONDomainDetail {
	status := "ok"
	if data.Error != "" || data.DomainDetail == nil {
		status = "error"
	}
	out := JSONDomainDetail{Status: status, Warning: firstNonEmpty(data.Warning, data.Error)}
	if data.DomainDetail == nil {
		return out
	}
	d := data.DomainDetail
	out.Domain = d.Domain
	out.AddedAt = d.AddedAt
	out.LastScanned = d.LastScanned
	out.Stats = JSONDomainDetailStats{
		SubdomainCount:   d.Stats.SubdomainCount,
		PortCount:        d.Stats.PortCount,
		CertificateCount: d.Stats.CertificateCount,
		TechnologyCount:  d.Stats.TechnologyCount,
		DNSRecordCount:   d.Stats.DNSRecordCount,
		VulnCount:        d.Stats.VulnCount,
		URLCount:         d.Stats.URLCount,
		APICount:         d.Stats.APICount,
		EmailCount:       d.Stats.EmailCount,
		CloudCount:       d.Stats.CloudCount,
		TakeoverCount:    d.Stats.TakeoverCount,
	}
	out.Subdomains = SubdomainsJSON(d.Subdomains)
	out.Ports = PortsJSON(d.Ports)
	out.Certificates = CertificatesJSON(d.Certificates)
	out.Technologies = TechnologiesJSON(d.Technologies)
	out.DNSRecords = DNSRecordsJSON(d.DNSRecords)
	out.Findings = FindingsJSON(d.Findings)
	out.URLs = URLsJSON(d.URLs)
	out.APIs = APIsJSON(d.APIs)
	out.Emails = EmailsJSON(d.Emails)
	out.CloudStorage = CloudStorageJSON(d.CloudStorage)
	out.Takeovers = TakeoversJSON(d.Takeovers)
	out.ChangeEvents = ChangeEventsJSON(d.ChangeEvents)
	return out
}

// OperationsJSON converts operations page data to JSON.
func OperationsJSON(data *OperationsData) JSONOperations {
	if data == nil {
		return JSONOperations{Status: "ok", Actions: []JSONAction{}, Runs: []JSONRun{}}
	}
	actions := make([]JSONAction, len(data.Actions))
	for i, a := range data.Actions {
		actions[i] = JSONAction{
			ID:                   a.ID,
			Label:                a.Label,
			RequiresTarget:       a.RequiresTarget,
			SupportsAllKnown:     a.SupportsAllKnown,
			SupportsPorts:        a.SupportsPorts,
			SupportsOutputFormat: a.SupportsOutputFormat,
			SupportsNuclei:       a.SupportsNuclei,
		}
	}
	return JSONOperations{
		Status:       "ok",
		Enabled:      data.Enabled,
		Actions:      actions,
		Runs:         RunsJSON(data.Runs),
		RunningCount: data.RunningCount,
		BinaryPath:   data.BinaryPath,
		ConfigPath:   data.ConfigPath,
		DatabasePath: data.DatabasePath,
		LogPath:      data.LogPath,
	}
}

// RunsJSON converts run records to JSON.
func RunsJSON(runs []RunRecord) []JSONRun {
	out := make([]JSONRun, len(runs))
	for i, r := range runs {
		out[i] = JSONRun{
			ID:         r.ID,
			Action:     r.Action,
			Label:      r.Label,
			Command:    r.Command,
			Target:     r.Target,
			Status:     r.Status,
			ExitCode:   r.ExitCode,
			StartedAt:  r.StartedAt,
			FinishedAt: r.FinishedAt,
			Duration:   r.Duration,
			Stdout:     r.Stdout,
			Stderr:     r.Stderr,
			Error:      r.Error,
			Truncated:  r.Truncated,
		}
	}
	return out
}

// ChangeEventsJSON converts change events to JSON.
func ChangeEventsJSON(events []ChangeEventView) []JSONChangeEvent {
	out := make([]JSONChangeEvent, len(events))
	for i, e := range events {
		out[i] = JSONChangeEvent{
			Domain:      e.Domain,
			ChangeType:  e.ChangeType,
			Severity:    e.Severity,
			Description: e.Description,
			OldValue:    e.OldValue,
			NewValue:    e.NewValue,
			Timestamp:   e.Timestamp,
		}
	}
	return out
}

// SubdomainsJSON converts subdomain views to JSON.
func SubdomainsJSON(rows []SubdomainView) []JSONSubdomain {
	out := make([]JSONSubdomain, len(rows))
	for i, s := range rows {
		out[i] = JSONSubdomain{Subdomain: s.Subdomain, DiscoveredAt: s.DiscoveredAt, LastSeen: s.LastSeen}
	}
	return out
}

// PortsJSON converts port views to JSON.
func PortsJSON(rows []PortView) []JSONPort {
	out := make([]JSONPort, len(rows))
	for i, p := range rows {
		out[i] = JSONPort{
			Host: p.Host, Port: p.Port, Protocol: p.Protocol, Service: p.Service,
			Version: p.Version, Product: p.Product, State: p.State, Banner: p.Banner,
			DiscoveredAt: p.DiscoveredAt,
		}
	}
	return out
}

// CertificatesJSON converts certificate views to JSON.
func CertificatesJSON(rows []CertificateView) []JSONCertificate {
	out := make([]JSONCertificate, len(rows))
	for i, c := range rows {
		out[i] = JSONCertificate{
			Host: c.Host, Port: c.Port, Subject: c.Subject, Issuer: c.Issuer,
			NotAfter: c.NotAfter, DaysUntilExpiry: c.DaysUntilExpiry, SAN: c.SAN,
		}
	}
	return out
}

// TechnologiesJSON converts technology views to JSON.
func TechnologiesJSON(rows []TechnologyView) []JSONTechnology {
	out := make([]JSONTechnology, len(rows))
	for i, t := range rows {
		out[i] = JSONTechnology{
			Host: t.Host, StatusCode: t.StatusCode, Title: t.Title, Server: t.Server,
			Technologies: t.Technologies, CheckedAt: t.CheckedAt,
		}
	}
	return out
}

// DNSRecordsJSON converts DNS views to JSON.
func DNSRecordsJSON(rows []DNSRecordView) []JSONDNSRecord {
	out := make([]JSONDNSRecord, len(rows))
	for i, d := range rows {
		out[i] = JSONDNSRecord{Domain: d.Domain, Records: d.Records, CheckedAt: d.CheckedAt}
	}
	return out
}

// FindingsJSON converts finding views to JSON.
func FindingsJSON(rows []FindingView) []JSONFinding {
	out := make([]JSONFinding, len(rows))
	for i, f := range rows {
		out[i] = JSONFinding{
			ID: f.ID, Name: f.Name, Severity: f.Severity, Description: f.Description,
			Host: f.Host, MatchedAt: f.MatchedAt, Tags: f.Tags, DiscoveredAt: f.DiscoveredAt,
		}
	}
	return out
}

// URLsJSON converts URL views to JSON.
func URLsJSON(rows []URLView) []JSONURL {
	out := make([]JSONURL, len(rows))
	for i, u := range rows {
		out[i] = JSONURL{
			URL: u.URL, Domain: u.Domain, Category: nullStringPtr(u.Category),
			Interesting: u.Interesting, Source: u.Source, DiscoveredAt: u.DiscoveredAt,
		}
	}
	return out
}

// APIsJSON converts API views to JSON.
func APIsJSON(rows []APIView) []JSONAPI {
	out := make([]JSONAPI, len(rows))
	for i, a := range rows {
		out[i] = JSONAPI{
			URL: a.URL, Type: nullStringPtr(a.Type), Title: nullStringPtr(a.Title),
			Version: nullStringPtr(a.Version), DiscoveredAt: a.DiscoveredAt,
		}
	}
	return out
}

// EmailsJSON converts email views to JSON.
func EmailsJSON(rows []EmailView) []JSONEmail {
	out := make([]JSONEmail, len(rows))
	for i, e := range rows {
		out[i] = JSONEmail{Address: e.Address, Source: e.Source, DiscoveredAt: e.DiscoveredAt}
	}
	return out
}

// CloudStorageJSON converts cloud storage views to JSON.
func CloudStorageJSON(rows []CloudStorageView) []JSONCloudStorage {
	out := make([]JSONCloudStorage, len(rows))
	for i, c := range rows {
		out[i] = JSONCloudStorage{
			Provider: c.Provider, BucketName: c.BucketName, URL: c.URL,
			AccessLevel: c.AccessLevel, Severity: c.Severity, Evidence: c.Evidence, Status: c.Status,
		}
	}
	return out
}

// TakeoversJSON converts takeover views to JSON.
func TakeoversJSON(rows []TakeoverView) []JSONTakeover {
	out := make([]JSONTakeover, len(rows))
	for i, t := range rows {
		out[i] = JSONTakeover{
			Subdomain: t.Subdomain, CNAME: t.CNAME, Service: t.Service,
			TakeoverType: t.TakeoverType, Confidence: t.Confidence, Evidence: t.Evidence,
			DiscoveredAt: t.DiscoveredAt,
		}
	}
	return out
}

func nullStringPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	s := ns.String
	return &s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
