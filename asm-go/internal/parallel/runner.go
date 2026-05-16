package parallel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/scanner/apis"
	"github.com/asm-tool/asm-go/internal/scanner/certificates"
	"github.com/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/asm-tool/asm-go/internal/scanner/dns"
	"github.com/asm-tool/asm-go/internal/scanner/emails"
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/asm-tool/asm-go/internal/scanner/ports"
	"github.com/asm-tool/asm-go/internal/scanner/subdomains"
	"github.com/asm-tool/asm-go/internal/scanner/takeover"
	"github.com/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/asm-tool/asm-go/internal/scanner/urls"
)

// ModuleType represents the type of scanner module
type ModuleType string

const (
	ModuleSubdomains   ModuleType = "subdomains"
	ModulePorts        ModuleType = "ports"
	ModuleCertificates ModuleType = "certificates"
	ModuleDNS          ModuleType = "dns"
	ModuleTakeover     ModuleType = "takeover"
	ModuleTechnologies ModuleType = "technologies"
	ModuleURLs         ModuleType = "urls"
	ModuleAPIs         ModuleType = "apis"
	ModuleEmails       ModuleType = "emails"
	ModuleCloudStorage ModuleType = "cloudstorage"
	ModuleNuclei       ModuleType = "nuclei"
)

// PortResult represents an open port
type PortResult struct {
	Host    string
	Port    int
	State   string
	Service string
	Banner  string
}

// DNSRecordSet represents DNS records for a host, including SOA, CAA, and DNSSEC.
type DNSRecordSet struct {
	Host    string
	Records []dns.Record
	SOA     *dns.SOARecord
	CAA     []dns.CAARecord
	DNSSEC  *dns.DNSSECResult
}

// TakeoverResult represents a takeover finding
type TakeoverResult struct {
	Host       string
	Vulnerable bool
	Service    string
	Confidence string
	Evidence   string
}

// Certificate is an alias for certificates.Certificate
type Certificate = certificates.Certificate

// TechResult represents technology detection for a host
type TechResult = technologies.Result

// CloudBucket is an alias for cloud.Bucket
type CloudBucket = cloud.Bucket

// VulnFinding is an alias for nuclei.Finding
type VulnFinding = nuclei.Finding

// VulnInfo is an alias for nuclei.TemplateInfo
type VulnInfo = nuclei.TemplateInfo

// URLResult is an alias for urls.URL
type URLResult = urls.URL

// APIResult is an alias for apis.API
type APIResult = apis.API

// EmailResult is an alias for emails.Email
type EmailResult = emails.Email

// ScanResult holds the complete scan results
type ScanResult struct {
	Domain          string
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	Subdomains      []string
	Ports           []PortResult
	Certificates    []*Certificate
	DNSRecords      []DNSRecordSet
	Takeovers       []TakeoverResult
	Technologies    []*TechResult
	URLs            []urls.URL
	APIs            []apis.API
	Emails          []emails.Email
	CloudStorage    []cloud.Bucket
	Vulnerabilities []*VulnFinding
	Errors          map[ModuleType]error
}

// ProgressCallback is called when a module completes
type ProgressCallback func(module ModuleType, duration time.Duration, err error)

// Runner orchestrates parallel execution of scanner modules
type Runner struct {
	DB                 *database.Database
	EnabledModules     map[ModuleType]bool
	PortWorkers        int
	Ports              []int // ports to scan (nil = use common defaults)
	APIWorkers         int
	TakeoverWorkers    int
	CloudWorkers       int
	HTTPTimeout        time.Duration
	NucleiSeverities   []string
	NucleiRateLimit    int
	RateLimit          int // max requests/sec for passive HTTP sources (0 = unlimited)
	InsecureSkipVerify bool
	OnProgress         ProgressCallback
}

// DefaultRunner creates a runner with default settings
func DefaultRunner(db *database.Database) *Runner {
	return &Runner{
		DB: db,
		EnabledModules: map[ModuleType]bool{
			ModuleSubdomains:   true,
			ModulePorts:        true,
			ModuleCertificates: true,
			ModuleDNS:          true,
			ModuleTakeover:     true,
			ModuleTechnologies: true,
			ModuleURLs:         true,
			ModuleAPIs:         true,
			ModuleEmails:       true,
			ModuleCloudStorage: true,
			ModuleNuclei:       false, // Disabled by default (requires nuclei installed)
		},
		PortWorkers:      100,
		APIWorkers:       30,
		TakeoverWorkers:  50,
		CloudWorkers:     20,
		HTTPTimeout:      10 * time.Second,
		NucleiSeverities: []string{"critical", "high"},
		NucleiRateLimit:  150,
	}
}

// Run executes a full scan for the given domain
func (r *Runner) Run(ctx context.Context, domain string) (*ScanResult, error) {
	result := &ScanResult{
		Domain:    domain,
		StartTime: time.Now(),
		Errors:    make(map[ModuleType]error),
	}

	// Phase 1: Subdomain enumeration (must complete first)
	if r.isEnabled(ModuleSubdomains) {
		r.reportProgress(ModuleSubdomains, 0, nil)
		start := time.Now()
		subs, err := r.runSubdomains(ctx, domain)
		duration := time.Since(start)
		if err != nil {
			result.Errors[ModuleSubdomains] = err
		}
		result.Subdomains = subs
		r.reportProgress(ModuleSubdomains, duration, err)
	}

	// Check context
	if ctx.Err() != nil {
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result, ctx.Err()
	}

	// If no subdomains, use domain itself
	hosts := result.Subdomains
	if len(hosts) == 0 {
		hosts = []string{domain}
	}

	// Phase 2: Independent modules in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Ports scan
	if r.isEnabled(ModulePorts) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			portResults, err := r.runPorts(ctx, hosts)
			duration := time.Since(start)
			mu.Lock()
			result.Ports = portResults
			if err != nil {
				result.Errors[ModulePorts] = err
			}
			mu.Unlock()
			r.reportProgress(ModulePorts, duration, err)
		}()
	}

	// Certificates
	if r.isEnabled(ModuleCertificates) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			certs, err := r.runCertificates(ctx, hosts)
			duration := time.Since(start)
			mu.Lock()
			result.Certificates = certs
			if err != nil {
				result.Errors[ModuleCertificates] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleCertificates, duration, err)
		}()
	}

	// DNS
	if r.isEnabled(ModuleDNS) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			records, err := r.runDNS(ctx, hosts)
			duration := time.Since(start)
			mu.Lock()
			result.DNSRecords = records
			if err != nil {
				result.Errors[ModuleDNS] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleDNS, duration, err)
		}()
	}

	// Takeover detection
	if r.isEnabled(ModuleTakeover) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			takeovers, err := r.runTakeover(ctx, hosts)
			duration := time.Since(start)
			mu.Lock()
			result.Takeovers = takeovers
			if err != nil {
				result.Errors[ModuleTakeover] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleTakeover, duration, err)
		}()
	}

	// Technologies
	if r.isEnabled(ModuleTechnologies) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			techs, err := r.runTechnologies(ctx, hosts)
			duration := time.Since(start)
			mu.Lock()
			result.Technologies = techs
			if err != nil {
				result.Errors[ModuleTechnologies] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleTechnologies, duration, err)
		}()
	}

	// URLs
	if r.isEnabled(ModuleURLs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			urlResults, err := r.runURLs(ctx, domain)
			duration := time.Since(start)
			mu.Lock()
			result.URLs = urlResults
			if err != nil {
				result.Errors[ModuleURLs] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleURLs, duration, err)
		}()
	}

	// APIs
	if r.isEnabled(ModuleAPIs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			apiResults, err := r.runAPIs(ctx, hosts)
			duration := time.Since(start)
			mu.Lock()
			result.APIs = apiResults
			if err != nil {
				result.Errors[ModuleAPIs] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleAPIs, duration, err)
		}()
	}

	// Emails
	if r.isEnabled(ModuleEmails) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			emailResults, err := r.runEmails(ctx, domain)
			duration := time.Since(start)
			mu.Lock()
			result.Emails = emailResults
			if err != nil {
				result.Errors[ModuleEmails] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleEmails, duration, err)
		}()
	}

	// Cloud storage
	if r.isEnabled(ModuleCloudStorage) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			buckets, err := r.runCloudStorage(ctx, domain)
			duration := time.Since(start)
			mu.Lock()
			result.CloudStorage = buckets
			if err != nil {
				result.Errors[ModuleCloudStorage] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleCloudStorage, duration, err)
		}()
	}

	// Nuclei vulnerability scanning
	if r.isEnabled(ModuleNuclei) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			vulns, err := r.runNuclei(ctx, hosts)
			duration := time.Since(start)
			mu.Lock()
			result.Vulnerabilities = vulns
			if err != nil {
				result.Errors[ModuleNuclei] = err
			}
			mu.Unlock()
			r.reportProgress(ModuleNuclei, duration, err)
		}()
	}

	// Wait for all modules to complete
	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Persist results to database
	if r.DB != nil {
		if err := r.persistResults(domain, result); err != nil {
			result.Errors[ModuleType("persist")] = err
			return result, err
		}
	}

	return result, nil
}

// persistResults saves all scan results to the database
func (r *Runner) persistResults(domain string, result *ScanResult) error {
	return r.DB.WithTransaction(func(tx *database.Transaction) error {
		return persistResultsInTransaction(tx, domain, result)
	})
}

func persistResultsInTransaction(tx *database.Transaction, domain string, result *ScanResult) error {
	var errs []error

	// Upsert domain and get its ID
	d, err := tx.Domains.Add(domain)
	collectPersistError(&errs, err, "saving domain %q", domain)

	// Subdomains
	if d != nil {
		for _, sub := range result.Subdomains {
			err := tx.Domains.AddSubdomain(d.ID, sub)
			collectPersistError(&errs, err, "saving subdomain %q", sub)
		}
	}

	// Ports
	for _, p := range result.Ports {
		err := tx.Ports.Add(&database.Port{
			Host:    p.Host,
			Port:    p.Port,
			State:   p.State,
			Service: p.Service,
			Banner:  p.Banner,
		})
		collectPersistError(&errs, err, "saving port %s:%d", p.Host, p.Port)
	}

	// Certificates
	for _, c := range result.Certificates {
		sanJSON, err := json.Marshal(c.SAN)
		if err != nil {
			collectPersistError(&errs, err, "encoding certificate SAN for %s:%d", c.Host, c.Port)
			continue
		}
		err = tx.Certificates.Add(&database.Certificate{
			Host:               c.Host,
			Port:               c.Port,
			Subject:            c.Subject,
			Issuer:             c.Issuer,
			SerialNumber:       c.SerialNumber,
			NotBefore:          c.NotBefore,
			NotAfter:           c.NotAfter,
			DaysUntilExpiry:    c.DaysUntilExpiry,
			Fingerprint:        c.Fingerprint,
			SAN:                string(sanJSON),
			SignatureAlgorithm: c.SignatureAlgorithm,
		})
		collectPersistError(&errs, err, "saving certificate %s:%d", c.Host, c.Port)
	}

	// Technologies
	for _, t := range result.Technologies {
		techJSON, err := json.Marshal(t.Technologies)
		if err != nil {
			collectPersistError(&errs, err, "encoding technologies for %q", t.Host)
			continue
		}
		headersJSON, err := json.Marshal(t.Headers)
		if err != nil {
			collectPersistError(&errs, err, "encoding technology headers for %q", t.Host)
			continue
		}
		err = tx.SaveTechnology(t.Host, t.StatusCode, t.Title, t.Server,
			string(techJSON), string(headersJSON), t.ContentLength, t.RedirectURL)
		collectPersistError(&errs, err, "saving technology %q", t.Host)
	}

	// DNS records — store the full result (SOA, CAA, DNSSEC included) and
	// detect changes vs. the previously stored snapshot.
	for _, rset := range result.DNSRecords {
		// Load previous snapshot before overwriting
		prev, err := tx.GetLatestDNSRecord(rset.Host)
		collectPersistError(&errs, err, "loading latest DNS record %q", rset.Host)

		// Serialize the full DNSRecordSet for rich change detection
		fullJSON, err := json.Marshal(rset)
		if err != nil {
			collectPersistError(&errs, err, "encoding DNS record set %q", rset.Host)
			continue
		}
		err = tx.SaveDNSRecords(rset.Host, string(fullJSON))
		collectPersistError(&errs, err, "saving DNS records %q", rset.Host)

		// Detect changes if we have a previous scan
		if prev != nil {
			var prevRset DNSRecordSet
			if err := json.Unmarshal([]byte(prev.Records), &prevRset); err == nil {
				// Build minimal dns.Result objects for comparison
				prevResult := dnsRecordSetToResult(prevRset)
				currResult := dnsRecordSetToResult(rset)
				changes := dns.DetectChanges(currResult, prevResult)
				for _, ch := range changes {
					severity := changeSeverity(ch.RecordType)
					err := tx.SaveChangeEvent(rset.Host, ch.Type, severity, ch.Description, ch.OldValue, ch.NewValue)
					collectPersistError(&errs, err, "saving DNS change event %q", rset.Host)
				}
			}
		}
	}

	// Takeovers (save all, not just vulnerable ones)
	for _, t := range result.Takeovers {
		if t.Vulnerable {
			err := tx.SaveTakeover(t.Host, "", t.Service, t.Confidence, t.Evidence)
			collectPersistError(&errs, err, "saving takeover %q", t.Host)
		}
	}

	// URLs
	for _, u := range result.URLs {
		interesting := 0
		if u.Interesting {
			interesting = 1
		}
		err := tx.SaveURL(u.Domain, u.URL, u.Category, u.Source, interesting)
		collectPersistError(&errs, err, "saving URL %q", u.URL)
	}

	// APIs
	for _, a := range result.APIs {
		endpointsJSON, err := json.Marshal(a.Endpoints)
		if err != nil {
			collectPersistError(&errs, err, "encoding API endpoints for %q", a.URL)
			continue
		}
		err = tx.SaveAPI(a.URL, a.Type, a.Title, a.Version, a.EndpointsCount, string(endpointsJSON))
		collectPersistError(&errs, err, "saving API %q", a.URL)
	}

	// Emails
	for _, e := range result.Emails {
		err := tx.SaveEmail(e.Domain, e.Address, e.Source)
		collectPersistError(&errs, err, "saving email %q", e.Address)
	}

	// Cloud storage
	for _, b := range result.CloudStorage {
		err := tx.SaveCloudBucket(b.Provider, b.BucketName, b.URL, b.Domain, b.AccessLevel, b.Severity, b.Evidence)
		collectPersistError(&errs, err, "saving cloud bucket %q", b.URL)
	}

	// Nuclei vulnerabilities
	for _, v := range result.Vulnerabilities {
		refs, err := json.Marshal(v.Info.Reference)
		if err != nil {
			collectPersistError(&errs, err, "encoding finding references for %q", v.TemplateID)
			continue
		}
		evidence, err := json.Marshal(v.ExtractedResults)
		if err != nil {
			collectPersistError(&errs, err, "encoding finding evidence for %q", v.TemplateID)
			continue
		}
		err = tx.Findings.Add(&database.Finding{
			TemplateID:  v.TemplateID,
			Name:        v.Info.Name,
			Severity:    v.Info.Severity,
			Description: v.Info.Description,
			Host:        v.Host,
			MatchedAt:   v.Matched,
			MatcherName: v.MatcherName,
			Evidence:    string(evidence),
			Refs:        string(refs),
			Tags:        v.Info.Tags,
			Type:        v.Type,
			Status:      "open",
		})
		collectPersistError(&errs, err, "saving finding %q for %q", v.TemplateID, v.Host)
	}

	// Update last_scanned timestamp
	err = tx.UpdateDomainLastScanned(domain)
	collectPersistError(&errs, err, "updating last scanned for %q", domain)

	if len(errs) > 0 {
		return fmt.Errorf("persisting scan results: %w", errors.Join(errs...))
	}

	return nil
}

func collectPersistError(errs *[]error, err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	*errs = append(*errs, fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err))
}

func (r *Runner) isEnabled(module ModuleType) bool {
	return r.EnabledModules[module]
}

func (r *Runner) reportProgress(module ModuleType, duration time.Duration, err error) {
	if r.OnProgress != nil {
		r.OnProgress(module, duration, err)
	}
}

func (r *Runner) runSubdomains(ctx context.Context, domain string) ([]string, error) {
	enum := subdomains.NewEnumeratorWithRateLimit(r.RateLimit)
	result := enum.Enumerate(ctx, domain)
	if len(result.Errors) > 0 {
		return result.Subdomains, fmt.Errorf("subdomain errors: %v", result.Errors)
	}
	return result.Subdomains, nil
}

func (r *Runner) runPorts(ctx context.Context, hosts []string) ([]PortResult, error) {
	scanner := ports.DefaultScanner()
	scanner.Workers = r.PortWorkers

	// Use configured ports or common defaults
	portsToScan := r.Ports
	if len(portsToScan) == 0 {
		portsToScan = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443}
	}

	var results []PortResult
	for _, host := range hosts {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		scanResult := scanner.Scan(ctx, host, portsToScan)
		for _, p := range scanResult.OpenPorts {
			results = append(results, PortResult{
				Host:    host,
				Port:    p.Port,
				State:   p.State,
				Service: p.Service,
				Banner:  p.Banner,
			})
		}
	}
	return results, nil
}

func (r *Runner) runCertificates(ctx context.Context, hosts []string) ([]*Certificate, error) {
	monitor := certificates.DefaultMonitor()
	monitor.InsecureSkipVerify = r.InsecureSkipVerify
	batch := monitor.CheckBatch(ctx, hosts, 443)
	return batch.Certificates, nil
}

func (r *Runner) runDNS(ctx context.Context, hosts []string) ([]DNSRecordSet, error) {
	monitor := dns.DefaultMonitor()
	var results []DNSRecordSet
	for _, host := range hosts {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		dnsResult := monitor.Lookup(ctx, host)
		var records []dns.Record
		for _, recList := range dnsResult.Records {
			records = append(records, recList...)
		}
		results = append(results, DNSRecordSet{
			Host:    host,
			Records: records,
			SOA:     dnsResult.SOA,
			CAA:     dnsResult.CAA,
			DNSSEC:  dnsResult.DNSSEC,
		})
	}
	return results, nil
}

func (r *Runner) runTakeover(ctx context.Context, hosts []string) ([]TakeoverResult, error) {
	detector := takeover.DefaultDetector()
	detector.Workers = r.TakeoverWorkers
	batch := detector.CheckBatch(ctx, hosts)

	var results []TakeoverResult
	for _, f := range batch.Findings {
		results = append(results, TakeoverResult{
			Host:       f.Subdomain,
			Vulnerable: f.Vulnerable,
			Service:    f.Service,
			Confidence: f.Confidence,
			Evidence:   f.Evidence,
		})
	}
	return results, nil
}

func (r *Runner) runTechnologies(ctx context.Context, hosts []string) ([]*TechResult, error) {
	fp := technologies.NewFingerprinter(r.InsecureSkipVerify)
	fp.Timeout = r.HTTPTimeout
	results := fp.FingerprintBatch(ctx, hosts)
	return results, nil
}

func (r *Runner) runURLs(ctx context.Context, domain string) ([]urls.URL, error) {
	enum := urls.NewEnumeratorWithRateLimit(r.RateLimit)
	result := enum.Enumerate(ctx, domain)
	return result.URLs, nil
}

func (r *Runner) runAPIs(ctx context.Context, hosts []string) ([]apis.API, error) {
	discovery := apis.NewDiscovery(r.InsecureSkipVerify)
	discovery.Workers = r.APIWorkers
	discovery.Timeout = r.HTTPTimeout

	var results []apis.API
	batch := discovery.DiscoverBatch(ctx, hosts)
	for _, res := range batch.Results {
		results = append(results, res.APIs...)
	}
	return results, nil
}

func (r *Runner) runEmails(ctx context.Context, domain string) ([]emails.Email, error) {
	enum := emails.DefaultEnumerator()
	result := enum.Enumerate(ctx, domain)
	return result.Emails, nil
}

func (r *Runner) runCloudStorage(ctx context.Context, domain string) ([]cloud.Bucket, error) {
	detector := cloud.DefaultDetector()
	detector.Workers = r.CloudWorkers
	result := detector.ProbeCommonBuckets(ctx, domain)
	return result.Buckets, nil
}

func (r *Runner) runNuclei(ctx context.Context, hosts []string) ([]*nuclei.Finding, error) {
	scanner := nuclei.DefaultScanner()
	scanner.Severities = r.NucleiSeverities
	scanner.RateLimit = r.NucleiRateLimit

	// Check if nuclei is installed
	if !scanner.IsInstalled() {
		return nil, fmt.Errorf("nuclei not installed")
	}

	// Convert hosts to URLs for scanning
	var targets []string
	for _, h := range hosts {
		targets = append(targets, "https://"+h)
		targets = append(targets, "http://"+h)
	}

	result, err := scanner.Scan(ctx, targets)
	if err != nil {
		return nil, err
	}

	return result.Findings, nil
}

// dnsRecordSetToResult converts a DNSRecordSet into a minimal dns.Result suitable
// for change detection.
func dnsRecordSetToResult(rset DNSRecordSet) *dns.Result {
	r := &dns.Result{
		Domain:  rset.Host,
		Records: make(map[string][]dns.Record),
		SOA:     rset.SOA,
		CAA:     rset.CAA,
		DNSSEC:  rset.DNSSEC,
	}
	for _, rec := range rset.Records {
		r.Records[rec.Type] = append(r.Records[rec.Type], rec)
	}
	return r
}

// changeSeverity maps a DNS record type to a change event severity.
func changeSeverity(recordType string) string {
	switch recordType {
	case "NS", "DNSSEC":
		return "critical"
	case "A", "AAAA", "MX", "SOA":
		return "high"
	case "CAA", "CNAME":
		return "medium"
	default:
		return "low"
	}
}
