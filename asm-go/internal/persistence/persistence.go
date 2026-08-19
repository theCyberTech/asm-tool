// Package persistence handles database persistence for scanner results.
// It provides a deep Store interface — two methods, one entry point.
// All save logic (type mapping, transaction handling, error collection)
// lives inside the concrete implementation.
package persistence

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/theCyberTech/asm-tool/asm-go/internal/database"
	"github.com/theCyberTech/asm-tool/asm-go/internal/parallel"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/apis"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/certificates"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/dns"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/emails"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/ports"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/takeover"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/urls"
)

// Store is the persistence entry point. A Store owns a database connection
// and persists scan results through a single method. Callers construct a
// Store once, pass it around or use it directly.
type Store interface {
	// SaveAll persists the complete scan result for a domain in a transaction.
	SaveAll(result *parallel.ScanResult) error
	// EnsureDomain creates or reactivates a domain row and marks it as
	// just scanned so the dashboard shows the result.
	EnsureDomain(domain string) error
	// SaveSnapshot stores a point-in-time snapshot used by `asm diff`.
	SaveSnapshot(result *parallel.ScanResult, scanType string) error
}

// storeImpl is the concrete implementation behind the Store interface.
type storeImpl struct {
	db *database.Database
}

// storeTxImpl wraps a database transaction as a Store.
type storeTxImpl struct {
	tx *database.Transaction
}

// NewStore returns a Store backed by the given database connection.
func NewStore(db *database.Database) Store {
	return &storeImpl{db: db}
}

// SaveAll persists the complete scan result for a domain.
func (s *storeImpl) SaveAll(result *parallel.ScanResult) error {
	return s.db.WithTransaction(func(tx *database.Transaction) error {
		return saveTx(tx, result)
	})
}

// SaveSnapshot stores a point-in-time snapshot of the scan result.
func (s *storeImpl) SaveSnapshot(result *parallel.ScanResult, scanType string) error {
	return SaveScanSnapshot(s.db, result, scanType)
}

// saveTx saves a scan result within an existing transaction.
func saveTx(tx *database.Transaction, result *parallel.ScanResult) error {
	errs := []error{}
	collect := func(err error, msg string, args ...interface{}) {
		if err != nil {
			errs = append(errs, fmt.Errorf(msg, args...))
		}
	}

	ensuredDomains := make(map[string]struct{})
	ensureDomain := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := ensuredDomains[name]; ok {
			return
		}
		ensuredDomains[name] = struct{}{}
		if _, err := tx.Domains.Add(name); err != nil {
			collect(err, "saving domain %q", name)
		}
	}

	// Subdomains
	if len(result.Subdomains) > 0 {
		domain, err := tx.Domains.Add(result.Domain)
		if err != nil {
			collect(err, "saving domain %q", result.Domain)
		} else {
			ensuredDomains[strings.TrimSpace(result.Domain)] = struct{}{}
			if err := tx.Domains.AddSubdomains(domain.ID, result.Subdomains); err != nil {
				collect(err, "saving subdomains for %q", result.Domain)
			}
		}
	}

	// Ports
	dbPorts := make([]database.Port, 0)
	for _, r := range result.Ports {
		if r == nil {
			continue
		}
		for _, p := range r.OpenPorts {
			dbPorts = append(dbPorts, database.Port{
				Host:    r.Host,
				Port:    p.Port,
				State:   p.State,
				Service: p.Service,
				Banner:  p.Banner,
			})
		}
	}
	if err := tx.Ports.AddAll(dbPorts); err != nil {
		collect(err, "saving ports")
	}

	// Certificates: persist metadata even when verification failed, as long as
	// a certificate was actually retrieved.
	for _, cert := range result.Certificates {
		if cert == nil || cert.Fingerprint == "" {
			continue
		}
		dbCert := &database.Certificate{
			Host:               cert.Host,
			Port:               cert.Port,
			Subject:            cert.Subject,
			Issuer:             cert.Issuer,
			SerialNumber:       cert.SerialNumber,
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			DaysUntilExpiry:    cert.DaysUntilExpiry,
			Fingerprint:        cert.Fingerprint,
			SAN:                cert.SANString(),
			SignatureAlgorithm: cert.SignatureAlgorithm,
		}
		if err := tx.Certificates.Add(dbCert); err != nil {
			collect(err, "saving certificate %s:%d", cert.Host, cert.Port)
		}
	}

	// DNS
	for _, r := range result.DNSRecords {
		if r.Domain == "" {
			continue
		}
		prev, err := tx.GetLatestDNSRecord(r.Domain)
		if err != nil {
			collect(err, "loading DNS record %q", r.Domain)
		}

		resultJSON, err := json.Marshal(r)
		if err != nil {
			collect(err, "encoding DNS records %q", r.Domain)
		} else {
			if err := tx.SaveDNSRecords(r.Domain, string(resultJSON)); err != nil {
				collect(err, "saving DNS records %q", r.Domain)
			}
		}

		if prev != nil && prev.Records != "" {
			var prevResult dns.Result
			if err := json.Unmarshal([]byte(prev.Records), &prevResult); err == nil {
				for _, ch := range dns.DetectChanges(&r, &prevResult) {
					sev := dnsSeverity(ch.RecordType)
					if err := tx.SaveChangeEvent(r.Domain, ch.Type, sev, ch.Description, ch.OldValue, ch.NewValue); err != nil {
						collect(err, "saving DNS change event %q", r.Domain)
					}
				}
			}
		}
	}

	// Takeovers
	for _, f := range result.Takeovers {
		if !f.Vulnerable {
			continue
		}
		if err := tx.SaveTakeover(f.Subdomain, f.CNAME, f.Service, f.Confidence, f.Evidence); err != nil {
			collect(err, "saving takeover %q", f.Subdomain)
		}
	}

	// Technologies
	for _, r := range result.Technologies {
		if r == nil || r.Error != "" {
			continue
		}
		techJSON, err := json.Marshal(r.Technologies)
		if err != nil {
			collect(err, "encoding technologies for %q", r.Host)
		}
		headersJSON, err := json.Marshal(r.Headers)
		if err != nil {
			collect(err, "encoding technology headers for %q", r.Host)
		}
		if err := tx.SaveTechnology(r.Host, r.StatusCode, r.Title, r.Server,
			string(techJSON), string(headersJSON), r.ContentLength, r.RedirectURL); err != nil {
			collect(err, "saving technology %q", r.Host)
		}
	}

	// URLs
	urlRecords := make([]database.URLRecord, 0, len(result.URLs))
	for _, u := range result.URLs {
		ensureDomain(u.Domain)
		interesting := 0
		if u.Interesting {
			interesting = 1
		}
		urlRecords = append(urlRecords, database.URLRecord{
			Domain:      u.Domain,
			URL:         u.URL,
			Category:    u.Category,
			Source:      u.Source,
			Interesting: interesting,
		})
	}
	if err := tx.SaveURLs(urlRecords); err != nil {
		collect(err, "saving URLs")
	}

	// APIs
	for _, a := range result.APIs {
		endpointsJSON, err := json.Marshal(a.Endpoints)
		if err != nil {
			collect(err, "encoding API endpoints for %q", a.URL)
		}
		if err := tx.SaveAPI(a.URL, a.Type, a.Title, a.Version, a.EndpointsCount, string(endpointsJSON)); err != nil {
			collect(err, "saving API %q", a.URL)
		}
	}

	// Emails
	emailRecords := make([]database.EmailRecord, 0, len(result.Emails))
	for _, e := range result.Emails {
		ensureDomain(e.Domain)
		emailRecords = append(emailRecords, database.EmailRecord{
			Domain:  e.Domain,
			Address: e.Address,
			Source:  e.Source,
		})
	}
	if err := tx.SaveEmails(emailRecords); err != nil {
		collect(err, "saving emails")
	}

	// Cloud storage
	for _, b := range result.CloudStorage {
		ensureDomain(b.Domain)
		if err := tx.SaveCloudBucket(b.Provider, b.BucketName, b.URL, b.Domain, b.AccessLevel, b.Severity, b.Evidence); err != nil {
			collect(err, "saving cloud bucket %q", b.URL)
		}
	}

	// Nuclei findings
	for _, f := range result.Vulnerabilities {
		if f == nil {
			continue
		}
		dbFinding := &database.Finding{
			TemplateID:  f.TemplateID,
			Name:        f.Info.Name,
			Severity:    normalizeSeverity(f.Info.Severity),
			Description: f.Info.Description,
			Host:        f.Host,
			MatchedAt:   f.Matched,
			MatcherName: f.MatcherName,
			Evidence:    strings.Join(f.ExtractedResults, ", "),
			Refs:        strings.Join(f.Info.Reference, "\n"),
			Tags:        f.Info.Tags,
			Type:        f.Type,
			Status:      "open",
		}
		if err := tx.Findings.Add(dbFinding); err != nil {
			collect(err, "saving finding %q for %q", f.TemplateID, f.Host)
		}
	}

	// Update last_scanned timestamp
	if err := tx.UpdateDomainLastScanned(result.Domain); err != nil {
		collect(err, "updating last scanned for %q", result.Domain)
	}

	if len(errs) > 0 {
		return fmt.Errorf("saving scan results: %w", errs[0])
	}
	return nil
}

// EnsureDomain creates or reactivates a domain and updates last_scanned.
func (s *storeImpl) EnsureDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}
	return s.db.WithTransaction(func(tx *database.Transaction) error {
		if _, err := tx.Domains.Add(domain); err != nil {
			return fmt.Errorf("saving domain %q: %w", domain, err)
		}
		if err := tx.UpdateDomainLastScanned(domain); err != nil {
			return fmt.Errorf("updating last scanned for %q: %w", domain, err)
		}
		return nil
	})
}

// EnsureDomain creates or reactivates a domain within a transaction.
func (s *storeTxImpl) EnsureDomain(domain string) error {
	return ensureDomainTx(s.tx, domain)
}

// SaveAll persists the complete scan result for a domain (already inside a transaction).
func (s *storeTxImpl) SaveAll(result *parallel.ScanResult) error {
	return saveTx(s.tx, result)
}

// SaveSnapshot is not available on a transactional store; snapshots are
// written through the top-level Database connection.
func (s *storeTxImpl) SaveSnapshot(result *parallel.ScanResult, scanType string) error {
	return fmt.Errorf("SaveSnapshot is not supported inside a transaction")
}

// ensureDomainTx creates or reactivates a domain within an existing transaction.
func ensureDomainTx(tx *database.Transaction, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}
	if _, err := tx.Domains.Add(domain); err != nil {
		return fmt.Errorf("saving domain %q: %w", domain, err)
	}
	if err := tx.UpdateDomainLastScanned(domain); err != nil {
		return fmt.Errorf("updating last scanned for %q: %w", domain, err)
	}
	return nil
}

// normalizeSeverity maps severity strings to canonical values.
func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(severity))
	default:
		return "info"
	}
}

// dnsSeverity maps record type to change event severity.
func dnsSeverity(recordType string) string {
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

// snapshotPort is the JSON shape expected by `asm diff` for open ports.
type snapshotPort struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	State   string `json:"state"`
}

// snapshotVuln is the JSON shape expected by `asm diff` for vulnerabilities.
type snapshotVuln struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
}

// snapshotCert encodes useful certificate fields for a snapshot.
type snapshotCert struct {
	Host    string `json:"host"`
	Subject string `json:"subject"`
	Expiry  string `json:"expiry"`
}

// snapshotFindingCounts is stored as JSON on the snapshot row.
type snapshotFindingCounts struct {
	Vulnerabilities int `json:"vulnerabilities"`
	Takeovers       int `json:"takeovers"`
	Critical        int `json:"critical"`
}

// SaveScanSnapshot encodes a scan result and writes it via Database.SaveSnapshot.
func SaveScanSnapshot(db *database.Database, result *parallel.ScanResult, scanType string) error {
	if db == nil {
		return fmt.Errorf("cannot save snapshot: database is nil")
	}
	if result == nil {
		return fmt.Errorf("cannot save snapshot: result is nil")
	}
	domain := strings.TrimSpace(result.Domain)
	if domain == "" {
		return fmt.Errorf("cannot save snapshot: domain is empty")
	}

	subs := result.Subdomains
	if subs == nil {
		subs = []string{}
	}
	portsJSON := flattenSnapshotPorts(result.Ports)
	certsJSON := encodeSnapshotCerts(result.Certificates)
	vulnsJSON := encodeSnapshotVulns(result.Vulnerabilities)

	subBytes, err := json.Marshal(subs)
	if err != nil {
		return fmt.Errorf("encoding snapshot subdomains: %w", err)
	}
	portBytes, err := json.Marshal(portsJSON)
	if err != nil {
		return fmt.Errorf("encoding snapshot ports: %w", err)
	}
	certBytes, err := json.Marshal(certsJSON)
	if err != nil {
		return fmt.Errorf("encoding snapshot certificates: %w", err)
	}
	vulnBytes, err := json.Marshal(vulnsJSON)
	if err != nil {
		return fmt.Errorf("encoding snapshot vulnerabilities: %w", err)
	}

	counts := snapshotFindingCounts{
		Vulnerabilities: countVulnerabilities(result.Vulnerabilities),
		Takeovers:       countVulnerableTakeovers(result.Takeovers),
		Critical:        countCriticalVulns(result.Vulnerabilities),
	}
	countBytes, err := json.Marshal(counts)
	if err != nil {
		return fmt.Errorf("encoding snapshot finding counts: %w", err)
	}

	return db.SaveSnapshot(
		domain,
		scanType,
		len(result.Subdomains),
		len(portsJSON),
		len(result.Certificates),
		snapshotRiskScore(result),
		string(countBytes),
		string(subBytes),
		string(portBytes),
		string(certBytes),
		string(vulnBytes),
	)
}

func flattenSnapshotPorts(results []*ports.Result) []snapshotPort {
	out := make([]snapshotPort, 0)
	for _, r := range results {
		if r == nil {
			continue
		}
		for _, p := range r.OpenPorts {
			out = append(out, snapshotPort{
				Host:    r.Host,
				Port:    p.Port,
				Service: p.Service,
				State:   p.State,
			})
		}
	}
	return out
}

func encodeSnapshotCerts(certs []*certificates.Certificate) []snapshotCert {
	out := make([]snapshotCert, 0)
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		out = append(out, snapshotCert{
			Host:    cert.Host,
			Subject: cert.Subject,
			Expiry:  cert.NotAfter.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func encodeSnapshotVulns(findings []*nuclei.Finding) []snapshotVuln {
	out := make([]snapshotVuln, 0)
	for _, f := range findings {
		if f == nil {
			continue
		}
		out = append(out, snapshotVuln{
			TemplateID: f.TemplateID,
			Name:       f.Info.Name,
			Severity:   normalizeSeverity(f.Info.Severity),
			Host:       f.Host,
		})
	}
	return out
}

func countVulnerabilities(findings []*nuclei.Finding) int {
	n := 0
	for _, f := range findings {
		if f != nil {
			n++
		}
	}
	return n
}

func countCriticalVulns(findings []*nuclei.Finding) int {
	n := 0
	for _, f := range findings {
		if f != nil && normalizeSeverity(f.Info.Severity) == "critical" {
			n++
		}
	}
	return n
}

func countVulnerableTakeovers(findings []takeover.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Vulnerable {
			n++
		}
	}
	return n
}

func snapshotRiskScore(result *parallel.ScanResult) int {
	if result == nil {
		return 0
	}
	score := 0
	for _, f := range result.Vulnerabilities {
		if f == nil {
			continue
		}
		switch normalizeSeverity(f.Info.Severity) {
		case "critical":
			score += 10
		case "high":
			score += 5
		case "medium":
			score += 2
		case "low":
			score += 1
		}
	}
	for _, finding := range result.Takeovers {
		if finding.Vulnerable {
			score += 8
		}
	}
	for _, b := range result.CloudStorage {
		switch b.AccessLevel {
		case "listing_enabled", "public_read":
			score += 6
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// ── Convenience functions ────────────────────────────────────────────────
// These functions are provided for backward compatibility with callers that
// persist individual module results. Each wraps Store.SaveAll with a minimal
// ScanResult. Prefer calling Store directly for new code.

// newStore creates a Store from a database connection or transaction.
func newStore(store any) (Store, error) {
	switch s := store.(type) {
	case *database.Database:
		if s == nil {
			return nil, nil
		}
		return &storeImpl{db: s}, nil
	case *database.Transaction:
		if s == nil {
			return nil, nil
		}
		return &storeTxImpl{tx: s}, nil
	default:
		return nil, fmt.Errorf("unsupported persistence store %T", store)
	}
}

// ensureDomain creates or reactivates a domain.
func ensureDomain(store any, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}
	s, err := newStore(store)
	if err != nil || s == nil {
		return err
	}
	return s.EnsureDomain(domain)
}

// EnsureDomain creates or reactivates a domain.
func EnsureDomain(db *database.Database, domain string) error {
	return ensureDomain(db, domain)
}

// MarkDomainScanned updates the dashboard timestamp for a completed scanner run.
func MarkDomainScanned(store any, domain string) error {
	return ensureDomain(store, domain)
}

// SaveSubdomains persists subdomains for a domain.
func SaveSubdomains(store any, domain string, subdomains []string) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		Domain:     domain,
		Subdomains: subdomains,
	})
	return len(subdomains), err
}

// SavePortScanResults persists port scan results for a domain.
func SavePortScanResults(store any, results []*ports.Result) (int, error) {
	if results == nil {
		return 0, nil
	}
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		Ports: results,
	})
	return countOpenPortResults(results), err
}

// SaveAPIs persists API discovery results.
func SaveAPIs(store any, results []apis.API) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		APIs: results,
	})
	return len(results), err
}

// SaveCertificates persists TLS certificate results.
func SaveCertificates(store any, certs []*certificates.Certificate) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		Certificates: certs,
	})
	return countSavedCertificates(certs), err
}

// SaveDNSResults persists DNS lookup results.
func SaveDNSResults(store any, results []*dns.Result) error {
	if results == nil {
		return nil
	}
	var recs []dns.Result
	for _, r := range results {
		if r != nil {
			recs = append(recs, *r)
		}
	}
	s, err := newStore(store)
	if err != nil || s == nil {
		return err
	}
	return s.SaveAll(&parallel.ScanResult{
		DNSRecords: recs,
	})
}

// SaveDNSResult is an alias for SaveDNSResults (singular form for single result saves).
func SaveDNSResult(store any, result *dns.Result) error {
	if result == nil {
		return nil
	}
	return SaveDNSResults(store, []*dns.Result{result})
}

// SaveEmails persists email enumeration results.
func SaveEmails(store any, results []emails.Email) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		Emails: results,
	})
	return len(results), err
}

// SaveCloudBuckets persists cloud storage detection results.
func SaveCloudBuckets(store any, results []cloud.Bucket) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		CloudStorage: results,
	})
	return len(results), err
}

// SaveTechnologies persists technology fingerprint results.
func SaveTechnologies(store any, results []*technologies.Result) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		Technologies: results,
	})
	return len(results), err
}

// SaveURLs persists URL enumeration results.
func SaveURLs(store any, results []urls.URL) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		URLs: results,
	})
	return len(results), err
}

// TakeoverFinding is the persistence shape shared by standalone takeover scans
// and full scans. Kept for backward compatibility.
type TakeoverFinding = takeover.Finding

// SaveTakeovers persists subdomain takeover results.
func SaveTakeovers(store any, findings []TakeoverFinding) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		Takeovers: findings,
	})
	return len(findings), err
}

// SaveNucleiFindings persists vulnerability scan results.
func SaveNucleiFindings(store any, results []*nuclei.Finding) (int, error) {
	s, err := newStore(store)
	if err != nil || s == nil {
		return 0, err
	}
	err = s.SaveAll(&parallel.ScanResult{
		Vulnerabilities: results,
	})
	return len(results), err
}

func countOpenPortResults(results []*ports.Result) int {
	n := 0
	for _, r := range results {
		if r == nil {
			continue
		}
		n += len(r.OpenPorts)
	}
	return n
}

func countSavedCertificates(certs []*certificates.Certificate) int {
	n := 0
	for _, c := range certs {
		if c != nil && c.Fingerprint != "" {
			n++
		}
	}
	return n
}
