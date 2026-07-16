// Package persistence handles database persistence for scanner results.
// It provides a deep Store interface — two methods, one entry point.
// All save logic (type mapping, transaction handling, error collection)
// lives inside the concrete implementation.
package persistence

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/parallel"
	"github.com/asm-tool/asm-go/internal/scanner/apis"
	"github.com/asm-tool/asm-go/internal/scanner/certificates"
	"github.com/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/asm-tool/asm-go/internal/scanner/dns"
	"github.com/asm-tool/asm-go/internal/scanner/emails"
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/asm-tool/asm-go/internal/scanner/ports"
	"github.com/asm-tool/asm-go/internal/scanner/takeover"
	"github.com/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/asm-tool/asm-go/internal/scanner/urls"
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

// saveTx saves a scan result within an existing transaction.
func saveTx(tx *database.Transaction, result *parallel.ScanResult) error {
	errs := []error{}
	collect := func(err error, msg string, args ...interface{}) {
		if err != nil {
			errs = append(errs, fmt.Errorf(msg, args...))
		}
	}

		// Subdomains
		if len(result.Subdomains) > 0 {
			domain, err := tx.Domains.Add(result.Domain)
			if err != nil {
				collect(err, "saving domain %q", result.Domain)
			} else {
				for _, sub := range result.Subdomains {
					if err := tx.Domains.AddSubdomain(domain.ID, sub); err != nil {
						collect(err, "saving subdomain %q", sub)
					}
				}
			}
		}

		// Ports
		for _, r := range result.Ports {
			if r == nil {
				continue
			}
			for _, p := range r.OpenPorts {
				dbPort := database.Port{
					Host:    r.Host,
					Port:    p.Port,
					State:   p.State,
					Service: p.Service,
					Banner:  p.Banner,
				}
				if err := tx.Ports.Add(&dbPort); err != nil {
					collect(err, "saving port %s:%d", r.Host, p.Port)
				}
			}
		}

		// Certificates
		for _, cert := range result.Certificates {
			if cert == nil || cert.Error != "" {
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
		for _, u := range result.URLs {
			tx.Domains.Add(u.Domain)
			interesting := 0
			if u.Interesting {
				interesting = 1
			}
			if err := tx.SaveURL(u.Domain, u.URL, u.Category, u.Source, interesting); err != nil {
				collect(err, "saving URL %q", u.URL)
			}
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
		for _, e := range result.Emails {
			tx.Domains.Add(e.Domain)
			if err := tx.SaveEmail(e.Domain, e.Address, e.Source); err != nil {
				collect(err, "saving email %q", e.Address)
			}
		}

		// Cloud storage
		for _, b := range result.CloudStorage {
			tx.Domains.Add(b.Domain)
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
	return 0, err
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
	return 0, err
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
	return 0, err
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
	return 0, err
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
	return 0, err
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
	return 0, err
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
	return 0, err
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
	return 0, err
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
	return 0, err
}