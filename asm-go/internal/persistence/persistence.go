package persistence

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/scanner/apis"
	"github.com/asm-tool/asm-go/internal/scanner/certificates"
	"github.com/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/asm-tool/asm-go/internal/scanner/dns"
	"github.com/asm-tool/asm-go/internal/scanner/emails"
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/asm-tool/asm-go/internal/scanner/ports"
	"github.com/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/asm-tool/asm-go/internal/scanner/urls"
)

type writer struct {
	domains      *database.DomainRepository
	ports        *database.PortRepository
	certificates *database.CertificateRepository
	findings     *database.FindingRepository

	getLatestDNSRecord   func(string) (*database.DNSRecord, error)
	saveChangeEvent      func(string, string, string, string, string, string) error
	saveCloudBucket      func(string, string, string, string, string, string, string) error
	saveDNSRecords       func(string, string) error
	saveAPI              func(string, string, string, string, int, string, int) error
	saveEmail            func(string, string, string) error
	saveTakeover         func(string, string, string, string, string) error
	saveTechnology       func(string, int, string, string, string, string, int64, string) error
	saveURL              func(string, string, string, string, int) error
	updateDomainLastScan func(string) error
}

// TakeoverFinding is the persistence shape shared by standalone takeover scans
// and full scans.
type TakeoverFinding struct {
	Subdomain  string
	CNAME      string
	Service    string
	Confidence string
	Evidence   string
	Vulnerable bool
}

// EnsureDomain creates or reactivates a domain row so dashboard views have an
// anchor for scanner results.
func EnsureDomain(store any, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return err
	}
	_, err = w.domains.Add(domain)
	if err != nil {
		return fmt.Errorf("saving domain %q: %w", domain, err)
	}
	return nil
}

// MarkDomainScanned updates the dashboard timestamp for a completed scanner
// run. It creates the domain first so standalone module scans appear on the
// dashboard even if discover has not run yet.
func MarkDomainScanned(store any, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return err
	}
	if _, err := w.domains.Add(domain); err != nil {
		return fmt.Errorf("saving domain %q: %w", domain, err)
	}
	if err := w.updateDomainLastScan(domain); err != nil {
		return fmt.Errorf("updating last scanned for %q: %w", domain, err)
	}
	return nil
}

func SaveSubdomains(store any, domain string, subdomains []string) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	d, err := w.domains.Add(domain)
	if err != nil {
		return 0, fmt.Errorf("saving domain %q: %w", domain, err)
	}

	var errs []error
	saved := 0
	for _, sub := range subdomains {
		err := w.domains.AddSubdomain(d.ID, sub)
		if collect(&errs, err, "saving subdomain %q", sub) {
			saved++
		}
	}
	return saved, joined("saving subdomains", errs)
}

func SavePortScanResult(store any, result *ports.Result) (int, error) {
	if result == nil {
		return 0, nil
	}
	return SavePortScanResults(store, []*ports.Result{result})
}

func SavePortScanResults(store any, results []*ports.Result) (int, error) {
	var dbPorts []database.Port
	for _, result := range results {
		if result == nil {
			continue
		}
		for _, p := range result.OpenPorts {
			dbPorts = append(dbPorts, database.Port{
				Host:     result.Host,
				Port:     p.Port,
				Protocol: p.Protocol,
				Service:  p.Service,
				Version:  p.Version,
				State:    p.State,
				Banner:   p.Banner,
			})
		}
	}
	return SavePorts(store, dbPorts)
}

func SavePorts(store any, dbPorts []database.Port) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	for _, p := range dbPorts {
		err := w.ports.Add(&p)
		if collect(&errs, err, "saving port %s:%d", p.Host, p.Port) {
			saved++
		}
	}
	return saved, joined("saving ports", errs)
}

func SaveCertificates(store any, certs []*certificates.Certificate) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	for _, cert := range certs {
		if cert == nil || cert.Error != "" {
			continue
		}
		err := w.certificates.Add(&database.Certificate{
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
		})
		if collect(&errs, err, "saving certificate %s:%d", cert.Host, cert.Port) {
			saved++
		}
	}
	return saved, joined("saving certificates", errs)
}

func SaveDNSResult(store any, result *dns.Result) error {
	if result == nil {
		return nil
	}
	return SaveDNSResults(store, []*dns.Result{result})
}

func SaveDNSResults(store any, results []*dns.Result) error {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return err
	}

	var errs []error
	for _, result := range results {
		if result == nil {
			continue
		}
		prev, err := w.getLatestDNSRecord(result.Domain)
		collect(&errs, err, "loading latest DNS record %q", result.Domain)

		resultJSON, err := json.Marshal(result)
		if !collect(&errs, err, "encoding DNS records %q", result.Domain) {
			continue
		}
		collect(&errs, w.saveDNSRecords(result.Domain, string(resultJSON)), "saving DNS records %q", result.Domain)

		if prev == nil {
			continue
		}
		var prevResult dns.Result
		if err := json.Unmarshal([]byte(prev.Records), &prevResult); err != nil {
			continue
		}
		for _, ch := range dns.DetectChanges(result, &prevResult) {
			sev := dnsSeverity(ch.RecordType)
			err := w.saveChangeEvent(result.Domain, ch.Type, sev, ch.Description, ch.OldValue, ch.NewValue)
			collect(&errs, err, "saving DNS change event %q", result.Domain)
		}
	}
	return joined("saving DNS records", errs)
}

func SaveTechnologies(store any, results []*technologies.Result) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	for _, result := range results {
		if result == nil || result.Error != "" {
			continue
		}
		techJSON, err := json.Marshal(result.Technologies)
		if !collect(&errs, err, "encoding technologies for %q", result.Host) {
			continue
		}
		headersJSON, err := json.Marshal(result.Headers)
		if !collect(&errs, err, "encoding technology headers for %q", result.Host) {
			continue
		}
		err = w.saveTechnology(result.Host, result.StatusCode, result.Title, result.Server,
			string(techJSON), string(headersJSON), result.ContentLength, result.RedirectURL)
		if collect(&errs, err, "saving technology %q", result.Host) {
			saved++
		}
	}
	return saved, joined("saving technologies", errs)
}

func SaveURLs(store any, results []urls.URL) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	ensuredDomains := make(map[string]bool)
	for _, u := range results {
		if u.Domain != "" && !ensuredDomains[u.Domain] {
			_, err := w.domains.Add(u.Domain)
			collect(&errs, err, "saving domain %q", u.Domain)
			ensuredDomains[u.Domain] = err == nil
		}
		interesting := 0
		if u.Interesting {
			interesting = 1
		}
		err := w.saveURL(u.Domain, u.URL, u.Category, u.Source, interesting)
		if collect(&errs, err, "saving URL %q", u.URL) {
			saved++
		}
	}
	return saved, joined("saving URLs", errs)
}

func SaveAPIs(store any, results []apis.API) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	for _, api := range results {
		endpointsJSON, err := json.Marshal(api.Endpoints)
		if !collect(&errs, err, "encoding API endpoints for %q", api.URL) {
			continue
		}
		introspection := 0
		if api.IntrospectionEnabled {
			introspection = 1
		}
		err = w.saveAPI(api.URL, api.Type, api.Title, api.Version, api.EndpointsCount, string(endpointsJSON), introspection)
		if collect(&errs, err, "saving API %q", api.URL) {
			saved++
		}
	}
	return saved, joined("saving APIs", errs)
}

func SaveEmails(store any, results []emails.Email) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	ensuredDomains := make(map[string]bool)
	for _, email := range results {
		if email.Domain != "" && !ensuredDomains[email.Domain] {
			_, err := w.domains.Add(email.Domain)
			collect(&errs, err, "saving domain %q", email.Domain)
			ensuredDomains[email.Domain] = err == nil
		}
		err := w.saveEmail(email.Domain, email.Address, email.Source)
		if collect(&errs, err, "saving email %q", email.Address) {
			saved++
		}
	}
	return saved, joined("saving emails", errs)
}

func SaveCloudBuckets(store any, results []cloud.Bucket) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	ensuredDomains := make(map[string]bool)
	for _, bucket := range results {
		if bucket.Domain != "" && !ensuredDomains[bucket.Domain] {
			_, err := w.domains.Add(bucket.Domain)
			collect(&errs, err, "saving domain %q", bucket.Domain)
			ensuredDomains[bucket.Domain] = err == nil
		}
		err := w.saveCloudBucket(bucket.Provider, bucket.BucketName, bucket.URL, bucket.Domain, bucket.AccessLevel, bucket.Severity, bucket.Evidence)
		if collect(&errs, err, "saving cloud bucket %q", bucket.URL) {
			saved++
		}
	}
	return saved, joined("saving cloud buckets", errs)
}

func SaveTakeovers(store any, results []TakeoverFinding) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	for _, takeover := range results {
		if !takeover.Vulnerable {
			continue
		}
		err := w.saveTakeover(takeover.Subdomain, takeover.CNAME, takeover.Service, takeover.Confidence, takeover.Evidence)
		if collect(&errs, err, "saving takeover %q", takeover.Subdomain) {
			saved++
		}
	}
	return saved, joined("saving takeovers", errs)
}

func SaveNucleiFindings(store any, results []*nuclei.Finding) (int, error) {
	w, ok, err := newWriter(store)
	if err != nil || !ok {
		return 0, err
	}

	var errs []error
	saved := 0
	for _, finding := range results {
		if finding == nil {
			continue
		}
		err := w.findings.Add(&database.Finding{
			TemplateID:  finding.TemplateID,
			Name:        finding.Info.Name,
			Severity:    normalizeSeverity(finding.Info.Severity),
			Description: finding.Info.Description,
			Host:        finding.Host,
			MatchedAt:   finding.Matched,
			MatcherName: finding.MatcherName,
			Evidence:    strings.Join(finding.ExtractedResults, ", "),
			Refs:        strings.Join(finding.Info.Reference, "\n"),
			Tags:        finding.Info.Tags,
			Type:        finding.Type,
			Status:      "open",
		})
		if collect(&errs, err, "saving finding %q for %q", finding.TemplateID, finding.Host) {
			saved++
		}
	}
	return saved, joined("saving nuclei findings", errs)
}

func newWriter(store any) (writer, bool, error) {
	switch s := store.(type) {
	case nil:
		return writer{}, false, nil
	case *database.Database:
		if s == nil {
			return writer{}, false, nil
		}
		return writer{
			domains:              s.Domains,
			ports:                s.Ports,
			certificates:         s.Certificates,
			findings:             s.Findings,
			getLatestDNSRecord:   s.GetLatestDNSRecord,
			saveChangeEvent:      s.SaveChangeEvent,
			saveCloudBucket:      s.SaveCloudBucket,
			saveDNSRecords:       s.SaveDNSRecords,
			saveAPI:              s.SaveAPI,
			saveEmail:            s.SaveEmail,
			saveTakeover:         s.SaveTakeover,
			saveTechnology:       s.SaveTechnology,
			saveURL:              s.SaveURL,
			updateDomainLastScan: s.UpdateDomainLastScanned,
		}, true, nil
	case *database.Transaction:
		if s == nil {
			return writer{}, false, nil
		}
		return writer{
			domains:              s.Domains,
			ports:                s.Ports,
			certificates:         s.Certificates,
			findings:             s.Findings,
			getLatestDNSRecord:   s.GetLatestDNSRecord,
			saveChangeEvent:      s.SaveChangeEvent,
			saveCloudBucket:      s.SaveCloudBucket,
			saveDNSRecords:       s.SaveDNSRecords,
			saveAPI:              s.SaveAPI,
			saveEmail:            s.SaveEmail,
			saveTakeover:         s.SaveTakeover,
			saveTechnology:       s.SaveTechnology,
			saveURL:              s.SaveURL,
			updateDomainLastScan: s.UpdateDomainLastScanned,
		}, true, nil
	default:
		return writer{}, false, fmt.Errorf("unsupported persistence store %T", store)
	}
}

func collect(errs *[]error, err error, format string, args ...interface{}) bool {
	if err == nil {
		return true
	}
	*errs = append(*errs, fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err))
	return false
}

func joined(action string, errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", action, errors.Join(errs...))
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(severity))
	default:
		return "info"
	}
}

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
