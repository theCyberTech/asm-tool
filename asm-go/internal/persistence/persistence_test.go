package persistence

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/theCyberTech/asm-tool/asm-go/internal/database"
	"github.com/theCyberTech/asm-tool/asm-go/internal/parallel"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/apis"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/certificates"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/emails"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/ports"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/takeover"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/theCyberTech/asm-tool/asm-go/internal/scanner/urls"
)

func TestScannerHelpersPersistDashboardData(t *testing.T) {
	db := newTestDB(t)

	if _, err := SaveURLs(db, []urls.URL{
		{Domain: "example.com", URL: "https://www.example.com/api/users", Category: "api", Source: "wayback", Interesting: true},
	}); err != nil {
		t.Fatalf("SaveURLs err=%v, want nil", err)
	}

	if _, err := SaveAPIs(db, []apis.API{
		{URL: "https://www.example.com/openapi.json", Type: "openapi", Title: "Example API", Version: "3.0.0", EndpointsCount: 1, Endpoints: []string{"/users"}},
	}); err != nil {
		t.Fatalf("SaveAPIs err=%v, want nil", err)
	}

	if _, err := SaveEmails(db, []emails.Email{
		{Domain: "example.com", Address: "security@example.com", Source: "crtsh", Type: "role"},
	}); err != nil {
		t.Fatalf("SaveEmails err=%v, want nil", err)
	}

	if _, err := SaveCloudBuckets(db, []cloud.Bucket{
		{
			URL:         "https://example-assets.s3.amazonaws.com",
			Provider:    "s3",
			BucketName:  "example-assets",
			Domain:      "example.com",
			AccessLevel: "public_read",
			Severity:    "high",
			Evidence:    "public read",
		},
	}); err != nil {
		t.Fatalf("SaveCloudBuckets err=%v, want nil", err)
	}

	if _, err := SaveTechnologies(db, []*technologies.Result{
		{
			Host:         "www.example.com",
			StatusCode:   200,
			Title:        "Example",
			Server:       "nginx",
			Technologies: []technologies.Technology{{Name: "React", Category: "javascript", Confidence: 100}},
			Headers:      map[string]string{"server": "nginx"},
		},
	}); err != nil {
		t.Fatalf("SaveTechnologies err=%v, want nil", err)
	}

	if _, err := SaveTakeovers(db, []TakeoverFinding{
		{Subdomain: "dangling.example.com", CNAME: "dangling.github.io", Service: "github", Confidence: "HIGH", Evidence: "unclaimed", Vulnerable: true},
	}); err != nil {
		t.Fatalf("SaveTakeovers err=%v, want nil", err)
	}

	if _, err := SaveNucleiFindings(db, []*nuclei.Finding{
		{TemplateID: "unknown-severity", Info: nuclei.TemplateInfo{Name: "Unknown severity finding", Severity: "unknown"}, Host: "www.example.com"},
	}); err != nil {
		t.Fatalf("SaveNucleiFindings err=%v, want nil", err)
	}

	if err := MarkDomainScanned(db, "example.com"); err != nil {
		t.Fatalf("MarkDomainScanned returned error: %v", err)
	}

	stats, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats returned error: %v", err)
	}
	if stats.URLs != 1 || stats.APIs != 1 || stats.Emails != 1 || stats.CloudBuckets != 1 || stats.Takeovers != 1 || stats.Findings != 1 {
		t.Fatalf("stats = %+v, want saved scanner counts", stats)
	}

	detail, err := db.GetDomainDetailStats("example.com")
	if err != nil {
		t.Fatalf("GetDomainDetailStats returned error: %v", err)
	}
	if detail.URLCount != 1 || detail.APICount != 1 || detail.EmailCount != 1 || detail.CloudCount != 1 || detail.TechnologyCount != 1 || detail.TakeoverCount != 1 {
		t.Fatalf("domain detail stats = %+v, want saved scanner counts", detail)
	}

	domain, err := db.Domains.GetByName("example.com")
	if err != nil {
		t.Fatalf("GetByName returned error: %v", err)
	}
	if domain.LastScanned == nil {
		t.Fatal("last_scanned was not updated")
	}

	counts, err := db.GetFindingSeverityCounts()
	if err != nil {
		t.Fatalf("GetFindingSeverityCounts returned error: %v", err)
	}
	if counts.Info != 1 {
		t.Fatalf("info finding count = %d, want 1", counts.Info)
	}
}

func TestScannerHelpersWorkInsideTransaction(t *testing.T) {
	db := newTestDB(t)

	if err := db.WithTransaction(func(tx *database.Transaction) error {
		if _, err := SaveURLs(tx, []urls.URL{
			{Domain: "example.com", URL: "https://www.example.com/admin", Category: "admin", Source: "urlscan", Interesting: true},
		}); err != nil {
			return err
		}
		return MarkDomainScanned(tx, "example.com")
	}); err != nil {
		t.Fatalf("WithTransaction returned error: %v", err)
	}

	stats, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats returned error: %v", err)
	}
	if stats.Domains != 1 || stats.URLs != 1 {
		t.Fatalf("stats = %+v, want one domain and one URL", stats)
	}
}

func TestSaveAllBatchesHighVolumeResults(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db)

	const n = 250
	subs := make([]string, n)
	urlList := make([]urls.URL, n)
	emailList := make([]emails.Email, n)
	for i := 0; i < n; i++ {
		subs[i] = fmt.Sprintf("s%d.example.com", i)
		urlList[i] = urls.URL{
			Domain: "example.com",
			URL:    fmt.Sprintf("https://example.com/p/%d", i),
			Source: "wayback",
		}
		emailList[i] = emails.Email{
			Domain:  "example.com",
			Address: fmt.Sprintf("u%d@example.com", i),
			Source:  "hunter",
		}
	}

	err := store.SaveAll(&parallel.ScanResult{
		Domain:     "example.com",
		Subdomains: subs,
		Ports: []*ports.Result{{
			Host: "www.example.com",
			OpenPorts: []ports.Port{
				{Port: 80, State: "open", Service: "http"},
				{Port: 443, State: "open", Service: "https"},
			},
		}},
		URLs:   urlList,
		Emails: emailList,
	})
	if err != nil {
		t.Fatalf("SaveAll: %v", err)
	}

	stats, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.Subdomains != n || stats.URLs != n || stats.Emails != n || stats.Ports != 2 {
		t.Fatalf("stats = %+v, want %d subdomains/urls/emails and 2 ports", stats, n)
	}
}

func TestSaveSnapshotJSONMatchesDiffShapes(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db)

	expiry := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)
	result := &parallel.ScanResult{
		Domain:     "example.com",
		Subdomains: []string{"www.example.com", "api.example.com"},
		Ports: []*ports.Result{
			nil,
			{
				Host: "www.example.com",
				OpenPorts: []ports.Port{
					{Port: 80, State: "open", Service: "http"},
					{Port: 443, State: "open", Service: "https"},
				},
			},
		},
		Certificates: []*certificates.Certificate{
			{Host: "www.example.com", Subject: "CN=www.example.com", NotAfter: expiry},
		},
		Vulnerabilities: []*nuclei.Finding{
			{TemplateID: "cve-2024-0001", Info: nuclei.TemplateInfo{Name: "Critical RCE", Severity: "CRITICAL"}, Host: "www.example.com"},
			{TemplateID: "exposed-panel", Info: nuclei.TemplateInfo{Name: "Exposed admin", Severity: "high"}, Host: "api.example.com"},
		},
		Takeovers: []takeover.Finding{
			{Subdomain: "dangling.example.com", Vulnerable: true},
			{Subdomain: "ok.example.com", Vulnerable: false},
		},
		CloudStorage: []cloud.Bucket{
			{AccessLevel: "public_read"},
			{AccessLevel: "authenticated_only"},
		},
	}

	if err := store.SaveSnapshot(result, "full"); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}

	snapshots, err := db.GetLatestSnapshots("example.com", 1)
	if err != nil {
		t.Fatalf("GetLatestSnapshots: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("got %d snapshots, want 1", len(snapshots))
	}
	snap := snapshots[0]
	if snap.ScanType != "full" {
		t.Fatalf("scan_type = %q, want full", snap.ScanType)
	}
	if snap.SubdomainCount != 2 {
		t.Fatalf("subdomain_count = %d, want 2", snap.SubdomainCount)
	}
	if snap.PortCount != 2 {
		t.Fatalf("port_count = %d, want 2 open ports (not per-host results)", snap.PortCount)
	}
	if snap.CertificateCount != 1 {
		t.Fatalf("certificate_count = %d, want 1", snap.CertificateCount)
	}
	if snap.RiskScore != 29 {
		t.Fatalf("risk_score = %d, want 29 (10+5+8+6)", snap.RiskScore)
	}

	var subs []string
	if err := json.Unmarshal([]byte(snap.Subdomains), &subs); err != nil {
		t.Fatalf("unmarshal subdomains: %v", err)
	}
	if len(subs) != 2 || subs[0] != "www.example.com" || subs[1] != "api.example.com" {
		t.Fatalf("subdomains JSON = %#v, want [www.example.com api.example.com]", subs)
	}

	var portsJSON []snapshotPort
	if err := json.Unmarshal([]byte(snap.Ports), &portsJSON); err != nil {
		t.Fatalf("unmarshal ports: %v", err)
	}
	if len(portsJSON) != 2 {
		t.Fatalf("ports JSON len = %d, want 2", len(portsJSON))
	}
	if portsJSON[0] != (snapshotPort{Host: "www.example.com", Port: 80, Service: "http", State: "open"}) {
		t.Fatalf("ports[0] = %#v", portsJSON[0])
	}
	if portsJSON[1] != (snapshotPort{Host: "www.example.com", Port: 443, Service: "https", State: "open"}) {
		t.Fatalf("ports[1] = %#v", portsJSON[1])
	}

	var vulnsJSON []snapshotVuln
	if err := json.Unmarshal([]byte(snap.Vulnerabilities), &vulnsJSON); err != nil {
		t.Fatalf("unmarshal vulns: %v", err)
	}
	if len(vulnsJSON) != 2 {
		t.Fatalf("vulns JSON len = %d, want 2", len(vulnsJSON))
	}
	if vulnsJSON[0] != (snapshotVuln{TemplateID: "cve-2024-0001", Name: "Critical RCE", Severity: "critical", Host: "www.example.com"}) {
		t.Fatalf("vulns[0] = %#v", vulnsJSON[0])
	}
	if vulnsJSON[1] != (snapshotVuln{TemplateID: "exposed-panel", Name: "Exposed admin", Severity: "high", Host: "api.example.com"}) {
		t.Fatalf("vulns[1] = %#v", vulnsJSON[1])
	}

	var counts snapshotFindingCounts
	if err := json.Unmarshal([]byte(snap.FindingCounts), &counts); err != nil {
		t.Fatalf("unmarshal finding_counts: %v", err)
	}
	if counts.Vulnerabilities != 2 || counts.Takeovers != 1 || counts.Critical != 1 {
		t.Fatalf("finding_counts = %+v, want vulnerabilities=2 takeovers=1 critical=1", counts)
	}
}

func TestSaveSnapshotRejectsNilOrEmptyDomain(t *testing.T) {
	db := newTestDB(t)
	store := NewStore(db)

	if err := store.SaveSnapshot(nil, "full"); err == nil {
		t.Fatal("SaveSnapshot(nil) = nil, want error")
	}
	if err := store.SaveSnapshot(&parallel.ScanResult{}, "full"); err == nil {
		t.Fatal("SaveSnapshot(empty domain) = nil, want error")
	}
	if err := SaveScanSnapshot(nil, &parallel.ScanResult{Domain: "example.com"}, "full"); err == nil {
		t.Fatal("SaveScanSnapshot(nil db) = nil, want error")
	}
}

func TestSaveSnapshotRejectedInsideTransaction(t *testing.T) {
	db := newTestDB(t)
	err := db.WithTransaction(func(tx *database.Transaction) error {
		s, err := newStore(tx)
		if err != nil {
			return err
		}
		return s.SaveSnapshot(&parallel.ScanResult{Domain: "example.com"}, "full")
	})
	if err == nil {
		t.Fatal("expected error for SaveSnapshot inside a transaction")
	}
}

func newTestDB(t *testing.T) *database.Database {
	t.Helper()

	db, err := database.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("database.New returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}
