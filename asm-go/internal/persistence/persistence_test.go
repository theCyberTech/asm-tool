package persistence

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/parallel"
	"github.com/asm-tool/asm-go/internal/scanner/apis"
	"github.com/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/asm-tool/asm-go/internal/scanner/emails"
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/asm-tool/asm-go/internal/scanner/ports"
	"github.com/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/asm-tool/asm-go/internal/scanner/urls"
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
