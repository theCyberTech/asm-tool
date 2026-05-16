package persistence

import (
	"path/filepath"
	"testing"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/scanner/apis"
	"github.com/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/asm-tool/asm-go/internal/scanner/emails"
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/asm-tool/asm-go/internal/scanner/urls"
)

func TestScannerHelpersPersistDashboardData(t *testing.T) {
	db := newTestDB(t)

	if saved, err := SaveURLs(db, []urls.URL{
		{Domain: "example.com", URL: "https://www.example.com/api/users", Category: "api", Source: "wayback", Interesting: true},
	}); err != nil || saved != 1 {
		t.Fatalf("SaveURLs saved=%d err=%v, want saved=1 err=nil", saved, err)
	}

	if saved, err := SaveAPIs(db, []apis.API{
		{URL: "https://www.example.com/openapi.json", Type: "openapi", Title: "Example API", Version: "3.0.0", EndpointsCount: 1, Endpoints: []string{"/users"}},
	}); err != nil || saved != 1 {
		t.Fatalf("SaveAPIs saved=%d err=%v, want saved=1 err=nil", saved, err)
	}

	if saved, err := SaveEmails(db, []emails.Email{
		{Domain: "example.com", Address: "security@example.com", Source: "crtsh", Type: "role"},
	}); err != nil || saved != 1 {
		t.Fatalf("SaveEmails saved=%d err=%v, want saved=1 err=nil", saved, err)
	}

	if saved, err := SaveCloudBuckets(db, []cloud.Bucket{
		{
			URL:         "https://example-assets.s3.amazonaws.com",
			Provider:    "s3",
			BucketName:  "example-assets",
			Domain:      "example.com",
			AccessLevel: "public_read",
			Severity:    "high",
			Evidence:    "public read",
		},
	}); err != nil || saved != 1 {
		t.Fatalf("SaveCloudBuckets saved=%d err=%v, want saved=1 err=nil", saved, err)
	}

	if saved, err := SaveTechnologies(db, []*technologies.Result{
		{
			Host:         "www.example.com",
			StatusCode:   200,
			Title:        "Example",
			Server:       "nginx",
			Technologies: []technologies.Technology{{Name: "React", Category: "javascript", Confidence: 100}},
			Headers:      map[string]string{"server": "nginx"},
		},
	}); err != nil || saved != 1 {
		t.Fatalf("SaveTechnologies saved=%d err=%v, want saved=1 err=nil", saved, err)
	}

	if saved, err := SaveTakeovers(db, []TakeoverFinding{
		{Subdomain: "dangling.example.com", CNAME: "dangling.github.io", Service: "github", Confidence: "HIGH", Evidence: "unclaimed", Vulnerable: true},
	}); err != nil || saved != 1 {
		t.Fatalf("SaveTakeovers saved=%d err=%v, want saved=1 err=nil", saved, err)
	}

	if saved, err := SaveNucleiFindings(db, []*nuclei.Finding{
		{TemplateID: "unknown-severity", Info: nuclei.TemplateInfo{Name: "Unknown severity finding", Severity: "unknown"}, Host: "www.example.com"},
	}); err != nil || saved != 1 {
		t.Fatalf("SaveNucleiFindings saved=%d err=%v, want saved=1 err=nil", saved, err)
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
