package parallel

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asm-tool/asm-go/internal/database"
)

func TestPersistResultsCommitsSuccessfulScan(t *testing.T) {
	r, db := newPersistenceTestRunner(t)

	result := &ScanResult{
		Subdomains: []string{"www.example.com"},
		Ports: []PortResult{
			{Host: "www.example.com", Port: 443, State: "open", Service: "https"},
		},
		URLs: []URLResult{
			{Domain: "example.com", URL: "https://www.example.com/api/users", Category: "api", Source: "wayback", Interesting: true},
		},
		APIs: []APIResult{
			{URL: "https://www.example.com/openapi.json", Type: "openapi", Title: "Example API", Version: "3.0.0", EndpointsCount: 1, Endpoints: []string{"/users"}},
		},
		Emails: []EmailResult{
			{Domain: "example.com", Address: "security@example.com", Source: "crtsh", Type: "role"},
		},
		CloudStorage: []CloudBucket{
			{
				URL:         "https://example-assets.s3.amazonaws.com",
				Provider:    "s3",
				BucketName:  "example-assets",
				Domain:      "example.com",
				AccessLevel: "public_read",
				Severity:    "high",
				Evidence:    "public read",
			},
		},
	}

	if err := r.persistResults("example.com", result); err != nil {
		t.Fatalf("persistResults returned error: %v", err)
	}

	stats, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats returned error: %v", err)
	}
	if stats.Domains != 1 {
		t.Fatalf("domains count = %d, want 1", stats.Domains)
	}
	if stats.Subdomains != 1 {
		t.Fatalf("subdomains count = %d, want 1", stats.Subdomains)
	}
	if stats.Ports != 1 {
		t.Fatalf("ports count = %d, want 1", stats.Ports)
	}
	if stats.URLs != 1 {
		t.Fatalf("urls count = %d, want 1", stats.URLs)
	}
	if stats.APIs != 1 {
		t.Fatalf("apis count = %d, want 1", stats.APIs)
	}
	if stats.Emails != 1 {
		t.Fatalf("emails count = %d, want 1", stats.Emails)
	}
	if stats.CloudBuckets != 1 {
		t.Fatalf("cloud bucket count = %d, want 1", stats.CloudBuckets)
	}

	domain, err := db.Domains.GetByName("example.com")
	if err != nil {
		t.Fatalf("GetByName returned error: %v", err)
	}
	if domain.LastScanned == nil {
		t.Fatal("last_scanned was not updated")
	}
}

func TestPersistResultsRollsBackScanAndReturnsAggregatedWriteErrors(t *testing.T) {
	r, db := newPersistenceTestRunner(t)

	result := &ScanResult{
		Subdomains: []string{"www.example.com"},
		Ports: []PortResult{
			{Host: "www.example.com", Port: 443, State: "open", Service: "https"},
		},
		Takeovers: []TakeoverResult{
			{
				Host:       "dangling.example.com",
				Vulnerable: true,
				Service:    "github",
				Confidence: "INVALID",
				Evidence:   "test evidence",
			},
		},
		CloudStorage: []CloudBucket{
			{
				URL:         "https://storage.example.com/bucket",
				Provider:    "invalid-provider",
				BucketName:  "bucket",
				Domain:      "example.com",
				AccessLevel: "public_read",
				Severity:    "critical",
				Evidence:    "test evidence",
			},
		},
	}

	err := r.persistResults("example.com", result)
	if err == nil {
		t.Fatal("persistResults returned nil error")
	}

	errText := err.Error()
	for _, want := range []string{"saving takeover", "saving cloud bucket"} {
		if !strings.Contains(errText, want) {
			t.Fatalf("persistResults error = %q, want it to include %q", errText, want)
		}
	}

	stats, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats returned error: %v", err)
	}
	if stats.Domains != 0 || stats.Subdomains != 0 || stats.Ports != 0 {
		t.Fatalf("transaction left partial rows: domains=%d subdomains=%d ports=%d", stats.Domains, stats.Subdomains, stats.Ports)
	}
}

func TestRunReturnsPersistenceErrors(t *testing.T) {
	r, db := newPersistenceTestRunner(t)
	for module := range r.EnabledModules {
		r.EnabledModules[module] = false
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	result, err := r.Run(context.Background(), "example.com")
	if err == nil {
		t.Fatal("Run returned nil error")
	}
	if result == nil {
		t.Fatal("Run returned nil result")
	}
	if result.Errors[ModuleType("persist")] == nil {
		t.Fatal("Run did not record the persistence error")
	}
}

func newPersistenceTestRunner(t *testing.T) (*Runner, *database.Database) {
	t.Helper()

	db, err := database.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("database.New returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	return DefaultRunner(db), db
}
