package database

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	// Verify file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("database file was not created")
	}

	// Verify repositories are initialized
	if db.Domains == nil {
		t.Error("Domains repository is nil")
	}
	if db.Ports == nil {
		t.Error("Ports repository is nil")
	}
	if db.Certificates == nil {
		t.Error("Certificates repository is nil")
	}
	if db.Findings == nil {
		t.Error("Findings repository is nil")
	}
}

func TestNewCreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "subdir", "nested", "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	// Verify directories were created
	if _, err := os.Stat(filepath.Dir(dbPath)); os.IsNotExist(err) {
		t.Error("database directory was not created")
	}
}

func TestGetStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	stats, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	// Fresh database should have zero counts
	if stats.Domains != 0 {
		t.Errorf("expected 0 domains, got %d", stats.Domains)
	}
	if stats.Subdomains != 0 {
		t.Errorf("expected 0 subdomains, got %d", stats.Subdomains)
	}
}

func TestDomainRepository(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	// Test Add
	domain, err := db.Domains.Add("example.com")
	if err != nil {
		t.Fatalf("Add domain failed: %v", err)
	}

	if domain.ID == 0 {
		t.Error("domain ID should not be 0")
	}
	if domain.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got '%s'", domain.Domain)
	}

	// Test Add duplicate (should return existing)
	domain2, err := db.Domains.Add("example.com")
	if err != nil {
		t.Fatalf("Add duplicate domain failed: %v", err)
	}
	if domain2.ID != domain.ID {
		t.Error("duplicate add should return same domain")
	}

	// Test GetByName
	found, err := db.Domains.GetByName("example.com")
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}
	if found.ID != domain.ID {
		t.Error("GetByName returned wrong domain")
	}

	// Test List
	domains, err := db.Domains.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(domains) != 1 {
		t.Errorf("expected 1 domain, got %d", len(domains))
	}

	// Test AddSubdomain
	err = db.Domains.AddSubdomain(domain.ID, "www.example.com")
	if err != nil {
		t.Fatalf("AddSubdomain failed: %v", err)
	}

	// Test GetSubdomains
	subs, err := db.Domains.GetSubdomains(domain.ID)
	if err != nil {
		t.Fatalf("GetSubdomains failed: %v", err)
	}
	if len(subs) != 1 {
		t.Errorf("expected 1 subdomain, got %d", len(subs))
	}

	// Test GetSubdomainsByDomainName
	subNames, err := db.Domains.GetSubdomainsByDomainName("example.com")
	if err != nil {
		t.Fatalf("GetSubdomainsByDomainName failed: %v", err)
	}
	if len(subNames) != 1 {
		t.Errorf("expected 1 subdomain name, got %d", len(subNames))
	}
	if subNames[0] != "www.example.com" {
		t.Errorf("expected 'www.example.com', got '%s'", subNames[0])
	}
}

func TestPortRepository(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	// Test Add
	port := &Port{
		Host:     "example.com",
		Port:     80,
		Protocol: "tcp",
		Service:  "http",
		State:    "open",
	}

	err = db.Ports.Add(port)
	if err != nil {
		t.Fatalf("Add port failed: %v", err)
	}

	// Test GetByHost
	ports, err := db.Ports.GetByHost("example.com")
	if err != nil {
		t.Fatalf("GetByHost failed: %v", err)
	}
	if len(ports) != 1 {
		t.Errorf("expected 1 port, got %d", len(ports))
	}
	if ports[0].Port != 80 {
		t.Errorf("expected port 80, got %d", ports[0].Port)
	}
}

func TestCertificateRepository(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	// Test Add
	cert := &Certificate{
		Host:            "example.com",
		Port:            443,
		Subject:         "example.com",
		Issuer:          "Let's Encrypt",
		SerialNumber:    "12345",
		NotBefore:       time.Now().Add(-24 * time.Hour),
		NotAfter:        time.Now().Add(90 * 24 * time.Hour),
		DaysUntilExpiry: 90,
		Fingerprint:     "abc123",
	}

	err = db.Certificates.Add(cert)
	if err != nil {
		t.Fatalf("Add certificate failed: %v", err)
	}

	// Test GetByHost
	foundCert, err := db.Certificates.GetByHost("example.com", 443)
	if err != nil {
		t.Fatalf("GetByHost failed: %v", err)
	}
	if foundCert.Subject != "example.com" {
		t.Errorf("expected subject 'example.com', got '%s'", foundCert.Subject)
	}

	// Test GetExpiring
	expiring, err := db.Certificates.GetExpiring(100)
	if err != nil {
		t.Fatalf("GetExpiring failed: %v", err)
	}
	if len(expiring) != 1 {
		t.Errorf("expected 1 expiring cert, got %d", len(expiring))
	}
}

func TestCloudStorageQueriesMapSchemaColumns(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	err = db.SaveCloudBucket(
		"s3",
		"example-assets",
		"https://example-assets.s3.amazonaws.com",
		"example.com",
		"authenticated_only",
		"low",
		"bucket exists but requires authentication",
	)
	if err != nil {
		t.Fatalf("SaveCloudBucket failed: %v", err)
	}

	allBuckets, err := db.GetAllCloudStorage()
	if err != nil {
		t.Fatalf("GetAllCloudStorage failed: %v", err)
	}
	if len(allBuckets) != 1 {
		t.Fatalf("GetAllCloudStorage returned %d buckets, want 1", len(allBuckets))
	}
	if allBuckets[0].BucketName != "example-assets" || allBuckets[0].Status != "open" {
		t.Fatalf("bucket = %+v, want example-assets open", allBuckets[0])
	}

	domainBuckets, err := db.GetCloudStorageForDomain("example.com")
	if err != nil {
		t.Fatalf("GetCloudStorageForDomain failed: %v", err)
	}
	if len(domainBuckets) != 1 {
		t.Fatalf("GetCloudStorageForDomain returned %d buckets, want 1", len(domainBuckets))
	}
}

func TestIsTableNotExistsError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"nil error", "", false},
		{"sqlite no such table", "no such table: test", true},
		{"mysql doesn't exist", "Table 'db.test' doesn't exist", true},
		{"other error", "connection refused", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = &mockError{msg: tt.errMsg}
			}
			result := isTableNotExistsError(err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

func TestDatabaseClose(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	err = db.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Verify database is closed by trying to use it
	_, err = db.Domains.List()
	if err == nil {
		t.Error("expected error after close, got nil")
	}
}
