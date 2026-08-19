package database

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHostBelongsToDomain(t *testing.T) {
	tests := []struct {
		host, domain string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"api.www.example.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"example.com.evil.example", "example.com", false},
		{"example.com", "notexample.com", false},
		{"EXAMPLE.COM", "example.com", true},
		{"www.example.com:443", "example.com", true},
		{"", "example.com", false},
	}
	for _, tt := range tests {
		if got := HostBelongsToDomain(tt.host, tt.domain); got != tt.want {
			t.Errorf("HostBelongsToDomain(%q, %q) = %v, want %v", tt.host, tt.domain, got, tt.want)
		}
	}
}

func TestURLBelongsToDomain(t *testing.T) {
	tests := []struct {
		raw, domain string
		want        bool
	}{
		{"https://api.example.com/v1", "example.com", true},
		{"http://example.com", "example.com", true},
		{"https://notexample.com/path?q=example.com", "example.com", false},
		{"https://evil.example/redirect?next=https://example.com", "example.com", false},
		{"https://example.com.attacker.example/login", "example.com", false},
	}
	for _, tt := range tests {
		if got := URLBelongsToDomain(tt.raw, tt.domain); got != tt.want {
			t.Errorf("URLBelongsToDomain(%q, %q) = %v, want %v", tt.raw, tt.domain, got, tt.want)
		}
	}
}

func TestDomainScopedQueriesDoNotMatchUnrelatedHosts(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	if _, err := db.Domains.Add("example.com"); err != nil {
		t.Fatalf("Add domain: %v", err)
	}

	now := time.Now()
	if err := db.Certificates.Add(&Certificate{
		Host:            "notexample.com",
		Port:            443,
		Subject:         "unrelated",
		Issuer:          "test",
		SerialNumber:    "1",
		NotBefore:       now.Add(-24 * time.Hour),
		NotAfter:        now.Add(24 * time.Hour),
		DaysUntilExpiry: 1,
		Fingerprint:     "aaaa",
	}); err != nil {
		t.Fatalf("Add unrelated cert: %v", err)
	}
	if err := db.Certificates.Add(&Certificate{
		Host:            "www.example.com",
		Port:            443,
		Subject:         "www",
		Issuer:          "test",
		SerialNumber:    "2",
		NotBefore:       now.Add(-24 * time.Hour),
		NotAfter:        now.Add(24 * time.Hour),
		DaysUntilExpiry: 1,
		Fingerprint:     "bbbb",
	}); err != nil {
		t.Fatalf("Add related cert: %v", err)
	}

	if err := db.Findings.Add(&Finding{
		TemplateID: "t1",
		Name:       "unrelated",
		Severity:   "high",
		Host:       "notexample.com",
		Status:     "open",
	}); err != nil {
		t.Fatalf("Add unrelated finding: %v", err)
	}
	if err := db.Findings.Add(&Finding{
		TemplateID: "t2",
		Name:       "related",
		Severity:   "critical",
		Host:       "api.example.com",
		Status:     "open",
	}); err != nil {
		t.Fatalf("Add related finding: %v", err)
	}

	if err := db.SaveTakeover("notexample.com", "cname", "s3", "HIGH", "x"); err != nil {
		t.Fatalf("Save unrelated takeover: %v", err)
	}
	if err := db.SaveTakeover("dev.example.com", "cname", "s3", "HIGH", "x"); err != nil {
		t.Fatalf("Save related takeover: %v", err)
	}

	if err := db.SaveAPI("https://notexample.com/swagger.json", "openapi", "Nope", "3.0", 0, "[]"); err != nil {
		t.Fatalf("Save unrelated API: %v", err)
	}
	if err := db.SaveAPI("https://api.example.com/swagger.json", "openapi", "Yes", "3.0", 1, "[]"); err != nil {
		t.Fatalf("Save related API: %v", err)
	}
	if err := db.SaveAPI("https://evil.example/docs?site=example.com", "documentation", "Nope", "", 0, "[]"); err != nil {
		t.Fatalf("Save path-only API: %v", err)
	}

	if err := db.Ports.Add(&Port{Host: "example.com", Port: 443, State: "open", Service: "https"}); err != nil {
		t.Fatalf("Add apex port: %v", err)
	}
	if err := db.Ports.Add(&Port{Host: "notexample.com", Port: 80, State: "open", Service: "http"}); err != nil {
		t.Fatalf("Add unrelated port: %v", err)
	}

	certs, err := db.GetCertificatesForDomain("example.com")
	if err != nil {
		t.Fatalf("GetCertificatesForDomain: %v", err)
	}
	if len(certs) != 1 || certs[0].Host != "www.example.com" {
		t.Fatalf("certs = %+v, want only www.example.com", certs)
	}

	findings, err := db.GetVulnerabilitiesForDomain("example.com")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForDomain: %v", err)
	}
	if len(findings) != 1 || findings[0].Host != "api.example.com" {
		t.Fatalf("findings = %+v, want only api.example.com", findings)
	}

	takeovers, err := db.GetTakeoversForDomain("example.com")
	if err != nil {
		t.Fatalf("GetTakeoversForDomain: %v", err)
	}
	if len(takeovers) != 1 || takeovers[0].Subdomain != "dev.example.com" {
		t.Fatalf("takeovers = %+v, want only dev.example.com", takeovers)
	}

	apis, err := db.GetAPIsForDomain("example.com")
	if err != nil {
		t.Fatalf("GetAPIsForDomain: %v", err)
	}
	if len(apis) != 1 || apis[0].URL != "https://api.example.com/swagger.json" {
		t.Fatalf("apis = %+v, want only api.example.com", apis)
	}

	ports, err := db.GetPortsForDomain("example.com")
	if err != nil {
		t.Fatalf("GetPortsForDomain: %v", err)
	}
	if len(ports) != 1 || ports[0].Host != "example.com" {
		t.Fatalf("ports = %+v, want apex example.com", ports)
	}

	stats, err := db.GetDomainDetailStats("example.com")
	if err != nil {
		t.Fatalf("GetDomainDetailStats: %v", err)
	}
	if stats.CertificateCount != 1 || stats.VulnCount != 1 || stats.APICount != 1 || stats.PortCount != 1 || stats.TakeoverCount != 1 {
		t.Fatalf("stats = %+v, want cert/vuln/api/port/takeover counts of 1", stats)
	}

	domains, err := db.GetDomainsWithStats()
	if err != nil {
		t.Fatalf("GetDomainsWithStats: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("GetDomainsWithStats len = %d, want 1", len(domains))
	}
	if domains[0].PortCount != 1 {
		t.Fatalf("overview port count = %d, want 1 (apex)", domains[0].PortCount)
	}
	if domains[0].CriticalCount != 1 || domains[0].HighCount != 0 {
		t.Fatalf("overview finding counts critical=%d high=%d, want 1/0", domains[0].CriticalCount, domains[0].HighCount)
	}
}

func TestDomainMatchEscapesLikeWildcards(t *testing.T) {
	if HostBelongsToDomain("aXexample.com", "a_example.com") {
		t.Fatal("underscore must not be a LIKE wildcard")
	}
	if escapeLikePattern(`100%_fun\`) != `100\%\_fun\\` {
		t.Fatalf("escapeLikePattern = %q", escapeLikePattern(`100%_fun\`))
	}
}
