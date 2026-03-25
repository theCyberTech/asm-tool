package takeover

import (
	"testing"
	"time"
)

func TestDefaultDetector(t *testing.T) {
	d := DefaultDetector()

	if d == nil {
		t.Fatal("DefaultDetector returned nil")
	}

	if d.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}

	if d.HTTPClient == nil {
		t.Error("HTTPClient should not be nil")
	}

	if d.Workers != 20 {
		t.Errorf("expected 20 workers, got %d", d.Workers)
	}

	if d.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", d.Timeout)
	}

	if len(d.Fingerprints) == 0 {
		t.Error("fingerprints should not be empty")
	}
}

func TestNewDetector(t *testing.T) {
	// Test with TLS verification disabled
	d := NewDetector(true)
	if !d.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when passed true")
	}

	// Test with TLS verification enabled
	d = NewDetector(false)
	if d.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false when passed false")
	}
}

func TestDefaultFingerprints(t *testing.T) {
	fps := DefaultFingerprints()

	if len(fps) == 0 {
		t.Fatal("DefaultFingerprints should not be empty")
	}

	// Verify each fingerprint has required fields
	for i, fp := range fps {
		if fp.Service == "" {
			t.Errorf("fingerprint %d: Service should not be empty", i)
		}
		if len(fp.CNAMEPatterns) == 0 {
			t.Errorf("fingerprint %d (%s): CNAMEPatterns should not be empty", i, fp.Service)
		}
	}

	// Check for well-known services
	services := make(map[string]bool)
	for _, fp := range fps {
		services[fp.Service] = true
	}

	expectedServices := []string{"GitHub Pages", "AWS S3", "Heroku", "Azure"}
	for _, svc := range expectedServices {
		if !services[svc] {
			t.Errorf("expected service '%s' not found in fingerprints", svc)
		}
	}
}

func TestFindingStruct(t *testing.T) {
	finding := &Finding{
		Subdomain:     "test.example.com",
		CNAME:         "test.github.io",
		Service:       "GitHub Pages",
		Type:          "cname_to_unregistered",
		Confidence:    "HIGH",
		Evidence:      "404 response",
		Documentation: "https://docs.github.com/...",
		Vulnerable:    true,
	}

	if finding.Subdomain != "test.example.com" {
		t.Error("finding subdomain not set correctly")
	}
	if !finding.Vulnerable {
		t.Error("finding should be marked as vulnerable")
	}
	if finding.Confidence != "HIGH" {
		t.Error("finding confidence not set correctly")
	}
}

func TestResultStruct(t *testing.T) {
	result := &Result{
		Domain:   "example.com",
		Findings: []*Finding{{Subdomain: "test.example.com", Vulnerable: true}},
		Checked:  10,
		Duration: 5 * time.Second,
		Errors:   []string{"error1"},
	}

	if result.Domain != "example.com" {
		t.Error("result domain not set correctly")
	}
	if len(result.Findings) != 1 {
		t.Error("result findings not set correctly")
	}

	// Test VulnerableCount
	vulnCount := result.VulnerableCount()
	if vulnCount != 1 {
		t.Errorf("expected 1 vulnerable, got %d", vulnCount)
	}

	// Test HighConfidenceCount
	result.Findings[0].Confidence = "HIGH"
	highCount := result.HighConfidenceCount()
	if highCount != 1 {
		t.Errorf("expected 1 high confidence, got %d", highCount)
	}
}

func TestFingerprintStruct(t *testing.T) {
	fp := Fingerprint{
		Service:       "GitHub Pages",
		CNAMEPatterns: []string{"github.io"},
		Fingerprints:  []string{"There isn't a GitHub Pages site here"},
		HTTPStatus:    []int{404},
		Documentation: "https://docs.github.com/...",
		Vulnerable:    true,
	}

	if fp.Service != "GitHub Pages" {
		t.Error("fingerprint service not set correctly")
	}
	if len(fp.CNAMEPatterns) != 1 {
		t.Error("fingerprint CNAME patterns not set correctly")
	}
	if !fp.Vulnerable {
		t.Error("fingerprint should be marked as vulnerable")
	}
}

// TestDefaultFingerprints_VulnerableFlag verifies that services which handle
// dangling CNAMEs safely are marked Vulnerable=false, and truly vulnerable
// services are marked Vulnerable=true.
func TestDefaultFingerprints_VulnerableFlag(t *testing.T) {
	fps := DefaultFingerprints()
	byService := make(map[string]Fingerprint)
	for _, fp := range fps {
		byService[fp.Service] = fp
	}

	shouldBeVulnerable := []string{"AWS S3", "GitHub Pages", "Heroku"}
	for _, svc := range shouldBeVulnerable {
		fp, ok := byService[svc]
		if !ok {
			t.Logf("service %q not found in fingerprints, skipping", svc)
			continue
		}
		if !fp.Vulnerable {
			t.Errorf("service %q should have Vulnerable=true", svc)
		}
	}

	// These services do NOT allow takeover; they serve a 404 themselves.
	shouldNotBeVulnerable := []string{"Shopify", "Netlify", "Vercel"}
	for _, svc := range shouldNotBeVulnerable {
		fp, ok := byService[svc]
		if !ok {
			t.Logf("service %q not found in fingerprints, skipping", svc)
			continue
		}
		if fp.Vulnerable {
			t.Errorf("service %q should have Vulnerable=false (handles dangling CNAMEs)", svc)
		}
	}
}

func TestMatchesCNAME(t *testing.T) {
	d := DefaultDetector()
	tests := []struct {
		cname    string
		patterns []string
		want     bool
	}{
		{"mybucket.s3.amazonaws.com", []string{".s3.amazonaws.com"}, true},
		{"myapp.github.io", []string{".github.io"}, true},
		{"example.com", []string{".github.io", ".s3.amazonaws.com"}, false},
		{"", []string{".github.io"}, false},
	}
	for _, tt := range tests {
		got := d.matchesCNAME(tt.cname, tt.patterns)
		if got != tt.want {
			t.Errorf("matchesCNAME(%q, %v) = %v, want %v", tt.cname, tt.patterns, got, tt.want)
		}
	}
}

func TestResultHelperMethods(t *testing.T) {
	result := &Result{
		Domain: "example.com",
		Findings: []*Finding{
			{Subdomain: "a.example.com", Vulnerable: true, Confidence: "HIGH"},
			{Subdomain: "b.example.com", Vulnerable: true, Confidence: "MEDIUM"},
			{Subdomain: "c.example.com", Vulnerable: false, Confidence: "LOW"},
		},
		Checked: 10,
	}

	// Test VulnerableCount
	if result.VulnerableCount() != 2 {
		t.Errorf("expected 2 vulnerable, got %d", result.VulnerableCount())
	}

	// Test HighConfidenceCount
	if result.HighConfidenceCount() != 1 {
		t.Errorf("expected 1 high confidence, got %d", result.HighConfidenceCount())
	}
}
