package cloud

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

	if len(d.Patterns) == 0 {
		t.Error("patterns should not be empty")
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

func TestExtractFromURLs(t *testing.T) {
	d := DefaultDetector()

	tests := []struct {
		name     string
		urls     []string
		domain   string
		expected int
		provider string
	}{
		{
			name:     "S3 bucket URL",
			urls:     []string{"https://mybucket.s3.amazonaws.com/"},
			domain:   "example.com",
			expected: 1,
			provider: "s3",
		},
		{
			name:     "S3 path style",
			urls:     []string{"https://s3.amazonaws.com/mybucket/"},
			domain:   "example.com",
			expected: 1,
			provider: "s3",
		},
		{
			name:     "Azure blob storage",
			urls:     []string{"https://myaccount.blob.core.windows.net/"},
			domain:   "example.com",
			expected: 1,
			provider: "azure",
		},
		{
			name:     "GCS bucket",
			urls:     []string{"https://storage.googleapis.com/mybucket/"},
			domain:   "example.com",
			expected: 1,
			provider: "gcs",
		},
		{
			name:     "No bucket URLs",
			urls:     []string{"https://example.com/page", "https://cdn.example.com/asset.js"},
			domain:   "example.com",
			expected: 0,
		},
		{
			name:     "Empty URLs",
			urls:     []string{},
			domain:   "example.com",
			expected: 0,
		},
		{
			name:     "Duplicate buckets",
			urls:     []string{"https://mybucket.s3.amazonaws.com/a", "https://mybucket.s3.amazonaws.com/b"},
			domain:   "example.com",
			expected: 1, // Should deduplicate
			provider: "s3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buckets := d.ExtractFromURLs(tt.urls, tt.domain)

			if len(buckets) != tt.expected {
				t.Errorf("expected %d buckets, got %d", tt.expected, len(buckets))
			}

			if tt.expected > 0 && len(buckets) > 0 {
				if buckets[0].Provider != tt.provider {
					t.Errorf("expected provider %s, got %s", tt.provider, buckets[0].Provider)
				}
				if buckets[0].Domain != tt.domain {
					t.Errorf("expected domain %s, got %s", tt.domain, buckets[0].Domain)
				}
				if buckets[0].Source != "url_extraction" {
					t.Errorf("expected source 'url_extraction', got '%s'", buckets[0].Source)
				}
			}
		})
	}
}

func TestDefaultPatterns(t *testing.T) {
	patterns := DefaultPatterns()

	// Should have patterns for S3, Azure, and GCS
	providers := []string{"s3", "azure", "gcs"}
	for _, provider := range providers {
		if _, ok := patterns[provider]; !ok {
			t.Errorf("missing patterns for provider: %s", provider)
		}
		if len(patterns[provider]) == 0 {
			t.Errorf("no patterns defined for provider: %s", provider)
		}
	}
}

func TestBucketStruct(t *testing.T) {
	bucket := Bucket{
		URL:         "https://test.s3.amazonaws.com/file.txt",
		Provider:    "s3",
		BucketName:  "test",
		Domain:      "example.com",
		Source:      "active_probe",
		AccessLevel: "public_read",
		Severity:    "high",
		Evidence:    "200 OK response",
	}

	if bucket.Provider != "s3" {
		t.Error("bucket provider not set correctly")
	}
	if bucket.Severity != "high" {
		t.Error("bucket severity not set correctly")
	}
}

func TestResultStruct(t *testing.T) {
	result := Result{
		Domain:   "example.com",
		Buckets:  []Bucket{{BucketName: "test"}},
		Checked:  10,
		Duration: 5 * time.Second,
		Errors:   []string{"error1"},
	}

	if result.Domain != "example.com" {
		t.Error("result domain not set correctly")
	}
	if len(result.Buckets) != 1 {
		t.Error("result buckets not set correctly")
	}
	if len(result.Errors) != 1 {
		t.Error("result errors not set correctly")
	}
}
