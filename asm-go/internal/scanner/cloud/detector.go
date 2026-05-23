package cloud

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"github.com/asm-tool/asm-go/internal/scanner/safehttp"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Bucket represents a discovered cloud storage bucket
type Bucket struct {
	URL         string
	Provider    string // s3, azure, gcs
	BucketName  string
	Domain      string
	Source      string // url_extraction, active_probe
	AccessLevel string // listing_enabled, public_read, authenticated_only, not_found
	Severity    string // critical, high, medium, low
	Evidence    string
}

// Result represents cloud storage detection results
type Result struct {
	Domain   string
	Buckets  []Bucket
	Checked  int
	Duration time.Duration
	Errors   []string
}

// Detector finds cloud storage buckets
type Detector struct {
	HTTPClient         *http.Client
	Timeout            time.Duration
	Workers            int
	Patterns           map[string][]*regexp.Regexp
	InsecureSkipVerify bool // Whether to skip TLS certificate verification
}

// DefaultDetector returns a detector with built-in patterns (TLS verification enabled by default)
func DefaultDetector() *Detector {
	return NewDetector(false)
}

// NewDetector returns a detector with configurable TLS verification
func NewDetector(insecureSkipVerify bool) *Detector {
	return &Detector{
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
			},
			CheckRedirect: safehttp.NoFollow,
		},
		Timeout:            10 * time.Second,
		Workers:            20,
		Patterns:           DefaultPatterns(),
		InsecureSkipVerify: insecureSkipVerify,
	}
}

// ExtractFromURLs finds bucket references in a list of URLs
func (d *Detector) ExtractFromURLs(urls []string, domain string) []Bucket {
	var buckets []Bucket
	seen := make(map[string]bool)

	for _, url := range urls {
		for provider, patterns := range d.Patterns {
			for _, pattern := range patterns {
				matches := pattern.FindStringSubmatch(url)
				if len(matches) > 1 {
					bucketName := matches[1]
					key := provider + ":" + bucketName

					if !seen[key] {
						seen[key] = true
						buckets = append(buckets, Bucket{
							URL:        url,
							Provider:   provider,
							BucketName: bucketName,
							Domain:     domain,
							Source:     "url_extraction",
						})
					}
				}
			}
		}
	}

	return buckets
}

// CheckAccess verifies bucket access levels
func (d *Detector) CheckAccess(ctx context.Context, buckets []Bucket) *Result {
	start := time.Now()
	result := &Result{
		Checked: len(buckets),
	}

	if len(buckets) == 0 {
		result.Duration = time.Since(start)
		return result
	}

	resultCh := make(chan Bucket, len(buckets))
	sem := make(chan struct{}, d.Workers)
	var wg sync.WaitGroup

	for _, bucket := range buckets {
		wg.Add(1)
		go func(b Bucket) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			checked := d.checkBucketAccess(ctx, b)
			if checked.AccessLevel != "" {
				resultCh <- checked
			}
		}(bucket)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for bucket := range resultCh {
		result.Buckets = append(result.Buckets, bucket)
	}

	result.Duration = time.Since(start)
	return result
}

// ProbeCommonBuckets probes for common bucket naming patterns
func (d *Detector) ProbeCommonBuckets(ctx context.Context, domain string) *Result {
	start := time.Now()
	result := &Result{Domain: domain}

	// Generate common bucket names based on domain
	names := generateBucketNames(domain)
	result.Checked = len(names) * 3 // S3, Azure, GCS

	resultCh := make(chan Bucket, len(names)*3)
	sem := make(chan struct{}, d.Workers)
	var wg sync.WaitGroup

	for _, name := range names {
		// Check S3
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			bucket := Bucket{
				URL:        fmt.Sprintf("https://%s.s3.amazonaws.com", n),
				Provider:   "s3",
				BucketName: n,
				Domain:     domain,
				Source:     "active_probe",
			}

			checked := d.checkBucketAccess(ctx, bucket)
			if checked.AccessLevel != "not_found" && checked.AccessLevel != "" {
				resultCh <- checked
			}
		}(name)

		// Check Azure
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			bucket := Bucket{
				URL:        fmt.Sprintf("https://%s.blob.core.windows.net", n),
				Provider:   "azure",
				BucketName: n,
				Domain:     domain,
				Source:     "active_probe",
			}

			checked := d.checkBucketAccess(ctx, bucket)
			if checked.AccessLevel != "not_found" && checked.AccessLevel != "" {
				resultCh <- checked
			}
		}(name)

		// Check GCS
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			bucket := Bucket{
				URL:        fmt.Sprintf("https://storage.googleapis.com/%s", n),
				Provider:   "gcs",
				BucketName: n,
				Domain:     domain,
				Source:     "active_probe",
			}

			checked := d.checkBucketAccess(ctx, bucket)
			if checked.AccessLevel != "not_found" && checked.AccessLevel != "" {
				resultCh <- checked
			}
		}(name)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for bucket := range resultCh {
		result.Buckets = append(result.Buckets, bucket)
	}

	result.Duration = time.Since(start)
	return result
}

func (d *Detector) checkBucketAccess(ctx context.Context, bucket Bucket) Bucket {
	// Build the URL to check based on provider
	var checkURL string
	switch bucket.Provider {
	case "s3":
		checkURL = fmt.Sprintf("https://%s.s3.amazonaws.com", bucket.BucketName)
	case "azure":
		checkURL = fmt.Sprintf("https://%s.blob.core.windows.net/?restype=container&comp=list", bucket.BucketName)
	case "gcs":
		checkURL = fmt.Sprintf("https://storage.googleapis.com/%s", bucket.BucketName)
	default:
		checkURL = bucket.URL
	}

	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		return bucket
	}
	req.Header.Set("User-Agent", "ASM-Tool/2.0")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		bucket.AccessLevel = "not_found"
		return bucket
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	switch bucket.Provider {
	case "s3":
		bucket = d.classifyS3Response(bucket, resp.StatusCode, bodyStr)
	case "azure":
		bucket = d.classifyAzureResponse(bucket, resp.StatusCode, bodyStr)
	case "gcs":
		bucket = d.classifyGCSResponse(bucket, resp.StatusCode, bodyStr)
	}

	return bucket
}

func (d *Detector) classifyS3Response(bucket Bucket, status int, body string) Bucket {
	switch {
	case status == 200 && strings.Contains(body, "<ListBucketResult"):
		bucket.AccessLevel = "listing_enabled"
		bucket.Severity = "critical"
		bucket.Evidence = "Bucket listing is publicly accessible"

	case status == 200:
		bucket.AccessLevel = "public_read"
		bucket.Severity = "high"
		bucket.Evidence = "Bucket allows public read access"

	case status == 403:
		if strings.Contains(body, "AccessDenied") {
			bucket.AccessLevel = "authenticated_only"
			bucket.Severity = "low"
			bucket.Evidence = "Bucket exists but requires authentication"
		}

	case status == 404:
		if strings.Contains(body, "NoSuchBucket") {
			bucket.AccessLevel = "not_found"
		}

	default:
		bucket.AccessLevel = "unknown"
	}

	return bucket
}

func (d *Detector) classifyAzureResponse(bucket Bucket, status int, body string) Bucket {
	switch {
	case status == 200 && strings.Contains(body, "<EnumerationResults"):
		bucket.AccessLevel = "listing_enabled"
		bucket.Severity = "critical"
		bucket.Evidence = "Container listing is publicly accessible"

	case status == 200:
		bucket.AccessLevel = "public_read"
		bucket.Severity = "high"
		bucket.Evidence = "Container allows public read access"

	case status == 403 || status == 401:
		bucket.AccessLevel = "authenticated_only"
		bucket.Severity = "low"
		bucket.Evidence = "Container exists but requires authentication"

	case status == 404:
		bucket.AccessLevel = "not_found"

	default:
		bucket.AccessLevel = "unknown"
	}

	return bucket
}

func (d *Detector) classifyGCSResponse(bucket Bucket, status int, body string) Bucket {
	switch {
	case status == 200 && (strings.Contains(body, "<ListBucketResult") || strings.Contains(body, `"kind":"storage#objects"`) || strings.Contains(body, `"kind": "storage#objects"`)):
		bucket.AccessLevel = "listing_enabled"
		bucket.Severity = "critical"
		bucket.Evidence = "Bucket listing is publicly accessible"

	case status == 200:
		bucket.AccessLevel = "public_read"
		bucket.Severity = "high"
		bucket.Evidence = "Bucket allows public read access"

	case status == 403:
		bucket.AccessLevel = "authenticated_only"
		bucket.Severity = "low"
		bucket.Evidence = "Bucket exists but requires authentication"

	case status == 404:
		if strings.Contains(body, "NoSuchBucket") || strings.Contains(body, "not found") {
			bucket.AccessLevel = "not_found"
		}

	default:
		bucket.AccessLevel = "unknown"
	}

	return bucket
}

func generateBucketNames(domain string) []string {
	// Remove TLD for base name
	parts := strings.Split(domain, ".")
	baseName := parts[0]
	if len(parts) > 2 {
		baseName = strings.Join(parts[:len(parts)-1], "-")
	}

	// Clean the base name
	baseName = strings.ToLower(baseName)
	baseName = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(baseName, "-")

	names := []string{
		domain,
		baseName,
		baseName + "-backup",
		baseName + "-backups",
		baseName + "-data",
		baseName + "-files",
		baseName + "-storage",
		baseName + "-assets",
		baseName + "-static",
		baseName + "-media",
		baseName + "-uploads",
		baseName + "-images",
		baseName + "-docs",
		baseName + "-documents",
		baseName + "-public",
		baseName + "-private",
		baseName + "-dev",
		baseName + "-staging",
		baseName + "-prod",
		baseName + "-production",
		baseName + "-test",
		baseName + "-logs",
		baseName + "-archive",
		baseName + "-cdn",
		baseName + "-website",
		baseName + "-web",
		baseName + "-app",
		baseName + "-api",
		"backup-" + baseName,
		"data-" + baseName,
		"files-" + baseName,
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, name := range names {
		if !seen[name] && len(name) >= 3 && len(name) <= 63 {
			seen[name] = true
			unique = append(unique, name)
		}
	}

	return unique
}

// DefaultPatterns returns regex patterns for cloud storage URLs
func DefaultPatterns() map[string][]*regexp.Regexp {
	return map[string][]*regexp.Regexp{
		"s3": {
			regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\.s3\.amazonaws\.com`),
			regexp.MustCompile(`(?i)s3\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])`),
			regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\.s3[\.-][a-z0-9\-]+\.amazonaws\.com`),
			regexp.MustCompile(`(?i)s3[\.-][a-z0-9\-]+\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])`),
		},
		"azure": {
			regexp.MustCompile(`(?i)([a-z0-9]{3,24})\.blob\.core\.windows\.net`),
			regexp.MustCompile(`(?i)([a-z0-9]{3,24})\.file\.core\.windows\.net`),
			regexp.MustCompile(`(?i)([a-z0-9]{3,24})\.queue\.core\.windows\.net`),
			regexp.MustCompile(`(?i)([a-z0-9]{3,24})\.table\.core\.windows\.net`),
		},
		"gcs": {
			regexp.MustCompile(`(?i)storage\.googleapis\.com/([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])`),
			regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])\.storage\.googleapis\.com`),
			regexp.MustCompile(`(?i)storage\.cloud\.google\.com/([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])`),
		},
	}
}

// GetCritical returns buckets with critical severity
func (r *Result) GetCritical() []Bucket {
	var buckets []Bucket
	for _, b := range r.Buckets {
		if b.Severity == "critical" {
			buckets = append(buckets, b)
		}
	}
	return buckets
}

// GetPubliclyAccessible returns buckets that are publicly accessible
func (r *Result) GetPubliclyAccessible() []Bucket {
	var buckets []Bucket
	for _, b := range r.Buckets {
		if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
			buckets = append(buckets, b)
		}
	}
	return buckets
}
