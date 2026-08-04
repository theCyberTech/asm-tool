package takeover

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/asm-tool/asm-go/internal/httpclient"
)

// Finding represents a potential subdomain takeover
type Finding struct {
	Subdomain     string
	CNAME         string
	Service       string
	Type          string
	Confidence    string // HIGH, MEDIUM, LOW
	Evidence      string
	Documentation string
	Vulnerable    bool
}

// Result represents takeover detection results
type Result struct {
	Domain   string
	Findings []*Finding
	Checked  int
	Duration time.Duration
	Errors   []string
}

// Detector checks for subdomain takeover vulnerabilities
type Detector struct {
	HTTPClient         *http.Client
	Timeout            time.Duration
	Workers            int
	Fingerprints       []Fingerprint
	InsecureSkipVerify bool // Whether to skip TLS certificate verification
}

// Fingerprint represents a service takeover fingerprint
type Fingerprint struct {
	Service       string
	CNAMEPatterns []string
	Fingerprints  []string // Response body patterns
	HTTPStatus    []int    // Expected HTTP status codes
	Documentation string
	Vulnerable    bool // Is the service currently vulnerable
}

// DefaultDetector returns a detector with built-in fingerprints (TLS verification enabled by default)
func DefaultDetector() *Detector {
	return NewDetector(false)
}

// NewDetector returns a detector with configurable TLS verification
func NewDetector(insecureSkipVerify bool) *Detector {
	return &Detector{
		HTTPClient: httpclient.New(httpclient.Options{
			Timeout:            10 * time.Second,
			InsecureSkipVerify: insecureSkipVerify,
		}),
		Timeout:            10 * time.Second,
		Workers:            20,
		Fingerprints:       DefaultFingerprints(),
		InsecureSkipVerify: insecureSkipVerify,
	}
}

// Check checks a single subdomain for takeover vulnerability.
// Returns (nil, nil) when the subdomain has no CNAME or is not vulnerable.
// Returns a non-nil error only for unexpected failures (DNS server errors,
// timeouts, etc.) — NXDOMAIN on the CNAME lookup is treated as "not applicable".
func (d *Detector) Check(ctx context.Context, subdomain string) (*Finding, error) {
	finding := &Finding{
		Subdomain: subdomain,
	}

	// Resolve CNAME
	cname, err := net.DefaultResolver.LookupCNAME(ctx, subdomain)
	if err != nil {
		// NXDOMAIN means no CNAME record — not an error, just not applicable.
		// Context cancellation is also not worth reporting per-subdomain.
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, nil
		}
		if ctx.Err() != nil {
			return nil, nil
		}
		return nil, fmt.Errorf("CNAME lookup for %s: %w", subdomain, err)
	}

	cname = strings.TrimSuffix(cname, ".")
	if cname == "" || cname == subdomain {
		return nil, nil
	}

	finding.CNAME = cname

	// Check if CNAME resolves
	_, err = net.DefaultResolver.LookupHost(ctx, cname)
	cnameResolvable := err == nil

	// Match against fingerprints
	for _, fp := range d.Fingerprints {
		if !d.matchesCNAME(cname, fp.CNAMEPatterns) {
			continue
		}

		finding.Service = fp.Service
		finding.Documentation = fp.Documentation

		// If CNAME doesn't resolve, check if the service is actually vulnerable
		// (some services like Shopify, Netlify, Vercel have protections and are not takeover-able)
		if !cnameResolvable {
			finding.Vulnerable = fp.Vulnerable
			finding.Confidence = "HIGH"
			finding.Type = "NXDOMAIN"
			finding.Evidence = fmt.Sprintf("CNAME %s does not resolve", cname)
			return finding, nil
		}

		// Check HTTP response for fingerprints
		if len(fp.Fingerprints) > 0 {
			if evidence := d.checkHTTPFingerprint(ctx, subdomain, fp); evidence != "" {
				finding.Vulnerable = fp.Vulnerable
				finding.Confidence = "MEDIUM"
				finding.Type = "FINGERPRINT"
				finding.Evidence = evidence
				return finding, nil
			}
		}

		// Check for specific HTTP status codes
		if len(fp.HTTPStatus) > 0 {
			if status := d.checkHTTPStatus(ctx, subdomain, fp.HTTPStatus); status > 0 {
				finding.Vulnerable = fp.Vulnerable
				finding.Confidence = "LOW"
				finding.Type = "HTTP_STATUS"
				finding.Evidence = fmt.Sprintf("HTTP status %d", status)
				return finding, nil
			}
		}
	}

	return nil, nil
}

// CheckBatch checks multiple subdomains for takeover vulnerabilities
func (d *Detector) CheckBatch(ctx context.Context, subdomains []string) *Result {
	start := time.Now()
	result := &Result{
		Checked: len(subdomains),
	}

	findings := make(chan *Finding, len(subdomains))
	errors := make(chan string, len(subdomains))

	sem := make(chan struct{}, d.Workers)
	var wg sync.WaitGroup

	for _, sub := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			finding, err := d.Check(ctx, subdomain)
			if err != nil {
				errors <- err.Error()
			}
			if finding != nil && finding.Vulnerable {
				findings <- finding
			}
		}(sub)
	}

	go func() {
		wg.Wait()
		close(findings)
		close(errors)
	}()

	for finding := range findings {
		result.Findings = append(result.Findings, finding)
	}

	for err := range errors {
		result.Errors = append(result.Errors, err)
	}

	result.Duration = time.Since(start)
	return result
}

func (d *Detector) matchesCNAME(cname string, patterns []string) bool {
	cname = strings.ToLower(cname)
	for _, pattern := range patterns {
		if strings.Contains(cname, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func (d *Detector) checkHTTPFingerprint(ctx context.Context, subdomain string, fp Fingerprint) string {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ASM-Tool/2.0")

		resp, err := d.HTTPClient.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // 100KB limit
		resp.Body.Close()

		bodyStr := string(body)
		for _, fingerprint := range fp.Fingerprints {
			if strings.Contains(bodyStr, fingerprint) {
				return fmt.Sprintf("Response contains: %s", fingerprint)
			}
		}
	}
	return ""
}

func (d *Detector) checkHTTPStatus(ctx context.Context, subdomain string, expectedStatus []int) int {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ASM-Tool/2.0")

		resp, err := d.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		// Drain body to allow connection reuse, then close
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()

		for _, status := range expectedStatus {
			if resp.StatusCode == status {
				return status
			}
		}
	}
	return 0
}

// DefaultFingerprints returns the built-in takeover fingerprints
func DefaultFingerprints() []Fingerprint {
	return []Fingerprint{
		// AWS S3
		{
			Service:       "AWS S3",
			CNAMEPatterns: []string{".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"},
			Fingerprints:  []string{"NoSuchBucket", "The specified bucket does not exist"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/36",
		},
		// GitHub Pages
		{
			Service:       "GitHub Pages",
			CNAMEPatterns: []string{".github.io", ".githubusercontent.com"},
			Fingerprints:  []string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"},
			HTTPStatus:    []int{404},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/37",
		},
		// Heroku
		{
			Service:       "Heroku",
			CNAMEPatterns: []string{".herokuapp.com", ".herokussl.com"},
			Fingerprints:  []string{"No such app", "no-such-app"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/38",
		},
		// Shopify
		{
			Service:       "Shopify",
			CNAMEPatterns: []string{".myshopify.com"},
			Fingerprints:  []string{"Sorry, this shop is currently unavailable", "Only one step left"},
			Vulnerable:    false, // Shopify has protections now
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/32",
		},
		// Tumblr
		{
			Service:       "Tumblr",
			CNAMEPatterns: []string{".tumblr.com"},
			Fingerprints:  []string{"There's nothing here", "Whatever you were looking for doesn't currently exist at this address"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/77",
		},
		// WordPress.com
		{
			Service:       "WordPress.com",
			CNAMEPatterns: []string{".wordpress.com"},
			Fingerprints:  []string{"Do you want to register"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/76",
		},
		// Azure
		{
			Service:       "Azure",
			CNAMEPatterns: []string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net", ".azurehdinsight.net", ".azureedge.net"},
			Fingerprints:  []string{"404 Web Site not found", "Web App - Pair Verification"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35",
		},
		// Fastly
		{
			Service:       "Fastly",
			CNAMEPatterns: []string{".fastly.net", ".fastlylb.net"},
			Fingerprints:  []string{"Fastly error: unknown domain"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/22",
		},
		// Pantheon
		{
			Service:       "Pantheon",
			CNAMEPatterns: []string{".pantheonsite.io", ".pantheon.io"},
			Fingerprints:  []string{"404 error unknown site", "The gods are wise"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/24",
		},
		// Zendesk
		{
			Service:       "Zendesk",
			CNAMEPatterns: []string{".zendesk.com"},
			Fingerprints:  []string{"Help Center Closed", "this help center no longer exists"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/23",
		},
		// Surge.sh
		{
			Service:       "Surge.sh",
			CNAMEPatterns: []string{".surge.sh"},
			Fingerprints:  []string{"project not found"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/48",
		},
		// Netlify
		{
			Service:       "Netlify",
			CNAMEPatterns: []string{".netlify.app", ".netlify.com"},
			Fingerprints:  []string{"Not Found - Request ID"},
			Vulnerable:    false, // Netlify has protections
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/40",
		},
		// Vercel
		{
			Service:       "Vercel",
			CNAMEPatterns: []string{".vercel.app", ".now.sh"},
			Fingerprints:  []string{"The deployment could not be found"},
			Vulnerable:    false, // Vercel has protections
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/183",
		},
		// Fly.io
		{
			Service:       "Fly.io",
			CNAMEPatterns: []string{".fly.dev"},
			Fingerprints:  []string{"404 Not Found"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		// Cargo Collective
		{
			Service:       "Cargo Collective",
			CNAMEPatterns: []string{".cargocollective.com", "subdomain.cargocollective.com"},
			Fingerprints:  []string{"404 Not Found"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/152",
		},
		// Bitbucket
		{
			Service:       "Bitbucket",
			CNAMEPatterns: []string{".bitbucket.io"},
			Fingerprints:  []string{"Repository not found"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/73",
		},
		// Ghost
		{
			Service:       "Ghost",
			CNAMEPatterns: []string{".ghost.io"},
			Fingerprints:  []string{"The thing you were looking for is no longer here"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/12",
		},
		// Intercom
		{
			Service:       "Intercom",
			CNAMEPatterns: []string{".custom.intercom.help"},
			Fingerprints:  []string{"This page is reserved for"},
			Vulnerable:    false,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/100",
		},
		// Readme.io
		{
			Service:       "Readme.io",
			CNAMEPatterns: []string{".readme.io"},
			Fingerprints:  []string{"Project doesnt exist"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/41",
		},
		// Tilda
		{
			Service:       "Tilda",
			CNAMEPatterns: []string{".tilda.ws"},
			Fingerprints:  []string{"Please renew your subscription"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/155",
		},
		// Webflow
		{
			Service:       "Webflow",
			CNAMEPatterns: []string{".webflow.io"},
			Fingerprints:  []string{"The page you are looking for doesn't exist or has been moved"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/44",
		},
		// Unbounce
		{
			Service:       "Unbounce",
			CNAMEPatterns: []string{".unbounce.com", "unbouncepages.com"},
			Fingerprints:  []string{"The requested URL was not found on this server"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/11",
		},
		// HubSpot
		{
			Service:       "HubSpot",
			CNAMEPatterns: []string{".hubspot.net", ".hs-sites.com"},
			Fingerprints:  []string{"Domain not found"},
			Vulnerable:    false,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/135",
		},
		// LaunchRock
		{
			Service:       "LaunchRock",
			CNAMEPatterns: []string{".launchrock.com"},
			Fingerprints:  []string{"It looks like you may have taken a wrong turn somewhere"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/74",
		},
		// UserVoice
		{
			Service:       "UserVoice",
			CNAMEPatterns: []string{".uservoice.com"},
			Fingerprints:  []string{"This UserVoice subdomain is currently available"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/14",
		},
		// Cloudfront
		{
			Service:       "CloudFront",
			CNAMEPatterns: []string{".cloudfront.net"},
			Fingerprints:  []string{"Bad Request: ERROR: The request could not be satisfied"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/29",
		},
		// Elastic Beanstalk
		{
			Service:       "AWS Elastic Beanstalk",
			CNAMEPatterns: []string{".elasticbeanstalk.com"},
			Fingerprints:  []string{},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/194",
		},
		// Google Cloud Storage
		{
			Service:       "Google Cloud Storage",
			CNAMEPatterns: []string{".storage.googleapis.com", "c.storage.googleapis.com"},
			Fingerprints:  []string{"NoSuchBucket", "The specified bucket does not exist"},
			Vulnerable:    true,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		// Firebase
		{
			Service:       "Firebase",
			CNAMEPatterns: []string{".firebaseapp.com", ".web.app"},
			Fingerprints:  []string{"Site Not Found"},
			Vulnerable:    false,
			Documentation: "https://github.com/EdOverflow/can-i-take-over-xyz/issues/128",
		},
	}
}

// VulnerableCount returns the number of vulnerable findings
func (r *Result) VulnerableCount() int {
	count := 0
	for _, f := range r.Findings {
		if f.Vulnerable {
			count++
		}
	}
	return count
}

// HighConfidenceCount returns findings with HIGH confidence
func (r *Result) HighConfidenceCount() int {
	count := 0
	for _, f := range r.Findings {
		if f.Confidence == "HIGH" {
			count++
		}
	}
	return count
}

// Config holds configuration for takeover detection.
type Config struct {
	Workers            int
	Timeout            time.Duration
	HTTPClientTimeout  time.Duration
	InsecureSkipVerify bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Workers:           50,
		Timeout:           10 * time.Second,
		HTTPClientTimeout: 10 * time.Second,
	}
}

// ScanResult holds the result of takeover detection.
type ScanResult struct {
	Findings []Finding
	Duration time.Duration
	Err      error
}

// Scan performs takeover detection over hosts and returns findings.
func Scan(ctx context.Context, cfg Config, hosts []string) *ScanResult {
	if len(hosts) == 0 {
		return &ScanResult{}
	}

	// Apply defaults.
	if cfg.Workers == 0 {
		cfg.Workers = DefaultConfig().Workers
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}

	client := httpclient.New(httpclient.Options{
		Timeout:            cfg.Timeout,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})

	detector := &Detector{
		HTTPClient:         client,
		Timeout:            cfg.Timeout,
		Workers:            cfg.Workers,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		Fingerprints:       DefaultFingerprints(),
	}

	result := detector.CheckBatch(ctx, hosts)

	// Convert []*Finding to []Finding for the package-level return.
	findings := make([]Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, *f)
	}

	return &ScanResult{
		Findings: findings,
		Duration: result.Duration,
		Err:      result.firstError(),
	}
}

func (r *Result) firstError() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return fmt.Errorf("takeover errors: %s", strings.Join(r.Errors, "; "))
}
