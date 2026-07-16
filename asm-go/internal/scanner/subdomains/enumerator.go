package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/asm-tool/asm-go/internal/ratelimit"
	"github.com/asm-tool/asm-go/internal/target"
)

// Result represents subdomain enumeration results
type Result struct {
	Domain     string
	Subdomains []string
	Sources    map[string]int // Count per source
	Duration   time.Duration
	Errors     []string
}

// Source represents a subdomain enumeration source
type Source interface {
	Name() string
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

// Enumerator discovers subdomains from multiple sources
type Enumerator struct {
	Sources    []Source
	HTTPClient *http.Client
	Timeout    time.Duration
}

// DefaultEnumerator returns an enumerator with all built-in sources and no rate limiting.
func DefaultEnumerator() *Enumerator {
	return NewEnumeratorWithRateLimit(0)
}

// NewEnumeratorWithRateLimit returns an enumerator that caps outbound HTTP
// requests to rps requests per second across all sources. rps <= 0 means unlimited.
func NewEnumeratorWithRateLimit(rps int) *Enumerator {
	var transport http.RoundTripper = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	transport = ratelimit.NewTransport(transport, rps)

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return &Enumerator{
		Sources: []Source{
			&CertSpotterSource{client: client},
			&HackerTargetSource{client: client},
			&URLScanSource{client: client},
			&RapidDNSSource{client: client},
		},
		HTTPClient: client,
		Timeout:    120 * time.Second,
	}
}

// NewEnumerator creates an enumerator with custom sources
func NewEnumerator(sources []Source, timeout time.Duration) *Enumerator {
	e := DefaultEnumerator()
	if len(sources) > 0 {
		e.Sources = sources
	}
	if timeout > 0 {
		e.Timeout = timeout
	}
	return e
}

// Enumerate discovers subdomains from all sources concurrently
func (e *Enumerator) Enumerate(ctx context.Context, domain string) *Result {
	start := time.Now()
	normalizedDomain, err := target.NormalizeTarget(domain)
	result := &Result{
		Domain:  normalizedDomain,
		Sources: make(map[string]int),
	}
	if err != nil {
		result.Domain = strings.TrimSpace(domain)
		result.Errors = append(result.Errors, err.Error())
		result.Duration = time.Since(start)
		return result
	}
	domain = normalizedDomain

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	// Run all sources concurrently
	type sourceResult struct {
		source string
		subs   []string
		err    error
	}

	resultCh := make(chan sourceResult, len(e.Sources))
	var wg sync.WaitGroup

	for _, src := range e.Sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			subs, err := s.Enumerate(ctx, domain)
			resultCh <- sourceResult{
				source: s.Name(),
				subs:   subs,
				err:    err,
			}
		}(src)
	}

	// Close channel when done
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect and deduplicate results
	seen := make(map[string]bool)
	for sr := range resultCh {
		if sr.err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sr.source, sr.err))
			continue
		}

		count := 0
		for _, sub := range sr.subs {
			sub = normalizeSubdomain(sub, domain)
			if sub != "" && !seen[sub] {
				seen[sub] = true
				result.Subdomains = append(result.Subdomains, sub)
				count++
			}
		}
		result.Sources[sr.source] = count
	}

	// Sort results
	sort.Strings(result.Subdomains)
	result.Duration = time.Since(start)

	return result
}

// normalizeSubdomain cleans and validates a subdomain
func normalizeSubdomain(sub, domain string) string {
	return target.NormalizeSubdomain(sub, domain)
}

// isValidSubdomain checks if a subdomain contains only valid characters
func isValidSubdomain(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// CertSpotterSource queries SSLMate's CertSpotter API for certificate transparency logs
type CertSpotterSource struct {
	client *http.Client
}

func (s *CertSpotterSource) Name() string { return "certspotter" }

func (s *CertSpotterSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", url.QueryEscape(domain))

	maxRetries := 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			waitDuration := time.Duration(2<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitDuration):
			}
		}

		req, reqErr := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("User-Agent", "ASM-Tool/2.0")

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()

			var certs []struct {
				DNSNames []string `json:"dns_names"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
				return nil, err
			}

			seen := make(map[string]bool)
			var subs []string
			for _, cert := range certs {
				for _, name := range cert.DNSNames {
					name = strings.TrimSpace(name)
					if name != "" && !seen[name] {
						seen[name] = true
						subs = append(subs, name)
					}
				}
			}
			return subs, nil
		}

		resp.Body.Close()

		// Rate limited or server error - retry
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}

		// Client errors - don't retry
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return nil, lastErr
}

// HackerTargetSource queries the HackerTarget API
type HackerTargetSource struct {
	client *http.Client
}

func (s *HackerTargetSource) Name() string { return "hackertarget" }

func (s *HackerTargetSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ASM-Tool/2.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	// Limit response body to 10MB to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	text := string(body)
	if strings.Contains(strings.ToLower(text), "error") {
		return nil, fmt.Errorf("API error: %s", text)
	}

	var subs []string
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			sub := strings.TrimSpace(parts[0])
			if sub != "" {
				subs = append(subs, sub)
			}
		}
	}

	return subs, nil
}

// URLScanSource queries urlscan.io
type URLScanSource struct {
	client *http.Client
}

func (s *URLScanSource) Name() string { return "urlscan" }

func (s *URLScanSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=%s", url.QueryEscape("domain:"+domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ASM-Tool/2.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var data struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var subs []string
	for _, r := range data.Results {
		d := r.Page.Domain
		if d != "" && !seen[d] {
			seen[d] = true
			subs = append(subs, d)
		}
	}

	return subs, nil
}

// RapidDNSSource scrapes rapiddns.io for subdomains

type RapidDNSSource struct {
	client *http.Client
}

func (s *RapidDNSSource) Name() string { return "rapiddns" }

func (s *RapidDNSSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s", url.QueryEscape(domain))

	maxRetries := 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			waitDuration := time.Duration(2<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitDuration):
			}
		}

		req, reqErr := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("User-Agent", "ASM-Tool/2.0")

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
			if err != nil {
				return nil, err
			}

			// Parse HTML table - look for <td> elements containing subdomains
			seen := make(map[string]bool)
			var subs []string
			for _, line := range strings.Split(string(body), "\n") {
				line = strings.TrimSpace(line)
				// Look for table rows with subdomains
				if strings.Contains(line, "<td>") {
					// Extract content between <td> and </td>
					start := strings.Index(line, "<td>")
					end := strings.Index(line, "</td>")
					if start >= 0 && end > start {
						val := strings.TrimSpace(line[start+4 : end])
						if val != "" && strings.HasSuffix(val, domain) && !seen[val] {
							seen[val] = true
							subs = append(subs, val)
						}
					}
				}
			}
			return subs, nil
		}

		resp.Body.Close()

		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return nil, lastErr
}

// DNSBruteSource performs DNS brute forcing with a wordlist
type DNSBruteSource struct {
	Wordlist []string
	Workers  int
}

func (s *DNSBruteSource) Name() string { return "dnsbrute" }

func (s *DNSBruteSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	if len(s.Wordlist) == 0 {
		s.Wordlist = DefaultWordlist()
	}
	if s.Workers == 0 {
		s.Workers = 50
	}

	var (
		mu   sync.Mutex
		subs []string
	)

	// Semaphore for limiting concurrent lookups
	sem := make(chan struct{}, s.Workers)
	var wg sync.WaitGroup

	for _, word := range s.Wordlist {
		select {
		case <-ctx.Done():
			return subs, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()

			sub := fmt.Sprintf("%s.%s", w, domain)
			if _, err := net.LookupHost(sub); err == nil {
				mu.Lock()
				subs = append(subs, sub)
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()
	return subs, nil
}

// DefaultWordlist returns a basic wordlist for DNS brute forcing
func DefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
		"ns3", "ns4", "dns", "dns1", "dns2", "api", "dev", "staging", "prod",
		"production", "stage", "test", "testing", "admin", "administrator", "app",
		"apps", "beta", "blog", "cdn", "cloud", "cms", "cpanel", "dashboard",
		"demo", "docs", "email", "git", "gitlab", "github", "help", "home",
		"intranet", "jenkins", "jira", "login", "m", "mobile", "mx", "mysql",
		"new", "news", "old", "panel", "portal", "proxy", "remote", "secure",
		"server", "shop", "sql", "ssh", "ssl", "static", "store", "support",
		"vpn", "web", "webdisk", "wiki", "www2", "www3",
	}
}

// ValidateDomain checks if a domain name is valid
func ValidateDomain(domain string) bool {
	return target.ValidateDomain(domain)
}

// Config holds configuration for subdomain enumeration.
type Config struct {
	Domain       string
	RateLimit    int // rps, 0 = unlimited
	Timeout      time.Duration
	CustomSources []Source
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout: 120 * time.Second,
	}
}

// ScanResult holds the result of subdomain enumeration.
type ScanResult struct {
	Subdomains []string
	Sources    map[string]int
	Duration   time.Duration
	Errors     []string
	Err        error
}

// Scan enumerates subdomains from all configured sources.
func Scan(ctx context.Context, cfg Config, domain string) *ScanResult {
	// Use custom sources if provided, otherwise use defaults.
	sources := cfg.CustomSources
	if len(sources) == 0 {
		// Build default sources with rate limiting
		var transport http.RoundTripper = &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		}
		transport = ratelimit.NewTransport(transport, cfg.RateLimit)
		client := &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		}

		sources = []Source{
			&CertSpotterSource{client: client},
			&HackerTargetSource{client: client},
			&URLScanSource{client: client},
			&RapidDNSSource{client: client},
		}
	}

	enum := &Enumerator{
		Sources: sources,
		Timeout: cfg.Timeout,
	}

	r := enum.Enumerate(ctx, domain)
	return &ScanResult{
		Subdomains: r.Subdomains,
		Sources:    r.Sources,
		Duration:   r.Duration,
		Errors:     r.Errors,
		Err:        r.firstError(),
	}
}

// firstError returns the first non-nil error from the errors slice.
func (r *Result) firstError() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return fmt.Errorf("enumeration errors: %s", strings.Join(r.Errors, "; "))
}
