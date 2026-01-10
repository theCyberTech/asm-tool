package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
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

// DefaultEnumerator returns an enumerator with all built-in sources
func DefaultEnumerator() *Enumerator {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	return &Enumerator{
		Sources: []Source{
			&CrtShSource{client: client},
			&HackerTargetSource{client: client},
			&ThreatCrowdSource{client: client},
			&URLScanSource{client: client},
		},
		HTTPClient: client,
		Timeout:    60 * time.Second,
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
	result := &Result{
		Domain:  domain,
		Sources: make(map[string]int),
	}

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
	sub = strings.ToLower(strings.TrimSpace(sub))

	// Remove wildcards
	sub = strings.TrimPrefix(sub, "*.")
	sub = strings.TrimPrefix(sub, "www.")

	// Must end with the target domain
	if !strings.HasSuffix(sub, domain) {
		return ""
	}

	// Validate characters
	if !isValidSubdomain(sub) {
		return ""
	}

	return sub
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

// CrtShSource queries certificate transparency logs via crt.sh
type CrtShSource struct {
	client *http.Client
}

func (s *CrtShSource) Name() string { return "crt.sh" }

func (s *CrtShSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var subs []string
	for _, entry := range entries {
		// Handle multi-line entries
		for _, line := range strings.Split(entry.NameValue, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				subs = append(subs, line)
			}
		}
	}

	return subs, nil
}

// HackerTargetSource queries the HackerTarget API
type HackerTargetSource struct {
	client *http.Client
}

func (s *HackerTargetSource) Name() string { return "hackertarget" }

func (s *HackerTargetSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	body, err := io.ReadAll(resp.Body)
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

// ThreatCrowdSource queries ThreatCrowd API
type ThreatCrowdSource struct {
	client *http.Client
}

func (s *ThreatCrowdSource) Name() string { return "threatcrowd" }

func (s *ThreatCrowdSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return data.Subdomains, nil
}

// URLScanSource queries urlscan.io
type URLScanSource struct {
	client *http.Client
}

func (s *URLScanSource) Name() string { return "urlscan" }

func (s *URLScanSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

// AlienVaultSource queries AlienVault OTX
type AlienVaultSource struct {
	client *http.Client
}

func (s *AlienVaultSource) Name() string { return "alienvault" }

func (s *AlienVaultSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range data.PassiveDNS {
		if entry.Hostname != "" && !seen[entry.Hostname] {
			seen[entry.Hostname] = true
			subs = append(subs, entry.Hostname)
		}
	}

	return subs, nil
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

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidateDomain checks if a domain name is valid
func ValidateDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain)
}
