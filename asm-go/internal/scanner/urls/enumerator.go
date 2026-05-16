package urls

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/asm-tool/asm-go/internal/ratelimit"
	"github.com/asm-tool/asm-go/internal/target"
)

// URL represents a discovered URL with metadata
type URL struct {
	URL         string
	Domain      string
	Path        string
	Params      []string
	Category    string // js, api, config, backup, interesting, etc.
	Source      string
	Interesting bool

	// Liveness probe results (populated by ProbeURLs)
	StatusCode  int
	ContentType string
	Redirects   string // final URL after redirects (if different)
	Live        bool   // true if we got any HTTP response
}

// Result represents URL enumeration results
type Result struct {
	Domain     string
	URLs       []URL
	Sources    map[string]int
	Categories map[string]int
	Duration   time.Duration
	Errors     []string
}

// Source represents a URL enumeration source
type Source interface {
	Name() string
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

// Enumerator discovers URLs from multiple sources
type Enumerator struct {
	Sources    []Source
	HTTPClient *http.Client
	Timeout    time.Duration
}

// DefaultEnumerator returns an enumerator with built-in sources and no rate limiting.
func DefaultEnumerator() *Enumerator {
	return NewEnumeratorWithRateLimit(0)
}

// NewEnumeratorWithRateLimit returns an enumerator that caps outbound HTTP
// requests to rps requests per second across all sources. rps <= 0 means unlimited.
func NewEnumeratorWithRateLimit(rps int) *Enumerator {
	var transport http.RoundTripper = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}
	transport = ratelimit.NewTransport(transport, rps)

	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}

	return &Enumerator{
		Sources: []Source{
			&WaybackSource{client: client},
			&CommonCrawlSource{client: client},
			&URLScanSource{client: client},
			&AlienVaultSource{client: client},
		},
		HTTPClient: client,
		Timeout:    2 * time.Minute,
	}
}

// Enumerate discovers URLs from all sources
func (e *Enumerator) Enumerate(ctx context.Context, domain string) *Result {
	start := time.Now()
	normalizedDomain, err := target.NormalizeTarget(domain)
	result := &Result{
		Domain:     normalizedDomain,
		Sources:    make(map[string]int),
		Categories: make(map[string]int),
	}
	if err != nil {
		result.Domain = strings.TrimSpace(domain)
		result.Errors = append(result.Errors, err.Error())
		result.Duration = time.Since(start)
		return result
	}
	domain = normalizedDomain

	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	// Run sources concurrently
	type sourceResult struct {
		source string
		urls   []string
		err    error
	}

	resultCh := make(chan sourceResult, len(e.Sources))
	var wg sync.WaitGroup

	for _, src := range e.Sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			urls, err := s.Enumerate(ctx, domain)
			resultCh <- sourceResult{
				source: s.Name(),
				urls:   urls,
				err:    err,
			}
		}(src)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect and deduplicate
	seen := make(map[string]bool)
	for sr := range resultCh {
		if sr.err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sr.source, sr.err))
			continue
		}

		count := 0
		for _, rawURL := range sr.urls {
			rawURL = normalizeURL(rawURL)
			if rawURL == "" || seen[rawURL] {
				continue
			}

			// Validate URL belongs to domain
			if !urlBelongsToDomain(rawURL, domain) {
				continue
			}

			seen[rawURL] = true
			count++

			u := categorizeURL(rawURL, domain, sr.source)
			result.URLs = append(result.URLs, u)
			result.Categories[u.Category]++
		}
		result.Sources[sr.source] = count
	}

	// Sort by URL
	sort.Slice(result.URLs, func(i, j int) bool {
		return result.URLs[i].URL < result.URLs[j].URL
	})

	result.Duration = time.Since(start)
	return result
}

// GetInteresting returns URLs flagged as interesting
func (r *Result) GetInteresting() []URL {
	var interesting []URL
	for _, u := range r.URLs {
		if u.Interesting {
			interesting = append(interesting, u)
		}
	}
	return interesting
}

// GetByCategory returns URLs of a specific category
func (r *Result) GetByCategory(category string) []URL {
	var urls []URL
	for _, u := range r.URLs {
		if u.Category == category {
			urls = append(urls, u)
		}
	}
	return urls
}

// ProbeURLs performs liveness checks against the given URLs concurrently.
// It issues a HEAD request (falling back to GET on failure) and records
// the status code, content-type, and final URL after redirects.
// concurrency controls the number of simultaneous requests.
func (e *Enumerator) ProbeURLs(ctx context.Context, urlList []URL, concurrency int) []URL {
	if concurrency <= 0 {
		concurrency = 20
	}

	// Probe client: short timeout, follow redirects, record final URL.
	probeClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	result := make([]URL, len(urlList))
	copy(result, urlList)

	for i := range result {
		select {
		case <-ctx.Done():
			return result
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			u := &result[idx]
			probed := probeURL(ctx, probeClient, u.URL)

			mu.Lock()
			u.StatusCode = probed.StatusCode
			u.ContentType = probed.ContentType
			u.Redirects = probed.Redirects
			u.Live = probed.Live
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	return result
}

type probeResult struct {
	StatusCode  int
	ContentType string
	Redirects   string
	Live        bool
}

func probeURL(ctx context.Context, client *http.Client, rawURL string) probeResult {
	do := func(method string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ASM-Tool/2.0)")
		return client.Do(req)
	}

	resp, err := do("HEAD")
	if err != nil || resp.StatusCode == http.StatusMethodNotAllowed {
		// Fall back to GET
		if resp != nil {
			resp.Body.Close()
		}
		resp, err = do("GET")
	}
	if err != nil {
		return probeResult{}
	}
	defer resp.Body.Close()

	pr := probeResult{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Live:        true,
	}

	// Record final URL if redirected
	if resp.Request != nil && resp.Request.URL.String() != rawURL {
		pr.Redirects = resp.Request.URL.String()
	}

	return pr
}

func normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	// Add scheme if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	// Parse and normalize
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Remove fragments
	parsed.Fragment = ""

	return parsed.String()
}

func urlBelongsToDomain(rawURL, domain string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	return target.IsSubdomainOf(host, domain)
}

func categorizeURL(rawURL, domain, source string) URL {
	parsed, _ := url.Parse(rawURL)

	u := URL{
		URL:      rawURL,
		Domain:   domain,
		Path:     parsed.Path,
		Source:   source,
		Category: "other",
	}

	// Extract parameters
	for param := range parsed.Query() {
		u.Params = append(u.Params, param)
	}

	path := strings.ToLower(parsed.Path)
	pathAndQuery := strings.ToLower(rawURL)

	// Categorize based on patterns
	switch {
	// JavaScript files
	case strings.HasSuffix(path, ".js"):
		u.Category = "js"
		u.Interesting = true

	// API endpoints
	case strings.Contains(path, "/api/") ||
		strings.Contains(path, "/v1/") ||
		strings.Contains(path, "/v2/") ||
		strings.Contains(path, "/v3/") ||
		strings.Contains(path, "/graphql") ||
		strings.Contains(path, "/rest/"):
		u.Category = "api"
		u.Interesting = true

	// Configuration files
	case strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, ".xml") ||
		strings.HasSuffix(path, ".yaml") ||
		strings.HasSuffix(path, ".yml") ||
		strings.HasSuffix(path, ".conf") ||
		strings.HasSuffix(path, ".config") ||
		strings.HasSuffix(path, ".ini") ||
		strings.HasSuffix(path, ".env"):
		u.Category = "config"
		u.Interesting = true

	// Backup files
	case strings.HasSuffix(path, ".bak") ||
		strings.HasSuffix(path, ".backup") ||
		strings.HasSuffix(path, ".old") ||
		strings.HasSuffix(path, ".orig") ||
		strings.HasSuffix(path, ".save") ||
		strings.HasSuffix(path, ".swp") ||
		strings.HasSuffix(path, "~") ||
		strings.Contains(path, ".bak.") ||
		strings.Contains(path, ".backup."):
		u.Category = "backup"
		u.Interesting = true

	// Archives
	case strings.HasSuffix(path, ".zip") ||
		strings.HasSuffix(path, ".tar") ||
		strings.HasSuffix(path, ".tar.gz") ||
		strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".rar") ||
		strings.HasSuffix(path, ".7z"):
		u.Category = "archive"
		u.Interesting = true

	// Admin/sensitive paths
	case strings.Contains(path, "/admin") ||
		strings.Contains(path, "/login") ||
		strings.Contains(path, "/dashboard") ||
		strings.Contains(path, "/panel") ||
		strings.Contains(path, "/console") ||
		strings.Contains(path, "/manager"):
		u.Category = "admin"
		u.Interesting = true

	// Source code / dev files
	case strings.HasSuffix(path, ".php") ||
		strings.HasSuffix(path, ".asp") ||
		strings.HasSuffix(path, ".aspx") ||
		strings.HasSuffix(path, ".jsp"):
		u.Category = "server-code"

	// Static files
	case strings.HasSuffix(path, ".css") ||
		strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".jpg") ||
		strings.HasSuffix(path, ".gif") ||
		strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".svg") ||
		strings.HasSuffix(path, ".woff") ||
		strings.HasSuffix(path, ".woff2"):
		u.Category = "static"

	// Documents
	case strings.HasSuffix(path, ".pdf") ||
		strings.HasSuffix(path, ".doc") ||
		strings.HasSuffix(path, ".docx") ||
		strings.HasSuffix(path, ".xls") ||
		strings.HasSuffix(path, ".xlsx"):
		u.Category = "document"
	}

	// Check for sensitive parameters
	sensitiveParams := []string{"token", "key", "api_key", "apikey", "secret", "password", "pass", "auth", "session", "jwt", "access_token", "refresh_token"}
	for _, param := range u.Params {
		paramLower := strings.ToLower(param)
		for _, sensitive := range sensitiveParams {
			if strings.Contains(paramLower, sensitive) {
				u.Interesting = true
				break
			}
		}
	}

	// Check for interesting patterns in URL
	interestingPatterns := []string{
		"debug", "test", "staging", "dev", "internal", "private",
		"upload", "download", "export", "import", "backup",
		"redirect", "callback", "oauth", "saml", "sso",
	}
	for _, pattern := range interestingPatterns {
		if strings.Contains(pathAndQuery, pattern) {
			u.Interesting = true
			break
		}
	}

	return u
}

// WaybackSource queries the Wayback Machine
type WaybackSource struct {
	client *http.Client
}

func (s *WaybackSource) Name() string { return "wayback" }

func (s *WaybackSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s&output=txt&fl=original&collapse=urlkey", url.QueryEscape("*."+domain+"/*"))

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

	var urls []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	return urls, scanner.Err()
}

// CommonCrawlSource queries CommonCrawl index
type CommonCrawlSource struct {
	client *http.Client
}

func (s *CommonCrawlSource) Name() string { return "commoncrawl" }

// getLatestCommonCrawlIndex fetches the most recent CommonCrawl index ID.
// Falls back to a recent hardcoded value if the collinfo API is unreachable.
func (s *CommonCrawlSource) getLatestIndex(ctx context.Context) string {
	const fallback = "CC-MAIN-2025-13"

	req, err := http.NewRequestWithContext(ctx, "GET", "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return fallback
	}
	req.Header.Set("User-Agent", "ASM-Tool/2.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return fallback
	}
	defer resp.Body.Close()

	var indexes []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&indexes); err != nil || len(indexes) == 0 {
		return fallback
	}
	return indexes[0].ID
}

func (s *CommonCrawlSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	index := s.getLatestIndex(ctx)
	apiURL := fmt.Sprintf("https://index.commoncrawl.org/%s-index?url=%s&output=json", url.PathEscape(index), url.QueryEscape("*."+domain))

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

	var urls []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var entry struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil && entry.URL != "" {
			urls = append(urls, entry.URL)
		}
	}

	return urls, nil
}

// URLScanSource queries urlscan.io
type URLScanSource struct {
	client *http.Client
}

func (s *URLScanSource) Name() string { return "urlscan" }

func (s *URLScanSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=%s&size=1000", url.QueryEscape("domain:"+domain))

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
				URL string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var urls []string
	for _, r := range data.Results {
		if r.Page.URL != "" {
			urls = append(urls, r.Page.URL)
		}
	}

	return urls, nil
}

// AlienVaultSource queries AlienVault OTX
type AlienVaultSource struct {
	client *http.Client
}

func (s *AlienVaultSource) Name() string { return "alienvault" }

func (s *AlienVaultSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500", url.PathEscape(domain))

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

	var data struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	var urls []string
	for _, entry := range data.URLList {
		if entry.URL != "" {
			urls = append(urls, entry.URL)
		}
	}

	return urls, nil
}

// Patterns for extracting URLs from JavaScript
var jsURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["'](https?://[^"'\s<>]+)["']`),
	regexp.MustCompile(`["'](/[a-zA-Z0-9_/\-\.]+)["']`),
}

// ExtractFromJS extracts URLs from JavaScript content
func ExtractFromJS(content, baseURL string) []string {
	var urls []string
	seen := make(map[string]bool)

	for _, pattern := range jsURLPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				u := match[1]
				if strings.HasPrefix(u, "/") {
					// Relative URL
					if parsed, err := url.Parse(baseURL); err == nil {
						u = fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, u)
					}
				}
				if !seen[u] {
					seen[u] = true
					urls = append(urls, u)
				}
			}
		}
	}

	return urls
}
