package emails

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/theCyberTech/asm-tool/asm-go/internal/httpclient"
	"github.com/theCyberTech/asm-tool/asm-go/internal/target"
)

// Email represents a discovered email address
type Email struct {
	Address  string
	Domain   string
	Source   string
	Type     string // personal, generic, role, guessed
	Verified bool
}

// Result represents email enumeration results
type Result struct {
	Domain   string
	Emails   []Email
	Sources  map[string]int
	Duration time.Duration
	Errors   []string
}

// Source represents an email enumeration source
type Source interface {
	Name() string
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

// Enumerator discovers email addresses from multiple sources
type Enumerator struct {
	Sources    []Source
	HunterRef  *HunterSource // reference to configure API key
	HTTPClient *http.Client
	Timeout    time.Duration
}

// DefaultEnumerator returns an enumerator with built-in sources
func DefaultEnumerator() *Enumerator {
	client := httpclient.New(httpclient.Options{Timeout: 30 * time.Second})

	hunter := &HunterSource{client: client}

	return &Enumerator{
		Sources: []Source{
			hunter,
			&SkymemSource{client: client},
			&GitHubEmailSource{client: client},
			&EmailPermutatorSource{client: client},
		},
		HunterRef:  hunter,
		HTTPClient: client,
		Timeout:    90 * time.Second,
	}
}

// DefaultEnumeratorWithHunterAPIKey returns the default enumerator with Hunter configured.
func DefaultEnumeratorWithHunterAPIKey(apiKey string) *Enumerator {
	e := DefaultEnumerator()
	e.SetHunterAPIKey(apiKey)
	return e
}

// SetHunterAPIKey wires a configured Hunter.io API key into the Hunter source.
func (e *Enumerator) SetHunterAPIKey(apiKey string) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return
	}
	if e.HunterRef != nil {
		e.HunterRef.APIKey = apiKey
	} else {
		hunter := &HunterSource{client: e.HTTPClient, APIKey: apiKey}
		e.HunterRef = hunter
		e.Sources = append(e.Sources, hunter)
	}
}

// Enumerate discovers emails from all sources
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

	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	type sourceResult struct {
		source string
		emails []string
		err    error
	}

	resultCh := make(chan sourceResult, len(e.Sources))
	var wg sync.WaitGroup

	for _, src := range e.Sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			emails, err := s.Enumerate(ctx, domain)
			resultCh <- sourceResult{
				source: s.Name(),
				emails: emails,
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
		for _, email := range sr.emails {
			email = normalizeEmail(email)
			if email == "" || seen[email] {
				continue
			}

			// Validate email belongs to domain
			if !emailBelongsToDomain(email, domain) {
				continue
			}

			seen[email] = true
			count++

			result.Emails = append(result.Emails, emailFromSource(email, domain, sr.source))
		}
		result.Sources[sr.source] = count
	}

	// Sort by address
	sort.Slice(result.Emails, func(i, j int) bool {
		return result.Emails[i].Address < result.Emails[j].Address
	})

	result.Duration = time.Since(start)
	return result
}

// GetByType returns emails of a specific type
func (r *Result) GetByType(emailType string) []Email {
	var emails []Email
	for _, e := range r.Emails {
		if e.Type == emailType {
			emails = append(emails, e)
		}
	}
	return emails
}

func normalizeEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if !emailRegex.MatchString(email) {
		return ""
	}
	return email
}

func emailBelongsToDomain(email, domain string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	emailDomain := strings.ToLower(parts[1])
	return target.IsSubdomainOf(emailDomain, domain)
}

var roleEmailLocalParts = [...]string{
	"admin", "administrator", "webmaster", "postmaster", "hostmaster",
	"info", "contact", "support", "help", "sales", "marketing",
	"hr", "jobs", "careers", "recruiting", "legal", "compliance",
	"security", "abuse", "noc", "operations", "billing", "finance",
	"press", "media", "pr", "news", "office", "team", "staff",
	"hello", "hi", "enquiries", "inquiries", "feedback",
}

var genericEmailLocalPatterns = [...]string{
	"noreply", "no-reply", "donotreply", "mailer", "newsletter", "notification",
}

// emailFromSource builds an Email record for a discovered address.
// Permutator results are labeled as guesses: MX only means the domain
// accepts mail, not that the mailbox exists.
func emailFromSource(address, domain, source string) Email {
	email := Email{
		Address:  address,
		Domain:   domain,
		Source:   source,
		Verified: false,
		Type:     classifyEmail(address),
	}
	if source == "permutator" || source == (&EmailPermutatorSource{}).Name() {
		email.Type = "guessed"
	}
	return email
}

func classifyEmail(email string) string {
	local := strings.Split(email, "@")[0]
	local = strings.ToLower(local)

	// Role-based emails
	for _, role := range roleEmailLocalParts {
		if local == role || strings.HasPrefix(local, role+".") || strings.HasSuffix(local, "."+role) {
			return "role"
		}
	}

	// Generic patterns
	for _, pattern := range genericEmailLocalPatterns {
		if strings.Contains(local, pattern) {
			return "generic"
		}
	}

	return "personal"
}

var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

// GitHubEmailSource searches GitHub for email addresses in commits
type GitHubEmailSource struct {
	client *http.Client
}

func (s *GitHubEmailSource) Name() string { return "github" }

func (s *GitHubEmailSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	// Search GitHub for email patterns in code
	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=\\\"@%s\\\"&per_page=100", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ASM-Tool/2.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// GitHub API rate limits without auth
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited by GitHub API")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	// Extract emails from search results
	return extractEmails(string(body), domain), nil
}

// SkymemSource queries Skymem
type SkymemSource struct {
	client *http.Client
}

func (s *SkymemSource) Name() string { return "skymem" }

func (s *SkymemSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://www.skymem.info/srch?q=%s", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

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

	return extractEmails(string(body), domain), nil
}

// EmailPermutatorSource generates common email permutations for domains with
// valid MX records. MX only means the domain accepts mail; the addresses
// themselves are guesses, not verified mailboxes.
type EmailPermutatorSource struct {
	client *http.Client
}

func (s *EmailPermutatorSource) Name() string { return "permutator" }

func (s *EmailPermutatorSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	// Only generate permutations if the domain has MX records
	if !hasMXRecords(ctx, domain) {
		return nil, nil
	}

	patterns := []string{
		"info", "contact", "support", "help", "admin",
		"sales", "marketing", "hr", "jobs", "careers",
		"hello", "team", "office", "press", "media",
		"billing", "finance", "legal", "security",
		"noreply", "no-reply", "webmaster", "postmaster",
		"hostmaster", "abuse", "feedback", "enquiries",
	}

	emails := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		emails = append(emails, fmt.Sprintf("%s@%s", pattern, domain))
	}

	return emails, nil
}

// hasMXRecords checks if a domain has MX records indicating it accepts email.
func hasMXRecords(ctx context.Context, domain string) bool {
	mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain)
	return err == nil && len(mxRecords) > 0
}

// HunterSource queries Hunter.io (requires API key)
type HunterSource struct {
	client *http.Client
	APIKey string
}

func (s *HunterSource) Name() string { return "hunter" }

func (s *HunterSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	if s.APIKey == "" {
		return nil, fmt.Errorf("no API key configured")
	}

	apiURL := fmt.Sprintf("https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s", url.QueryEscape(domain), url.QueryEscape(s.APIKey))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var data struct {
		Data struct {
			Emails []struct {
				Value string `json:"value"`
			} `json:"emails"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var emails []string
	for _, e := range data.Data.Emails {
		if e.Value != "" {
			emails = append(emails, e.Value)
		}
	}

	return emails, nil
}

// extractEmails extracts email addresses from text
func extractEmails(text, domain string) []string {
	var emails []string
	seen := make(map[string]bool)

	matches := emailRegex.FindAllString(text, -1)
	for _, match := range matches {
		match = strings.ToLower(strings.TrimSpace(match))
		if !seen[match] && emailBelongsToDomain(match, domain) {
			seen[match] = true
			emails = append(emails, match)
		}
	}

	return emails
}

// CommonRoleEmails returns common role-based email addresses to try
func CommonRoleEmails(domain string) []string {
	roles := []string{
		"admin", "administrator", "webmaster", "postmaster", "hostmaster",
		"info", "contact", "support", "help", "sales", "marketing",
		"hr", "jobs", "careers", "legal", "security", "abuse",
		"billing", "finance", "press", "media", "office", "team",
		"hello", "enquiries", "feedback", "noreply",
	}

	var emails []string
	for _, role := range roles {
		emails = append(emails, fmt.Sprintf("%s@%s", role, domain))
	}
	return emails
}

// Config holds configuration for email enumeration.
type Config struct {
	HunterAPIKey string
	RateLimit    int
	Timeout      time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout: 90 * time.Second,
	}
}

// ScanResult holds the result of email enumeration.
type ScanResult struct {
	Emails []Email
	Errors []string
	Err    error
}

// Scan enumerates emails from passive sources.
func Scan(ctx context.Context, cfg Config, domain string) *ScanResult {
	client := httpclient.New(httpclient.Options{Timeout: 30 * time.Second})

	hunter := &HunterSource{client: client, APIKey: cfg.HunterAPIKey}
	sources := []Source{
		hunter,
		&SkymemSource{client: client},
		&GitHubEmailSource{client: client},
		&EmailPermutatorSource{client: client},
	}

	enum := &Enumerator{
		Sources:    sources,
		HunterRef:  hunter,
		HTTPClient: client,
		Timeout:    cfg.Timeout,
	}

	r := enum.Enumerate(ctx, domain)
	return &ScanResult{
		Emails: r.Emails,
		Errors: r.Errors,
		Err:    firstError(r.Errors),
	}
}

// firstError returns a non-nil error if errs has any entries.
func firstError(errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
}
