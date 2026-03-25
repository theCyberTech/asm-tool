package emails

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Email represents a discovered email address
type Email struct {
	Address  string
	Domain   string
	Source   string
	Type     string // personal, generic, role
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
	HTTPClient *http.Client
	Timeout    time.Duration
}

// DefaultEnumerator returns an enumerator with built-in sources
func DefaultEnumerator() *Enumerator {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns: 100,
		},
	}

	return &Enumerator{
		Sources: []Source{
			&HunterSource{client: client},
			&SkymemSource{client: client},
			&CrtShEmailSource{client: client},
		},
		HTTPClient: client,
		Timeout:    60 * time.Second,
	}
}

// Enumerate discovers emails from all sources
func (e *Enumerator) Enumerate(ctx context.Context, domain string) *Result {
	start := time.Now()
	result := &Result{
		Domain:  domain,
		Sources: make(map[string]int),
	}

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

			result.Emails = append(result.Emails, Email{
				Address: email,
				Domain:  domain,
				Source:  sr.source,
				Type:    classifyEmail(email),
			})
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
	domain = strings.ToLower(domain)
	return emailDomain == domain || strings.HasSuffix(emailDomain, "."+domain)
}

func classifyEmail(email string) string {
	local := strings.Split(email, "@")[0]
	local = strings.ToLower(local)

	// Role-based emails
	roleEmails := []string{
		"admin", "administrator", "webmaster", "postmaster", "hostmaster",
		"info", "contact", "support", "help", "sales", "marketing",
		"hr", "jobs", "careers", "recruiting", "legal", "compliance",
		"security", "abuse", "noc", "operations", "billing", "finance",
		"press", "media", "pr", "news", "office", "team", "staff",
		"hello", "hi", "enquiries", "inquiries", "feedback",
	}

	for _, role := range roleEmails {
		if local == role || strings.HasPrefix(local, role+".") || strings.HasSuffix(local, "."+role) {
			return "role"
		}
	}

	// Generic patterns
	genericPatterns := []string{"noreply", "no-reply", "donotreply", "mailer", "newsletter", "notification"}
	for _, pattern := range genericPatterns {
		if strings.Contains(local, pattern) {
			return "generic"
		}
	}

	return "personal"
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// HunterSource queries Hunter.io (free tier)
type HunterSource struct {
	client *http.Client
	APIKey string
}

func (s *HunterSource) Name() string { return "hunter" }

func (s *HunterSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	if s.APIKey == "" {
		// Try without API key (very limited)
		return nil, fmt.Errorf("no API key configured")
	}

	apiURL := fmt.Sprintf("https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s", domain, s.APIKey)

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

// SkymemSource queries Skymem
type SkymemSource struct {
	client *http.Client
}

func (s *SkymemSource) Name() string { return "skymem" }

func (s *SkymemSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://www.skymem.info/srch?q=%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract emails from response
	return extractEmails(string(body), domain), nil
}

// CrtShEmailSource extracts emails from certificate data
type CrtShEmailSource struct {
	client *http.Client
}

func (s *CrtShEmailSource) Name() string { return "crtsh" }

func (s *CrtShEmailSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return extractEmails(string(body), domain), nil
}

// extractEmails extracts email addresses from text
func extractEmails(text, domain string) []string {
	var emails []string
	seen := make(map[string]bool)

	matches := emailRegex.FindAllString(text, -1)
	for _, match := range matches {
		match = strings.ToLower(match)
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
