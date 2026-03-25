package technologies

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result represents technology fingerprinting results for a host
type Result struct {
	Host           string
	StatusCode     int
	Title          string
	Server         string
	Technologies   []Technology
	Headers        map[string]string
	ContentLength  int64
	RedirectURL    string
	ResponseTime   time.Duration
	Error          string
}

// Technology represents a detected technology
type Technology struct {
	Name       string
	Category   string
	Version    string
	Confidence int // 0-100
}

// Fingerprinter detects technologies on web servers
type Fingerprinter struct {
	HTTPClient *http.Client
	Timeout    time.Duration
	Workers    int
	Signatures []Signature
}

// Signature represents a technology detection signature
type Signature struct {
	Name       string
	Category   string
	Headers    map[string]*regexp.Regexp
	Cookies    map[string]*regexp.Regexp
	Meta       map[string]*regexp.Regexp
	HTML       []*regexp.Regexp
	Scripts    []*regexp.Regexp
	Implies    []string
}

// DefaultFingerprinter returns a fingerprinter with built-in signatures
func DefaultFingerprinter() *Fingerprinter {
	return &Fingerprinter{
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		Timeout:    10 * time.Second,
		Workers:    30,
		Signatures: DefaultSignatures(),
	}
}

// Fingerprint checks a single host for technologies
func (f *Fingerprinter) Fingerprint(ctx context.Context, host string) *Result {
	result := &Result{
		Host:    host,
		Headers: make(map[string]string),
	}

	// Try HTTPS first, then HTTP
	var resp *http.Response
	var body []byte
	var err error

	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host

		req, reqErr := http.NewRequestWithContext(ctx, "GET", url, nil)
		if reqErr != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		start := time.Now()
		resp, err = f.HTTPClient.Do(req)
		if err == nil {
			result.ResponseTime = time.Since(start)
			body, _ = io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB limit
			resp.Body.Close()
			break
		}
	}

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = resp.StatusCode
	result.ContentLength = resp.ContentLength

	// Extract headers
	for k, v := range resp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	// Server header
	result.Server = resp.Header.Get("Server")

	// Check for redirect
	if loc := resp.Header.Get("Location"); loc != "" {
		result.RedirectURL = loc
	}

	// Extract title
	result.Title = extractTitle(string(body))

	// Detect technologies
	bodyStr := string(body)
	detected := make(map[string]Technology)

	for _, sig := range f.Signatures {
		if tech := f.matchSignature(sig, resp.Header, bodyStr); tech != nil {
			if existing, ok := detected[tech.Name]; !ok || tech.Confidence > existing.Confidence {
				detected[tech.Name] = *tech
			}
		}
	}

	// Add header-based detections
	f.detectFromHeaders(resp.Header, detected)

	// Convert to slice and sort
	for _, tech := range detected {
		result.Technologies = append(result.Technologies, tech)
	}
	sort.Slice(result.Technologies, func(i, j int) bool {
		return result.Technologies[i].Name < result.Technologies[j].Name
	})

	return result
}

// FingerprintBatch checks multiple hosts for technologies
func (f *Fingerprinter) FingerprintBatch(ctx context.Context, hosts []string) []*Result {
	results := make([]*Result, len(hosts))

	sem := make(chan struct{}, f.Workers)
	var wg sync.WaitGroup

	for i, host := range hosts {
		wg.Add(1)
		go func(idx int, h string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				results[idx] = &Result{Host: h, Error: "cancelled"}
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			results[idx] = f.Fingerprint(ctx, h)
		}(i, host)
	}

	wg.Wait()
	return results
}

func (f *Fingerprinter) matchSignature(sig Signature, headers http.Header, body string) *Technology {
	confidence := 0

	// Check headers
	for header, pattern := range sig.Headers {
		if val := headers.Get(header); val != "" {
			if pattern.MatchString(val) {
				confidence += 30
			}
		}
	}

	// Check HTML patterns
	for _, pattern := range sig.HTML {
		if pattern.MatchString(body) {
			confidence += 40
		}
	}

	// Check script patterns
	for _, pattern := range sig.Scripts {
		if pattern.MatchString(body) {
			confidence += 30
		}
	}

	if confidence > 0 {
		return &Technology{
			Name:       sig.Name,
			Category:   sig.Category,
			Confidence: min(confidence, 100),
		}
	}

	return nil
}

func (f *Fingerprinter) detectFromHeaders(headers http.Header, detected map[string]Technology) {
	// Server header analysis
	server := strings.ToLower(headers.Get("Server"))
	if server != "" {
		serverTechs := map[string]string{
			"nginx":      "Nginx",
			"apache":     "Apache",
			"iis":        "Microsoft IIS",
			"cloudflare": "Cloudflare",
			"openresty":  "OpenResty",
			"litespeed":  "LiteSpeed",
			"caddy":      "Caddy",
			"gunicorn":   "Gunicorn",
			"uvicorn":    "Uvicorn",
			"werkzeug":   "Werkzeug",
			"express":    "Express.js",
			"kestrel":    "Kestrel",
		}
		for pattern, name := range serverTechs {
			if strings.Contains(server, pattern) {
				detected[name] = Technology{Name: name, Category: "Web Server", Confidence: 90}
			}
		}
	}

	// X-Powered-By
	poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	if poweredBy != "" {
		poweredByTechs := map[string]string{
			"php":         "PHP",
			"asp.net":     "ASP.NET",
			"express":     "Express.js",
			"next.js":     "Next.js",
			"nuxt":        "Nuxt.js",
			"django":      "Django",
			"flask":       "Flask",
			"rails":       "Ruby on Rails",
			"laravel":     "Laravel",
			"symfony":     "Symfony",
		}
		for pattern, name := range poweredByTechs {
			if strings.Contains(poweredBy, pattern) {
				detected[name] = Technology{Name: name, Category: "Framework", Confidence: 90}
			}
		}
	}

	// Security headers
	if headers.Get("Strict-Transport-Security") != "" {
		detected["HSTS"] = Technology{Name: "HSTS", Category: "Security", Confidence: 100}
	}
	if headers.Get("Content-Security-Policy") != "" {
		detected["CSP"] = Technology{Name: "CSP", Category: "Security", Confidence: 100}
	}
	if headers.Get("X-Frame-Options") != "" {
		detected["X-Frame-Options"] = Technology{Name: "X-Frame-Options", Category: "Security", Confidence: 100}
	}

	// CDN detection
	if headers.Get("CF-Ray") != "" {
		detected["Cloudflare"] = Technology{Name: "Cloudflare", Category: "CDN", Confidence: 100}
	}
	if headers.Get("X-Cache") != "" && strings.Contains(headers.Get("Via"), "cloudfront") {
		detected["CloudFront"] = Technology{Name: "CloudFront", Category: "CDN", Confidence: 100}
	}
	if headers.Get("X-Served-By") != "" && strings.Contains(headers.Get("X-Served-By"), "cache") {
		detected["Fastly"] = Technology{Name: "Fastly", Category: "CDN", Confidence: 80}
	}
	if headers.Get("X-Vercel-Id") != "" {
		detected["Vercel"] = Technology{Name: "Vercel", Category: "PaaS", Confidence: 100}
	}
	if headers.Get("X-Netlify") != "" || strings.Contains(server, "netlify") {
		detected["Netlify"] = Technology{Name: "Netlify", Category: "PaaS", Confidence: 100}
	}
}

func extractTitle(html string) string {
	// Simple title extraction
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}

	title := html[start : start+end]
	title = strings.TrimSpace(title)

	// Decode common HTML entities
	title = strings.ReplaceAll(title, "&amp;", "&")
	title = strings.ReplaceAll(title, "&lt;", "<")
	title = strings.ReplaceAll(title, "&gt;", ">")
	title = strings.ReplaceAll(title, "&quot;", "\"")
	title = strings.ReplaceAll(title, "&#39;", "'")

	// Truncate if too long
	if len(title) > 100 {
		title = title[:97] + "..."
	}

	return title
}

// DefaultSignatures returns built-in technology signatures
func DefaultSignatures() []Signature {
	return []Signature{
		{
			Name:     "WordPress",
			Category: "CMS",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress`)},
			Headers:  map[string]*regexp.Regexp{"X-Powered-By": regexp.MustCompile(`(?i)wordpress`)},
		},
		{
			Name:     "Drupal",
			Category: "CMS",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)drupal|sites/all/|sites/default/`)},
			Headers:  map[string]*regexp.Regexp{"X-Drupal-Cache": regexp.MustCompile(`.*`)},
		},
		{
			Name:     "Joomla",
			Category: "CMS",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)/media/jui/|/components/com_`)},
		},
		{
			Name:     "React",
			Category: "JavaScript Framework",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)react|_reactRootContainer|data-reactroot`)},
			Scripts:  []*regexp.Regexp{regexp.MustCompile(`(?i)react\.production\.min\.js|react-dom`)},
		},
		{
			Name:     "Vue.js",
			Category: "JavaScript Framework",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)v-app|vue-router|data-v-[a-f0-9]`)},
			Scripts:  []*regexp.Regexp{regexp.MustCompile(`(?i)vue\.runtime|vue\.min\.js|vuejs`)},
		},
		{
			Name:     "Angular",
			Category: "JavaScript Framework",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)ng-app|ng-controller|ng-model|\[ng-`)},
			Scripts:  []*regexp.Regexp{regexp.MustCompile(`(?i)angular\.min\.js|angular\.js`)},
		},
		{
			Name:     "jQuery",
			Category: "JavaScript Library",
			Scripts:  []*regexp.Regexp{regexp.MustCompile(`(?i)jquery[-.]?\d*\.?(min\.)?js`)},
		},
		{
			Name:     "Bootstrap",
			Category: "CSS Framework",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)bootstrap\.min\.(css|js)|class="[^"]*\b(container|row|col-|btn-|navbar)`)},
		},
		{
			Name:     "Tailwind CSS",
			Category: "CSS Framework",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)class="[^"]*\b(flex|grid|bg-|text-|p-|m-|w-|h-)\w+`)},
		},
		{
			Name:     "Google Analytics",
			Category: "Analytics",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)google-analytics\.com/|googletagmanager\.com|gtag\(|_gaq\.push`)},
		},
		{
			Name:     "Google Tag Manager",
			Category: "Tag Manager",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`)},
		},
		{
			Name:     "Shopify",
			Category: "E-commerce",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)cdn\.shopify\.com|shopify-section`)},
		},
		{
			Name:     "Magento",
			Category: "E-commerce",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)mage/|Magento_|/skin/frontend/`)},
		},
		{
			Name:     "WooCommerce",
			Category: "E-commerce",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)woocommerce|wc-|is-woocommerce`)},
		},
		{
			Name:     "Cloudflare",
			Category: "CDN",
			Headers:  map[string]*regexp.Regexp{"CF-Ray": regexp.MustCompile(`.*`)},
		},
		{
			Name:     "Varnish",
			Category: "Cache",
			Headers:  map[string]*regexp.Regexp{"X-Varnish": regexp.MustCompile(`.*`), "Via": regexp.MustCompile(`(?i)varnish`)},
		},
		{
			Name:     "reCAPTCHA",
			Category: "Security",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)google\.com/recaptcha|grecaptcha`)},
		},
		{
			Name:     "Stripe",
			Category: "Payment",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)js\.stripe\.com|stripe\.js`)},
		},
		{
			Name:     "Font Awesome",
			Category: "Font",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)fontawesome|fa-[a-z]+-?[a-z]*`)},
		},
		{
			Name:     "Sentry",
			Category: "Error Tracking",
			HTML:     []*regexp.Regexp{regexp.MustCompile(`(?i)sentry\.io|browser\.sentry-cdn`)},
		},
	}
}

// TechnologyJSON converts result to JSON-friendly format
func (r *Result) TechnologyJSON() string {
	if len(r.Technologies) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(r.Technologies)
	return string(b)
}

// TechnologyNames returns just the names as a slice
func (r *Result) TechnologyNames() []string {
	names := make([]string, len(r.Technologies))
	for i, t := range r.Technologies {
		names[i] = t.Name
	}
	return names
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
