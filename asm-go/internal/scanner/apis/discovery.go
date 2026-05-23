package apis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// API represents a discovered API endpoint
type API struct {
	URL                  string
	Type                 string // swagger, openapi, graphql, rest, documentation
	Version              string
	Title                string
	Description          string
	EndpointsCount       int
	Endpoints            []string
	IntrospectionEnabled bool
	SecuritySchemes      []string
}

// Result represents API discovery results for a host
type Result struct {
	Host     string
	APIs     []API
	Duration time.Duration
	Error    string
}

// BatchResult represents results for multiple hosts
type BatchResult struct {
	Results  []*Result
	Total    int
	Found    int
	Duration time.Duration
}

// Discovery finds API endpoints on web servers
type Discovery struct {
	HTTPClient *http.Client
	Timeout    time.Duration
	Workers    int
	Paths      []string
}

// DefaultDiscovery returns a discovery with built-in paths and TLS verification enabled.
func DefaultDiscovery() *Discovery {
	return NewDiscovery(false)
}

// NewDiscovery returns a discovery with configurable TLS verification.
func NewDiscovery(insecureSkipVerify bool) *Discovery {
	return &Discovery{
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
				MaxIdleConns:    100,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 2 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		Timeout: 10 * time.Second,
		Workers: 30,
		Paths:   DefaultAPIPaths(),
	}
}

// Discover finds APIs on a single host
func (d *Discovery) Discover(ctx context.Context, host string) *Result {
	start := time.Now()
	result := &Result{Host: host}

	// Try both schemes
	var baseURL string
	for _, scheme := range []string{"https", "http"} {
		testURL := fmt.Sprintf("%s://%s", scheme, host)
		if d.testConnection(ctx, testURL) {
			baseURL = testURL
			break
		}
	}

	if baseURL == "" {
		result.Error = "host not reachable"
		result.Duration = time.Since(start)
		return result
	}

	// Check common API paths with bounded concurrency.
	const pathConcurrency = 10
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(pathConcurrency)

	var mu sync.Mutex
	for _, path := range d.Paths {
		p := path
		g.Go(func() error {
			if gctx.Err() != nil {
				return nil
			}

			url := baseURL + p
			if api := d.checkPath(gctx, url, p); api != nil {
				mu.Lock()
				result.APIs = append(result.APIs, *api)
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()

	// Check for GraphQL
	if gql := d.checkGraphQL(ctx, baseURL); gql != nil {
		result.APIs = append(result.APIs, *gql)
	}

	result.Duration = time.Since(start)
	return result
}

// DiscoverBatch finds APIs on multiple hosts
func (d *Discovery) DiscoverBatch(ctx context.Context, hosts []string) *BatchResult {
	start := time.Now()
	batch := &BatchResult{
		Total:   len(hosts),
		Results: make([]*Result, len(hosts)),
	}

	sem := make(chan struct{}, d.Workers)
	var wg sync.WaitGroup

	for i, host := range hosts {
		wg.Add(1)
		go func(idx int, h string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				batch.Results[idx] = &Result{Host: h, Error: "cancelled"}
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			batch.Results[idx] = d.Discover(ctx, h)
		}(i, host)
	}

	wg.Wait()

	// Count found
	for _, r := range batch.Results {
		if len(r.APIs) > 0 {
			batch.Found++
		}
	}

	batch.Duration = time.Since(start)
	return batch
}

func (d *Discovery) testConnection(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "ASM-Tool/2.0")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

func (d *Discovery) checkPath(ctx context.Context, url, path string) *API {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "ASM-Tool/2.0")
	req.Header.Set("Accept", "application/json, */*")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB limit
	if err != nil {
		return nil
	}

	contentType := resp.Header.Get("Content-Type")

	// Check for OpenAPI/Swagger
	if isSwaggerPath(path) || strings.Contains(contentType, "json") {
		if api := parseOpenAPI(body, url); api != nil {
			return api
		}
	}

	// Check for API documentation pages
	if isDocPath(path) && strings.Contains(contentType, "html") {
		return &API{
			URL:   url,
			Type:  "documentation",
			Title: extractTitle(string(body)),
		}
	}

	return nil
}

func (d *Discovery) checkGraphQL(ctx context.Context, baseURL string) *API {
	graphqlPaths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

	for _, path := range graphqlPaths {
		url := baseURL + path

		// Test with introspection query
		introspectionQuery := `{"query":"query{__schema{types{name}}}"}`

		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "ASM-Tool/2.0")

		resp, err := d.HTTPClient.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err == nil {
				if data, ok := result["data"]; ok && data != nil {
					api := &API{
						URL:                  url,
						Type:                 "graphql",
						IntrospectionEnabled: true,
					}

					// Check if introspection returned schema
					if dataMap, ok := data.(map[string]interface{}); ok {
						if schema, ok := dataMap["__schema"]; ok && schema != nil {
							api.IntrospectionEnabled = true
						}
					}

					return api
				}
			}
		}

		// Check for GraphQL error response (still indicates GraphQL endpoint)
		if resp.StatusCode == 400 || resp.StatusCode == 200 {
			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err == nil {
				if _, hasErrors := result["errors"]; hasErrors {
					return &API{
						URL:                  url,
						Type:                 "graphql",
						IntrospectionEnabled: false,
					}
				}
			}
		}
	}

	return nil
}

func isSwaggerPath(path string) bool {
	swaggerPaths := []string{
		"swagger", "openapi", "api-docs", "api.json", "api.yaml",
		"swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
	}
	pathLower := strings.ToLower(path)
	for _, sp := range swaggerPaths {
		if strings.Contains(pathLower, sp) {
			return true
		}
	}
	return false
}

func isDocPath(path string) bool {
	docPaths := []string{
		"docs", "documentation", "api-reference", "reference", "developer",
	}
	pathLower := strings.ToLower(path)
	for _, dp := range docPaths {
		if strings.Contains(pathLower, dp) {
			return true
		}
	}
	return false
}

func parseOpenAPI(body []byte, url string) *API {
	var spec map[string]interface{}
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil
	}

	api := &API{URL: url}

	// Check for OpenAPI 3.x
	if openapi, ok := spec["openapi"].(string); ok {
		api.Type = "openapi"
		api.Version = openapi
	} else if swagger, ok := spec["swagger"].(string); ok {
		// Swagger 2.0
		api.Type = "swagger"
		api.Version = swagger
	} else {
		return nil
	}

	// Extract info
	if info, ok := spec["info"].(map[string]interface{}); ok {
		if title, ok := info["title"].(string); ok {
			api.Title = title
		}
		if desc, ok := info["description"].(string); ok {
			api.Description = truncate(desc, 200)
		}
		if version, ok := info["version"].(string); ok {
			if api.Version == "" {
				api.Version = version
			}
		}
	}

	// Count endpoints
	if paths, ok := spec["paths"].(map[string]interface{}); ok {
		api.EndpointsCount = len(paths)
		for path := range paths {
			api.Endpoints = append(api.Endpoints, path)
			if len(api.Endpoints) >= 20 {
				break
			}
		}
	}

	// Check security schemes
	if components, ok := spec["components"].(map[string]interface{}); ok {
		if secSchemes, ok := components["securitySchemes"].(map[string]interface{}); ok {
			for name := range secSchemes {
				api.SecuritySchemes = append(api.SecuritySchemes, name)
			}
		}
	}

	return api
}

func extractTitle(html string) string {
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
	return truncate(strings.TrimSpace(html[start:start+end]), 100)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// DefaultAPIPaths returns common API documentation paths
func DefaultAPIPaths() []string {
	return []string{
		// Swagger/OpenAPI
		"/swagger.json",
		"/swagger.yaml",
		"/swagger/",
		"/swagger/v1/swagger.json",
		"/swagger/v2/swagger.json",
		"/api/swagger.json",
		"/api/swagger.yaml",
		"/api-docs",
		"/api-docs/",
		"/api-docs.json",
		"/v1/api-docs",
		"/v2/api-docs",
		"/v3/api-docs",
		"/openapi.json",
		"/openapi.yaml",
		"/openapi/",
		"/api/openapi.json",
		"/api/openapi.yaml",
		"/docs/api",

		// Documentation
		"/docs",
		"/docs/",
		"/documentation",
		"/documentation/",
		"/api/docs",
		"/api/documentation",
		"/developer",
		"/developer/",
		"/developers",
		"/developers/",
		"/api-reference",

		// Common API paths
		"/api",
		"/api/",
		"/api/v1",
		"/api/v2",
		"/api/v3",
		"/rest",
		"/rest/",

		// Health/Status endpoints (indicate API presence)
		"/health",
		"/healthz",
		"/status",
		"/api/health",
		"/api/status",
		"/.well-known/openapi.json",
	}
}
