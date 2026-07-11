package subdomains

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type captureTransport struct {
	req  *http.Request
	body string
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.req = req
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Request:    req,
	}, nil
}

func TestNormalizeSubdomainRequiresLabelBoundary(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		domain string
		want   string
	}{
		{name: "wildcard and case normalized", host: "*.WWW.Example.COM.", domain: "example.com", want: "www.example.com"},
		{name: "apex allowed", host: "example.com", domain: "example.com", want: "example.com"},
		{name: "subdomain allowed", host: "api.example.com", domain: "example.com", want: "api.example.com"},
		{name: "suffix without boundary rejected", host: "badexample.com", domain: "example.com", want: ""},
		{name: "outside domain rejected", host: "example.com.attacker.com", domain: "example.com", want: ""},
		{name: "invalid host rejected", host: "bad_example.com", domain: "example.com", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSubdomain(tt.host, tt.domain)
			if got != tt.want {
				t.Fatalf("normalizeSubdomain(%q, %q) = %q, want %q", tt.host, tt.domain, got, tt.want)
			}
		})
	}
}

func TestPassiveSourceRequestsEscapeQueryValues(t *testing.T) {
	tests := []struct {
		name         string
		source       func(*http.Client) Source
		body         string
		wantRawQuery string
	}{
		{
			name: "certspotter domain parameter",
			source: func(client *http.Client) Source {
				return &CertSpotterSource{client: client}
			},
			body:         `[]`,
			wantRawQuery: "domain=example.com&include_subdomains=true&expand=dns_names",
		},
		{
			name: "urlscan colon escaped",
			source: func(client *http.Client) Source {
				return &URLScanSource{client: client}
			},
			body:         `{"results":[]}`,
			wantRawQuery: "q=domain%3Aexample.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &captureTransport{body: tt.body}
			client := &http.Client{Transport: transport}
			if _, err := tt.source(client).Enumerate(context.Background(), "example.com"); err != nil {
				t.Fatalf("Enumerate returned error: %v", err)
			}
			if transport.req == nil {
				t.Fatal("source did not issue a request")
			}
			if got := transport.req.URL.RawQuery; got != tt.wantRawQuery {
				t.Fatalf("RawQuery = %q, want %q", got, tt.wantRawQuery)
			}
		})
	}
}
