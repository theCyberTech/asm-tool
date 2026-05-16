package target

import (
	"strings"
	"testing"
)

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "lowercase and trim", input: " Example.COM. ", want: "example.com"},
		{name: "punycode", input: "xn--example-9d0b.com", want: "xn--example-9d0b.com"},
		{name: "empty", input: " ", wantErr: true},
		{name: "url rejected", input: "https://example.com", wantErr: true},
		{name: "path rejected", input: "example.com/path", wantErr: true},
		{name: "query rejected", input: "example.com?x=1", wantErr: true},
		{name: "label too long", input: strings.Repeat("a", 64) + ".com", wantErr: true},
		{name: "bad label boundary", input: "-example.com", wantErr: true},
		{name: "double dot", input: "example..com", wantErr: true},
		{name: "space rejected", input: "bad example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeTarget(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeTarget(%q) succeeded, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeTarget(%q) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeTarget(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
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
			got := NormalizeSubdomain(tt.host, tt.domain)
			if got != tt.want {
				t.Fatalf("NormalizeSubdomain(%q, %q) = %q, want %q", tt.host, tt.domain, got, tt.want)
			}
		})
	}
}

func TestSafeFilenamePart(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "Example.COM", want: "example.com"},
		{input: "../../bad/example.com", want: "bad-example.com"},
		{input: "   ", want: "scan"},
	}

	for _, tt := range tests {
		if got := SafeFilenamePart(tt.input); got != tt.want {
			t.Fatalf("SafeFilenamePart(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
