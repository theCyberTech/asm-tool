package target

import (
	"fmt"
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

func TestNormalizeScanTargetRestrictsToCrewAI(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "apex allowed", input: " CrewAI.COM. ", want: "crewai.com"},
		{name: "subdomain allowed", input: "app.crewai.com", want: "app.crewai.com"},
		{name: "nested subdomain allowed", input: "api.staging.crewai.com", want: "api.staging.crewai.com"},
		{name: "suffix without boundary rejected", input: "notcrewai.com", wantErr: "restricted to crewai.com"},
		{name: "other domain rejected", input: "google.com", wantErr: "restricted to crewai.com"},
		{name: "lookalike subdomain rejected", input: "crewai.com.attacker.com", wantErr: "restricted to crewai.com"},
		{name: "invalid still rejected", input: "https://crewai.com", wantErr: "invalid target domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeScanTarget(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("NormalizeScanTarget(%q) succeeded, want error", tt.input)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NormalizeScanTarget(%q) error = %q, want %q", tt.input, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeScanTarget(%q) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeScanTarget(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if !IsAllowedScanTarget(tt.input) {
				t.Fatalf("IsAllowedScanTarget(%q) = false, want true", tt.input)
			}
		})
	}
}

func TestFilterAllowedScanTargets(t *testing.T) {
	got := FilterAllowedScanTargets([]string{
		"google.com",
		" CrewAI.com. ",
		"app.crewai.com",
		"crewai.com",
		"https://crewai.com",
		"api.crewai.com",
	})
	want := []string{"crewai.com", "app.crewai.com", "api.crewai.com"}
	if len(got) != len(want) {
		t.Fatalf("FilterAllowedScanTargets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("FilterAllowedScanTargets[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCapScanHostsKeepsApexAndLimit(t *testing.T) {
	hosts := []string{"crewai.com"}
	for i := 0; i < 40; i++ {
		hosts = append(hosts, fmt.Sprintf("h%d.crewai.com", i))
	}
	got := CapScanHosts("crewai.com", hosts)
	if len(got) != HostScanLimit {
		t.Fatalf("len = %d, want %d", len(got), HostScanLimit)
	}
	if got[0] != "crewai.com" {
		t.Fatalf("first host = %q, want crewai.com", got[0])
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
