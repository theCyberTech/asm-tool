package nuclei

import (
	"os"
	"strings"
	"testing"
)

func TestSanitizeNucleiTarget(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{name: "valid host", input: "www.example.com", want: "www.example.com", wantOK: true},
		{name: "host normalized", input: " Example.COM. ", want: "example.com", wantOK: true},
		{name: "https url", input: "https://example.com/path", want: "https://example.com/path", wantOK: true},
		{name: "http url", input: "http://example.com", want: "http://example.com", wantOK: true},
		{name: "empty skipped", input: "  ", wantOK: false},
		{name: "newline rejected", input: "example.com\nhttps://evil.example", wantOK: false},
		{name: "cr rejected", input: "example.com\revil.example", wantOK: false},
		{name: "nul rejected", input: "example.com\x00evil.example", wantOK: false},
		{name: "invalid host rejected", input: "not a domain", wantOK: false},
		{name: "ftp scheme rejected", input: "ftp://example.com", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sanitizeNucleiTarget(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("sanitizeNucleiTarget(%q) ok=%v, want %v", tt.input, ok, tt.wantOK)
			}
			if tt.wantOK && got != tt.want {
				t.Fatalf("sanitizeNucleiTarget(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestWriteTargetFileSanitization(t *testing.T) {
	t.Run("valid host accepted", func(t *testing.T) {
		path, err := writeTargetFile([]string{"www.example.com"})
		if err != nil {
			t.Fatalf("writeTargetFile returned error: %v", err)
		}
		defer os.Remove(path)

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		got := strings.TrimSpace(string(data))
		if got != "www.example.com" {
			t.Fatalf("file contents = %q, want www.example.com", got)
		}
	})

	t.Run("newline rejected valid remains", func(t *testing.T) {
		path, err := writeTargetFile([]string{
			"example.com\nhttps://attacker.example",
			"www.example.com",
		})
		if err != nil {
			t.Fatalf("writeTargetFile returned error: %v", err)
		}
		defer os.Remove(path)

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		got := strings.TrimSpace(string(data))
		if got != "www.example.com" {
			t.Fatalf("file contents = %q, want only www.example.com", got)
		}
		if strings.Contains(string(data), "attacker.example") {
			t.Fatal("injected target was written")
		}
	})

	t.Run("all rejected returns error", func(t *testing.T) {
		path, err := writeTargetFile([]string{"", "bad\nhost", "not a domain"})
		if err == nil {
			os.Remove(path)
			t.Fatal("expected error when all targets are rejected")
		}
		if path != "" {
			t.Fatalf("path should be empty on error, got %q", path)
		}
	})
}

func TestBuildArgsSkipsUnsafeHeaders(t *testing.T) {
	s := DefaultScanner()
	s.Headers = map[string]string{
		"X-Ok":     "safe",
		"X-Bad":    "a\r\nX-Injected: 1",
		"Bad\nKey": "x",
	}
	args := s.buildArgs("/tmp/targets")

	var headers []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-H" && i+1 < len(args) {
			headers = append(headers, args[i+1])
			i++
		}
	}

	foundOK := false
	for _, h := range headers {
		if strings.Contains(h, "\r") || strings.Contains(h, "\n") {
			t.Fatalf("unsafe header written to args: %q", h)
		}
		if h == "X-Ok: safe" {
			foundOK = true
		}
		if strings.Contains(h, "X-Injected") {
			t.Fatalf("injected header present: %q", h)
		}
	}
	if !foundOK {
		t.Fatalf("safe header missing, got %v", headers)
	}
}
