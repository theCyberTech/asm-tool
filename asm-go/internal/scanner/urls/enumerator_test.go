package urls

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com/path", "https://example.com/path"},
		{"http://example.com", "http://example.com"},
		{"example.com/path", "https://example.com/path"},
		{"  https://example.com  ", "https://example.com"},
		{"https://example.com/path#fragment", "https://example.com/path"},
		{"", ""},
		{"not a url |||", ""},
	}

	for _, tt := range tests {
		got := normalizeURL(tt.input)
		if got != tt.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestURLBelongsToDomain(t *testing.T) {
	tests := []struct {
		url    string
		domain string
		want   bool
	}{
		{"https://example.com/path", "example.com", true},
		{"https://sub.example.com/path", "example.com", true},
		{"https://other.com/path", "example.com", false},
		{"https://notexample.com/path", "example.com", false},
		{"invalid url", "example.com", false},
	}

	for _, tt := range tests {
		got := urlBelongsToDomain(tt.url, tt.domain)
		if got != tt.want {
			t.Errorf("urlBelongsToDomain(%q, %q) = %v, want %v", tt.url, tt.domain, got, tt.want)
		}
	}
}

func TestCategorizeURL(t *testing.T) {
	tests := []struct {
		url          string
		wantCategory string
		wantInterest bool
	}{
		{"https://example.com/app.js", "js", true},
		{"https://example.com/api/v1/users", "api", true},
		{"https://example.com/config.yaml", "config", true},
		{"https://example.com/backup.bak", "backup", true},
		{"https://example.com/archive.zip", "archive", true},
		{"https://example.com/admin/panel", "admin", true},
		{"https://example.com/style.css", "static", false},
		{"https://example.com/image.png", "static", false},
		{"https://example.com/normal/page", "other", false},
		{"https://example.com/login", "admin", true},
		{"https://example.com/oauth/callback", "other", true}, // interesting pattern
	}

	for _, tt := range tests {
		u := categorizeURL(tt.url, "example.com", "test")
		if u.Category != tt.wantCategory {
			t.Errorf("categorizeURL(%q).Category = %q, want %q", tt.url, u.Category, tt.wantCategory)
		}
		if u.Interesting != tt.wantInterest {
			t.Errorf("categorizeURL(%q).Interesting = %v, want %v", tt.url, u.Interesting, tt.wantInterest)
		}
	}
}

func TestCategorizeURL_SensitiveParams(t *testing.T) {
	u := categorizeURL("https://example.com/page?api_key=secret123", "example.com", "test")
	if !u.Interesting {
		t.Error("URL with api_key param should be interesting")
	}
}

func TestProbeURLs_CancelledContextReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e := &Enumerator{}
	urls := []URL{{URL: "http://127.0.0.1:1/"}}

	done := make(chan struct{})
	var got []URL
	go func() {
		defer close(done)
		got = e.ProbeURLs(ctx, urls, 2)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ProbeURLs did not return promptly with a cancelled context")
	}
	if len(got) != 1 {
		t.Fatalf("len(result) = %d, want 1", len(got))
	}
}

func TestProbeURLs_CancelWaitsForInFlight(t *testing.T) {
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e := &Enumerator{}
	urlList := []URL{
		{URL: srv.URL + "/a"},
		{URL: srv.URL + "/b"},
		{URL: srv.URL + "/c"},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.ProbeURLs(ctx, urlList, 2)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not start")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ProbeURLs did not return after cancel; in-flight WaitGroup may have leaked")
	}
}

func TestExtractFromJS(t *testing.T) {
	js := `
		var apiBase = "/api/v1/users";
		fetch("https://example.com/api/data");
		var internal = '/internal/config';
	`
	urls := ExtractFromJS(js, "https://example.com")
	if len(urls) == 0 {
		t.Error("expected to extract URLs from JS, got none")
	}

	found := false
	for _, u := range urls {
		if u == "https://example.com/api/data" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find https://example.com/api/data in %v", urls)
	}
}
