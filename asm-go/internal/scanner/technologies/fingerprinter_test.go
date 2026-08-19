package technologies

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestScanDetectsWordPress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Write([]byte(`<html><body><link href="/wp-content/themes/x.css"></body></html>`))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	results := Scan(context.Background(), Config{Workers: 1, Timeout: 2 * time.Second}, []string{host})
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Error != "" {
		t.Fatalf("Scan error = %q", results[0].Error)
	}
	found := false
	for _, tech := range results[0].Technologies {
		if tech.Name == "WordPress" {
			found = true
		}
	}
	if !found {
		t.Fatalf("technologies = %+v, want WordPress", results[0].Technologies)
	}
}

func TestFingerprintBatchZeroWorkersDoesNotDeadlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	fp := NewFingerprinter(false)
	fp.HTTPClient = srv.Client()
	fp.Workers = 0
	fp.Timeout = time.Second

	done := make(chan struct{})
	go func() {
		_ = fp.FingerprintBatch(context.Background(), []string{u.Host})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("FingerprintBatch deadlocked with zero workers")
	}
}
