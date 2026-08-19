package apis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestScanFindsOpenAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"Demo"},"paths":{"/pets":{}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	result := Scan(context.Background(), Config{Workers: 1, Timeout: 2 * time.Second}, []string{host})
	if len(result.APIs) == 0 {
		t.Fatalf("expected OpenAPI finding, got %+v", result)
	}
	found := false
	for _, api := range result.APIs {
		if api.Type == "openapi" && api.Title == "Demo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("APIs = %+v, want openapi Demo", result.APIs)
	}
}

func TestCheckPathIgnoresSoft404Docs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><title>Spa</title><body>hello</body></html>`))
	}))
	defer srv.Close()

	d := NewDiscovery(false)
	d.HTTPClient = srv.Client()
	d.Timeout = 2 * time.Second
	api := d.checkPath(context.Background(), srv.URL+"/docs", "/docs")
	if api != nil {
		t.Fatalf("soft 404 docs classified as API: %+v", api)
	}
}

func TestGraphQLIntrospectionRequiresSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/graphql":
			w.Write([]byte(`{"data":{"ok":true}}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	d := NewDiscovery(false)
	d.HTTPClient = srv.Client()
	d.Timeout = 2 * time.Second
	api := d.checkGraphQL(context.Background(), srv.URL)
	if api == nil {
		t.Fatal("expected GraphQL endpoint")
	}
	if api.IntrospectionEnabled {
		t.Fatal("introspection should be disabled without __schema")
	}
}

func TestDiscoverBatchZeroWorkersDoesNotDeadlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	d := NewDiscovery(false)
	d.HTTPClient = srv.Client()
	d.Workers = 0
	d.Paths = []string{"/swagger.json"}

	done := make(chan struct{})
	go func() {
		_ = d.DiscoverBatch(context.Background(), []string{u.Host})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DiscoverBatch deadlocked with zero workers")
	}
}
