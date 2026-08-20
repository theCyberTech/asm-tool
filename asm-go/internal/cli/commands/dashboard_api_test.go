package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/dashboard"
	"github.com/asm-tool/asm-go/internal/database"
)

func testDashboardMux(t *testing.T) (*http.ServeMux, *database.Database) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Domains.Add("example.com"); err != nil {
		t.Fatalf("Add domain: %v", err)
	}
	if err := db.Ports.Add(&database.Port{
		Host: "api.example.com", Port: 443, Protocol: "tcp", State: "open", Service: "https",
	}); err != nil {
		t.Fatalf("Add port: %v", err)
	}

	ops := newTestDashboardOps(t, makeScript(t, "echo ok\nexit 0\n"))
	ops.defs = ops.operationDefinitions()
	ops.actions = ops.operationOptions()
	ops.enabled = true

	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "asm.db")
	return newDashboardMux(&Deps{DB: db, Cfg: cfg}, ops), db
}

func TestDashboardMuxServesTypeScriptSPA(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatalf("expected TypeScript SPA shell, body = %s", rec.Body.String())
	}
}

func TestOverviewJSONIncludesDomainsAndFindings(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Status string `json:"status"`
		Stats  struct {
			Domains int `json:"domains"`
		}
		Domains []struct {
			Domain string `json:"domain"`
		} `json:"domains"`
		Findings struct {
			Total int `json:"total"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding overview: %v", err)
	}
	if payload.Status != "ok" {
		t.Fatalf("status = %q", payload.Status)
	}
	if payload.Stats.Domains < 1 {
		t.Fatalf("domains count = %d", payload.Stats.Domains)
	}
	if len(payload.Domains) != 1 || payload.Domains[0].Domain != "example.com" {
		t.Fatalf("domains = %+v", payload.Domains)
	}
}

func TestDomainsJSONRejectsInvalidDate(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/domains?from=not-a-date", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDomainDetailJSONIncludesPorts(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Status string `json:"status"`
		Domain string `json:"domain"`
		Ports  []struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"ports"`
		Stats struct {
			PortCount int `json:"port_count"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding domain: %v", err)
	}
	if payload.Status != "ok" || payload.Domain != "example.com" {
		t.Fatalf("payload = %+v", payload)
	}
	if payload.Stats.PortCount < 1 {
		t.Fatalf("port_count = %d", payload.Stats.PortCount)
	}
	found := false
	for _, p := range payload.Ports {
		if p.Host == "api.example.com" && p.Port == 443 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing port in %+v", payload.Ports)
	}
}

func TestAssetsJSONListsPorts(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/assets/ports", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Status string `json:"status"`
		Kind   string `json:"kind"`
		Count  int    `json:"count"`
		Items  []struct {
			Host string `json:"host"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding assets: %v", err)
	}
	if payload.Kind != "ports" || payload.Count < 1 {
		t.Fatalf("payload = %+v", payload)
	}
	if payload.Items[0].Host != "api.example.com" {
		t.Fatalf("host = %q", payload.Items[0].Host)
	}
}

func TestDomainAssetJSONUnknownKind(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/assets/nope", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestStartRunJSONReturnsRun(t *testing.T) {
	mux, _ := testDashboardMux(t)
	body := strings.NewReader(`{"action":"status"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/runs/start", body)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Status string `json:"status"`
		Run    struct {
			Action string `json:"action"`
			Status string `json:"status"`
		} `json:"run"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding start run: %v body=%s", err, rec.Body.String())
	}
	if payload.Status != "ok" || payload.Run.Action != "status" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestParseDomainAPIPath(t *testing.T) {
	got, ok := parseDomainAPIPath("/api/domains/example.com")
	if !ok || got.domain != "example.com" || got.kind != "" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	got, ok = parseDomainAPIPath("/api/domains/example.com/assets/ports")
	if !ok || got.kind != "ports" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if _, ok := parseDomainAPIPath("/api/domains/example.com/assets/nope"); ok {
		t.Fatal("expected unknown kind to fail")
	}
}

func TestFilterDomainStatsByName(t *testing.T) {
	now := time.Now()
	domains := []dashboard.DomainStats{
		{Domain: "example.com", LastScanned: &now},
		{Domain: "other.org", LastScanned: &now},
	}
	filtered, err := filterDomainStats(domains, url.Values{"q": []string{"EXAMPLE"}})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Domain != "example.com" {
		t.Fatalf("filtered = %+v", filtered)
	}
}
