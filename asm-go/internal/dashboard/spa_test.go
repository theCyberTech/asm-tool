package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeSPAReturnsIndex(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ServeSPA(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatalf("SPA index missing root mount, body = %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "CrewAI - ASM loading") {
		t.Fatalf("SPA index missing visible fallback, body = %s", rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("ACA origin = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestServeSPAReturnsIndexForClientRoute(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/domains", nil)
	rec := httptest.NewRecorder()
	ServeSPA(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatal("client route did not serve SPA index")
	}
}

func TestServeSPAServesBuiltAssets(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ServeIndex(rec, req)
	body := rec.Body.String()
	assetPath, ok := jsAssetPath(body)
	if !ok {
		t.Fatalf("index missing hashed JS src: %s", body)
	}
	if strings.Contains(body, " crossorigin") {
		t.Fatalf("module script should not use crossorigin in preview browsers, body = %s", body)
	}

	assetReq := httptest.NewRequest(http.MethodGet, assetPath, nil)
	assetRec := httptest.NewRecorder()
	ServeSPA(assetRec, assetReq)
	if assetRec.Code != http.StatusOK {
		t.Fatalf("%s status = %d, body = %s", assetPath, assetRec.Code, assetRec.Body.String())
	}
	if !strings.Contains(assetRec.Header().Get("Content-Type"), "javascript") && assetRec.Body.Len() < 1000 {
		t.Fatalf("asset content-type = %q len=%d", assetRec.Header().Get("Content-Type"), assetRec.Body.Len())
	}
}

func TestServeSPAMissingAssetIsNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil)
	rec := httptest.NewRecorder()
	ServeSPA(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestServeSPAKeepsPreviousHashedBundle(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/assets/index-D9AbP2Oy.js", nil)
	rec := httptest.NewRecorder()
	ServeSPA(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("previous hashed bundle status = %d, want 200 so cached index.html can still boot", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "javascript") && rec.Body.Len() < 1000 {
		t.Fatalf("previous bundle content-type = %q len=%d", rec.Header().Get("Content-Type"), rec.Body.Len())
	}
}

func jsAssetPath(body string) (string, bool) {
	const prefix = `src="/assets/`
	start := strings.Index(body, prefix)
	if start < 0 {
		return "", false
	}
	start += len(`src="`)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		return "", false
	}
	path := body[start : start+end]
	if !strings.HasPrefix(path, "/assets/") || !strings.HasSuffix(path, ".js") {
		return "", false
	}
	return path, true
}
