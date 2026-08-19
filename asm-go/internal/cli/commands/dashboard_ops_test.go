package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
)

func newTestDashboardOps(t *testing.T, script string) *dashboardOps {
	t.Helper()
	root := t.TempDir()
	goDir := filepath.Join(root, "asm-go")
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0755); err != nil {
		t.Fatalf("creating logs dir: %v", err)
	}
	return &dashboardOps{
		rootDir:    root,
		goDir:      goDir,
		binaryPath: script,
		configPath: filepath.Join(root, "config.yaml"),
		dbPath:     filepath.Join(root, "data", "asm.db"),
		logPath:    filepath.Join(root, "logs", "dashboard-runs.jsonl"),
	}
}

func makeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "asm-test")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatalf("writing script: %v", err)
	}
	return path
}

func TestDashboardOpsRejectsInvalidTarget(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "exit 0\n"))
	ops.defs = ops.operationDefinitions()

	_, err := ops.start(operationRequest{Action: "discover", Target: "example.com/path"})
	if err == nil {
		t.Fatal("expected invalid target to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid target domain") {
		t.Fatalf("error = %q, want invalid target domain", err.Error())
	}
}

func TestDashboardOpsRejectsUnsupportedAction(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "exit 0\n"))
	ops.defs = ops.operationDefinitions()

	_, err := ops.start(operationRequest{Action: "rm"})
	if err == nil {
		t.Fatal("expected unsupported action to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported action") {
		t.Fatalf("error = %q, want unsupported action", err.Error())
	}
}

func TestDashboardOpsStatusRunCapturesOutputAndHistory(t *testing.T) {
	script := makeScript(t, "echo stdout:$*\necho stderr-line >&2\nexit 0\n")
	ops := newTestDashboardOps(t, script)
	ops.defs = ops.operationDefinitions()
	ops.actions = ops.operationOptions()

	run, err := ops.start(operationRequest{Action: "status"})
	if err != nil {
		t.Fatalf("start status: %v", err)
	}

	var completed bool
	for i := 0; i < 250; i++ {
		time.Sleep(20 * time.Millisecond)
		data := ops.pageData()
		if len(data.Runs) == 1 && data.Runs[0].ID == run.ID && data.Runs[0].Status != "running" {
			completed = true
			run = data.Runs[0]
			break
		}
	}
	if !completed {
		t.Fatal("status run did not complete")
	}
	if run.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded; stderr=%q error=%q", run.Status, run.Stderr, run.Error)
	}
	if !strings.Contains(run.Stdout, "status") {
		t.Fatalf("stdout = %q, want command arguments", run.Stdout)
	}
	if !strings.Contains(run.Stderr, "stderr-line") {
		t.Fatalf("stderr = %q, want stderr-line", run.Stderr)
	}

	var history []byte
	for i := 0; i < 50; i++ {
		history, err = os.ReadFile(ops.logPath)
		if err == nil && strings.Contains(string(history), `"Status"`) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("reading run history: %v", err)
	}
	t.Fatalf("history = %q, want serialized status run", string(history))
}

func TestDashboardOpsStartHandlerReturnsRunsPartial(t *testing.T) {
	script := makeScript(t, "echo ok\nexit 0\n")
	ops := newTestDashboardOps(t, script)
	ops.defs = ops.operationDefinitions()
	ops.actions = ops.operationOptions()
	ops.enabled = true

	req := httptest.NewRequest(http.MethodPost, "/api/runs/start", strings.NewReader("action=status"))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()

	ops.handleStartRun(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Status") {
		t.Fatalf("response body does not include status run: %s", rec.Body.String())
	}
}

func TestDomainsRouteRendersDomainsPage(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	defer db.Close()

	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "asm.db")
	handler := makeDomainsHandler(&Deps{DB: db, Cfg: cfg})

	req := httptest.NewRequest(http.MethodGet, "/domains", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/domains status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<h1 class="page-title">Domains</h1>`) {
		t.Fatalf("/domains body does not contain domains page title")
	}
	if !strings.Contains(body, "All Domains") {
		t.Fatalf("/domains body does not contain domains table")
	}
	if strings.Contains(body, "Attack Surface Overview") {
		t.Fatalf("/domains rendered the overview page instead of the domains page")
	}
}

func TestFindAvailableAddrReturnsRequestedPortWhenFree(t *testing.T) {
	addr, err := findAvailableAddr("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("findAvailableAddr: %v", err)
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("addr = %q, want 127.0.0.1 prefix", addr)
	}
}

func TestFindAvailableAddrSkipsInUsePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()

	inUsePort := portFromAddr(t, ln.Addr().String())

	addr, err := findAvailableAddr("127.0.0.1", inUsePort)
	if err != nil {
		t.Fatalf("findAvailableAddr: %v", err)
	}
	if strings.HasSuffix(addr, fmt.Sprintf(":%d", inUsePort)) {
		t.Fatalf("addr = %q, should not reuse in-use port %d", addr, inUsePort)
	}
}

func portFromAddr(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting addr %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing port %q: %v", portStr, err)
	}
	return port
}

func TestDashboardOverviewStatCardsLinkToAssetPages(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	defer db.Close()

	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "asm.db")
	handler := makeIndexHandler(&Deps{DB: db, Cfg: cfg})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/ status = %d, body = %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	for _, href := range []string{
		`href="/domains"`,
		`href="/subdomains"`,
		`href="/ports"`,
		`href="/certificates"`,
		`href="/urls"`,
		`href="/apis"`,
		`href="/emails"`,
		`href="/cloud"`,
	} {
		if !strings.Contains(body, href) {
			t.Fatalf("dashboard overview missing stat-card link %s", href)
		}
	}
}

func TestDashboardOpsStartHandlerDisabledByDefault(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "exit 0\n"))
	ops.defs = ops.operationDefinitions()

	req := httptest.NewRequest(http.MethodPost, "/api/runs/start", strings.NewReader("action=status"))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()

	ops.handleStartRun(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardOpsStartHandlerRejectsCrossOrigin(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "exit 0\n"))
	ops.defs = ops.operationDefinitions()
	ops.enabled = true

	req := httptest.NewRequest(http.MethodPost, "/api/runs/start", strings.NewReader("action=status"))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	ops.handleStartRun(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardOpsStartHandlerRequiresToken(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "echo ok\nexit 0\n"))
	ops.defs = ops.operationDefinitions()
	ops.actions = ops.operationOptions()
	ops.enabled = true
	ops.token = "secret-token"

	unauth := httptest.NewRequest(http.MethodPost, "/api/runs/start", strings.NewReader("action=status"))
	unauth.Host = "127.0.0.1:8080"
	unauth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unauth.Header.Set("Origin", "http://127.0.0.1:8080")
	unauthRec := httptest.NewRecorder()
	ops.handleStartRun(unauthRec, unauth)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401, body = %s", unauthRec.Code, unauthRec.Body.String())
	}

	auth := httptest.NewRequest(http.MethodPost, "/api/runs/start", strings.NewReader("action=status"))
	auth.Host = "127.0.0.1:8080"
	auth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth.Header.Set("X-ASM-Token", "secret-token")
	authRec := httptest.NewRecorder()
	ops.handleStartRun(authRec, auth)
	if authRec.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, body = %s", authRec.Code, authRec.Body.String())
	}
}

func TestDashboardOpsRejectsMissingTarget(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "exit 0\n"))
	ops.defs = ops.operationDefinitions()

	_, err := ops.start(operationRequest{Action: "scan"})
	if err == nil {
		t.Fatal("expected missing target to be rejected")
	}
	if !strings.Contains(err.Error(), "requires a target") {
		t.Fatalf("error = %q, want requires a target", err.Error())
	}
}

func TestDashboardOpsOmitsBuildAndTestActions(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "exit 0\n"))
	ops.defs = ops.operationDefinitions()
	ops.actions = ops.operationOptions()

	for _, action := range []string{"build", "test"} {
		if _, ok := ops.defs[action]; ok {
			t.Fatalf("unexpected %s action in operations allowlist", action)
		}
	}
}

func TestResolveDashboardOptionsRequiresTokenOffLoopback(t *testing.T) {
	deps := &Deps{Cfg: config.Default()}
	cmd := DashboardCmd(deps)
	if err := cmd.ParseFlags([]string{"--host", "0.0.0.0", "--enable-ops"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	_, err := resolveDashboardOptions(cmd, deps)
	if err == nil {
		t.Fatal("expected token requirement when enabling ops on 0.0.0.0")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "::1", "[::1]"} {
		if !isLoopbackHost(host) {
			t.Fatalf("isLoopbackHost(%q) = false, want true", host)
		}
	}
	if isLoopbackHost("0.0.0.0") {
		t.Fatal("isLoopbackHost(0.0.0.0) = true, want false")
	}
}

func TestDomainDetailRejectsInvalidPath(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	defer db.Close()

	handler := makeDomainDetailHandler(&Deps{DB: db, Cfg: config.Default()})
	req := httptest.NewRequest(http.MethodGet, "/domains/example.com/not-a-domain", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestStatsHandlerJSONIncludesStatus(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	defer db.Close()

	handler := makeStatsHandler(&Deps{DB: db, Cfg: config.Default()})
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding stats JSON: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("status field = %v, want ok", payload["status"])
	}
	if _, ok := payload["findings"].(map[string]interface{}); !ok {
		t.Fatalf("findings = %T, want object", payload["findings"])
	}
}

func TestDomainsPartialRejectsInvalidDate(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	defer db.Close()

	handler := makeDomainsPartialHandler(&Deps{DB: db, Cfg: config.Default()})
	req := httptest.NewRequest(http.MethodGet, "/partials/domains?from=not-a-date", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDomainsPageHasFilterErrorHandling(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	defer db.Close()

	handler := makeDomainsHandler(&Deps{DB: db, Cfg: config.Default()})
	req := httptest.NewRequest(http.MethodGet, "/domains", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "htmx:responseError") {
		t.Fatal("/domains is missing HTMX error handling")
	}
	if !strings.Contains(body, "htmx:sendError") {
		t.Fatal("/domains is missing HTMX network error handling")
	}
}
