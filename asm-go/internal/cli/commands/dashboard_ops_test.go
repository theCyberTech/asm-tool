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

	_, err := ops.start(operationRequest{Action: "discover", Target: "crewai.com/path"})
	if err == nil {
		t.Fatal("expected invalid target to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid target domain") {
		t.Fatalf("error = %q, want invalid target domain", err.Error())
	}
}

func TestDashboardOpsRejectsOutOfScopeTarget(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "exit 0\n"))
	ops.defs = ops.operationDefinitions()

	_, err := ops.start(operationRequest{Action: "scan", Target: "google.com"})
	if err == nil {
		t.Fatal("expected out-of-scope target to be rejected")
	}
	if !strings.Contains(err.Error(), "restricted to crewai.com") {
		t.Fatalf("error = %q, want restricted to crewai.com", err.Error())
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
	waitForRunIdle(t, ops)
}

func TestDomainsRouteServesSPA(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/domains", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/domains status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatalf("/domains should serve the TypeScript SPA, body = %s", rec.Body.String())
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

func TestListenDashboardAcceptsIPv4(t *testing.T) {
	ln, err := listenDashboard("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listenDashboard: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp4 %s: %v", ln.Addr(), err)
	}
	_ = conn.Close()
}

func TestPublicDashboardURLUsesLoopbackForWildcard(t *testing.T) {
	if got := publicDashboardURL("0.0.0.0:8080"); got != "http://127.0.0.1:8080" {
		t.Fatalf("got %q", got)
	}
	if got := publicDashboardURL("127.0.0.1:8080"); got != "http://127.0.0.1:8080" {
		t.Fatalf("got %q", got)
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

func TestDashboardOverviewServesSPA(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/ status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatalf("expected TypeScript SPA shell, body = %s", rec.Body.String())
	}
}

func TestDashboardOpsStartHandlerAvailableByDefault(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "echo ok\nexit 0\n"))
	ops.defs = ops.operationDefinitions()
	ops.actions = ops.operationOptions()

	req := httptest.NewRequest(http.MethodPost, "/api/runs/start", strings.NewReader("action=status"))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()

	ops.handleStartRun(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	waitForRunIdle(t, ops)
}

func TestDashboardOpsStartHandlerRejectsCrossOrigin(t *testing.T) {
	ops := newTestDashboardOps(t, makeScript(t, "exit 0\n"))
	ops.defs = ops.operationDefinitions()

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
	waitForRunIdle(t, ops)
}

func waitForRunIdle(t *testing.T, ops *dashboardOps) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data := ops.pageData()
		if len(data.Runs) > 0 {
			running := false
			for _, run := range data.Runs {
				if run.Status == "running" {
					running = true
					break
				}
			}
			if !running {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("dashboard run did not finish before test cleanup")
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

func TestResolveDashboardOptionsAllowsOffLoopbackWithoutToken(t *testing.T) {
	deps := &Deps{Cfg: config.Default()}
	cmd := DashboardCmd(deps)
	if err := cmd.ParseFlags([]string{"--host", "0.0.0.0"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	opts, err := resolveDashboardOptions(cmd, deps)
	if err != nil {
		t.Fatalf("resolveDashboardOptions: %v", err)
	}
	if opts.host != "0.0.0.0" {
		t.Fatalf("host = %q, want 0.0.0.0", opts.host)
	}
	if opts.token != "" {
		t.Fatalf("token = %q, want empty", opts.token)
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

func TestDomainDetailAPIRejectsInvalidPath(t *testing.T) {
	mux, _ := testDashboardMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/not-a-domain", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDomainDetailJSONListsHostRecords(t *testing.T) {
	mux, db := testDashboardMux(t)
	now := time.Now()
	if err := db.Certificates.Add(&database.Certificate{
		Host: "api.example.com", Port: 443, Subject: "api.example.com",
		Issuer: "test-ca", NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		DaysUntilExpiry: 1, SAN: "api.example.com",
	}); err != nil {
		t.Fatalf("Add cert: %v", err)
	}
	if _, err := db.Raw().Exec(`
		INSERT INTO technologies (host, status_code, title, server, technologies)
		VALUES ('api.example.com', 200, 'API', 'nginx', 'Go')
	`); err != nil {
		t.Fatalf("insert technology: %v", err)
	}
	if _, err := db.Raw().Exec(`
		INSERT INTO dns_records (domain, records)
		VALUES ('api.example.com', 'A 1.2.3.4')
	`); err != nil {
		t.Fatalf("insert dns: %v", err)
	}

	pageReq := httptest.NewRequest(http.MethodGet, "/domains/example.com", nil)
	pageRec := httptest.NewRecorder()
	mux.ServeHTTP(pageRec, pageReq)
	if pageRec.Code != http.StatusOK {
		t.Fatalf("page status = %d, body = %s", pageRec.Code, pageRec.Body.String())
	}
	if !strings.Contains(pageRec.Body.String(), `id="root"`) {
		t.Fatal("domain page should serve the TypeScript SPA")
	}

	for _, kind := range []string{"ports", "certificates", "technologies", "dns"} {
		req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/assets/"+kind, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s assets status = %d, body = %s", kind, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "api.example.com") {
			t.Fatalf("%s assets missing subdomain host, body = %s", kind, rec.Body.String())
		}
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

func TestFilterDomainStatsRejectsInvalidDate(t *testing.T) {
	_, err := filterDomainStats(nil, map[string][]string{"from": {"not-a-date"}})
	if err == nil || !strings.Contains(err.Error(), "invalid from date") {
		t.Fatalf("err = %v, want invalid from date", err)
	}
}
