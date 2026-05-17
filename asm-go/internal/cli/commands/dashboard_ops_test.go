package commands

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	req := httptest.NewRequest(http.MethodPost, "/api/runs/start", strings.NewReader("action=status"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
