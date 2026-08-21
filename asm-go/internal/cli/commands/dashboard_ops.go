package commands

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/dashboard"
	"github.com/asm-tool/asm-go/internal/target"
)

const (
	maxDashboardRuns        = 50
	maxDashboardOutputBytes = 256 * 1024
)

type dashboardOps struct {
	mu         sync.RWMutex
	runs       []dashboard.RunRecord
	nextID     int64
	rootDir    string
	goDir      string
	binaryPath string
	configPath string
	dbPath     string
	logPath    string
	actions    []dashboard.OperationOption
	defs       map[string]operationDefinition
	enabled    bool
	token      string
}

type operationDefinition struct {
	dashboard.OperationOption
	build func(operationRequest) (commandSpec, error)
}

type operationRequest struct {
	Action       string `json:"action"`
	Target       string `json:"target"`
	AllKnown     bool   `json:"all_known"`
	Ports        string `json:"ports"`
	OutputFormat string `json:"output_format"`
	Nuclei       bool   `json:"nuclei"`
	Verbose      bool   `json:"verbose"`
}

type commandSpec struct {
	Name string
	Args []string
	Dir  string
}

func newDashboardOps(deps *Deps) *dashboardOps {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	rootDir, goDir := detectToolDirs(cwd)

	binaryPath, err := os.Executable()
	if err != nil || binaryPath == "" {
		binaryPath = filepath.Join(goDir, "asm-go")
	}

	dbPath := ""
	if deps != nil && deps.Cfg != nil {
		dbPath = deps.Cfg.DatabasePath
	}
	if dbPath != "" && !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(cwd, dbPath)
	}

	configPath := filepath.Join(rootDir, "config.yaml")
	if !fileExists(configPath) {
		configPath = ""
	}

	ops := &dashboardOps{
		rootDir:    rootDir,
		goDir:      goDir,
		binaryPath: binaryPath,
		configPath: configPath,
		dbPath:     dbPath,
		logPath:    filepath.Join(rootDir, "logs", "dashboard-runs.jsonl"),
	}
	ops.defs = ops.operationDefinitions()
	ops.actions = ops.operationOptions()
	ops.loadHistory()
	return ops
}

func detectToolDirs(cwd string) (string, string) {
	if fileExists(filepath.Join(cwd, "asm-go", "go.mod")) {
		return cwd, filepath.Join(cwd, "asm-go")
	}
	if fileExists(filepath.Join(cwd, "go.mod")) && fileExists(filepath.Join(cwd, "cmd", "asm", "main.go")) {
		return filepath.Dir(cwd), cwd
	}
	return cwd, filepath.Join(cwd, "asm-go")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (o *dashboardOps) requireEnabled(w http.ResponseWriter, r *http.Request) bool {
	if o.enabled {
		return true
	}
	http.Error(w, "operations are disabled; start the dashboard with --enable-ops", http.StatusForbidden)
	return false
}

func (o *dashboardOps) authorize(w http.ResponseWriter, r *http.Request) bool {
	if o.token == "" {
		return true
	}
	if o.requestHasValidToken(r) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="ASM Operations"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func (o *dashboardOps) requestHasValidToken(r *http.Request) bool {
	if o.token == "" {
		return false
	}
	if tokenMatches(requestToken(r), o.token) {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if user != "asm" && user != "" {
		return false
	}
	return tokenMatches(pass, o.token)
}

func requestToken(r *http.Request) string {
	if h := strings.TrimSpace(r.Header.Get("X-ASM-Token")); h != "" {
		return h
	}
	const bearer = "bearer "
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); len(auth) > len(bearer) && strings.EqualFold(auth[:len(bearer)], bearer) {
		return strings.TrimSpace(auth[len(bearer):])
	}
	if t := strings.TrimSpace(r.URL.Query().Get("token")); t != "" {
		return t
	}
	return strings.TrimSpace(r.FormValue("ops_token"))
}

func tokenMatches(got, want string) bool {
	if want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func sameOriginRequest(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" || src == "null" {
		return false
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (o *dashboardOps) operationDefinitions() map[string]operationDefinition {
	cli := func(args ...string) commandSpec {
		base := make([]string, 0, len(args)+4)
		if o.configPath != "" {
			base = append(base, "--config", o.configPath)
		}
		if o.dbPath != "" {
			base = append(base, "--db", o.dbPath)
		}
		base = append(base, args...)
		return commandSpec{Name: o.binaryPath, Args: base, Dir: o.rootDir}
	}

	buildDomainCommand := func(command string, req operationRequest) (commandSpec, error) {
		args := []string{command}
		if req.AllKnown {
			args = append(args, "--all-known")
		} else {
			normalized, err := target.NormalizeTarget(req.Target)
			if err != nil {
				return commandSpec{}, err
			}
			args = append(args, normalized)
		}
		return cli(args...), nil
	}

	defs := []operationDefinition{
		{
			OperationOption: dashboard.OperationOption{ID: "status", Label: "Status"},
			build: func(req operationRequest) (commandSpec, error) {
				return cli("status"), nil
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "scan", Label: "Full scan", RequiresTarget: true, SupportsOutputFormat: true, SupportsNuclei: true},
			build: func(req operationRequest) (commandSpec, error) {
				normalized, err := target.NormalizeTarget(req.Target)
				if err != nil {
					return commandSpec{}, err
				}
				args := []string{"scan", normalized}
				if req.OutputFormat != "" {
					args = append(args, "--output", req.OutputFormat, "--output-dir", filepath.Join(o.rootDir, "reports"))
				}
				if req.Nuclei {
					args = append(args, "--nuclei")
				}
				if req.Verbose {
					args = append(args, "--verbose")
				}
				return cli(args...), nil
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "discover", Label: "Discover subdomains", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("discover", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "dns", Label: "DNS check", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("dns", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "urls", Label: "URL enumeration", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("urls", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "certificates", Label: "Certificate check", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("certificates", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "takeover", Label: "Takeover check", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("takeover", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "fingerprint", Label: "Fingerprint", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("fingerprint", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "apis", Label: "API discovery", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("apis", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "emails", Label: "Email enumeration", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("emails", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "cloudstorage", Label: "Cloud storage", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("cloudstorage", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "portscan", Label: "Port scan", RequiresTarget: true, SupportsAllKnown: true, SupportsPorts: true},
			build: func(req operationRequest) (commandSpec, error) {
				spec, err := buildDomainCommand("portscan", req)
				if err != nil {
					return commandSpec{}, err
				}
				if strings.TrimSpace(req.Ports) != "" {
					ports := strings.TrimSpace(req.Ports)
					if len(config.ParsePortString(ports)) == 0 {
						return commandSpec{}, fmt.Errorf("ports must be a comma-separated list or range")
					}
					spec.Args = append(spec.Args, "--ports", ports)
				}
				return spec, nil
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "nuclei", Label: "Nuclei scan", RequiresTarget: true, SupportsAllKnown: true},
			build: func(req operationRequest) (commandSpec, error) {
				return buildDomainCommand("nuclei", req)
			},
		},
		{
			OperationOption: dashboard.OperationOption{ID: "report", Label: "Generate report", RequiresTarget: true, SupportsOutputFormat: true},
			build: func(req operationRequest) (commandSpec, error) {
				normalized, err := target.NormalizeTarget(req.Target)
				if err != nil {
					return commandSpec{}, err
				}
				format := req.OutputFormat
				if format == "" {
					format = "html"
				}
				args := []string{"report", normalized, "--format", format, "--output", filepath.Join(o.rootDir, "reports")}
				return cli(args...), nil
			},
		},
	}

	out := make(map[string]operationDefinition, len(defs))
	for _, def := range defs {
		out[def.ID] = def
	}
	return out
}

func (o *dashboardOps) operationOptions() []dashboard.OperationOption {
	order := []string{
		"status", "scan", "discover", "dns", "urls",
		"certificates", "takeover", "fingerprint", "apis", "emails",
		"cloudstorage", "portscan", "nuclei", "report",
	}
	options := make([]dashboard.OperationOption, 0, len(order))
	for _, id := range order {
		if def, ok := o.defs[id]; ok {
			options = append(options, def.OperationOption)
		}
	}
	return options
}

func (o *dashboardOps) handleRunsPartial(w http.ResponseWriter, r *http.Request) {
	if !o.requireEnabled(w, r) || !o.authorize(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := dashboard.PageData{ActivePage: "operations", Operations: o.pageData()}
	if err := dashboard.RenderPartial(w, "runs-panel", data); err != nil {
		http.Error(w, "Failed to render runs: "+err.Error(), http.StatusInternalServerError)
	}
}

func (o *dashboardOps) handleOperationsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if o.enabled && !o.authorize(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, dashboard.OperationsJSON(o.pageData()))
}

func (o *dashboardOps) handleRunsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !o.requireEnabled(w, r) || !o.authorize(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"runs":   o.pageData().Runs,
	})
}

func (o *dashboardOps) handleStartRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !o.requireEnabled(w, r) {
		return
	}

	isJSON := strings.Contains(r.Header.Get("Content-Type"), "application/json")
	if !isJSON {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
	}
	if !o.authorize(w, r) {
		return
	}
	if !o.requestHasValidToken(r) && !sameOriginRequest(r) {
		http.Error(w, "csrf check failed", http.StatusForbidden)
		return
	}

	var req operationRequest
	if isJSON {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"status":  "error",
				"message": "invalid json",
			})
			return
		}
	} else {
		req = operationRequest{
			Action:       r.FormValue("action"),
			Target:       r.FormValue("target"),
			AllKnown:     r.FormValue("all_known") == "on",
			Ports:        r.FormValue("ports"),
			OutputFormat: r.FormValue("output_format"),
			Nuclei:       r.FormValue("nuclei") == "on",
			Verbose:      r.FormValue("verbose") == "on",
		}
	}

	run, err := o.start(req)
	if err != nil {
		if isJSON || wantsJSON(r) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if isJSON || wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok",
			"run":    run,
		})
		return
	}
	o.handleRunsPartial(w, r)
}

func (o *dashboardOps) pageData() *dashboard.OperationsData {
	o.mu.RLock()
	defer o.mu.RUnlock()

	runs := make([]dashboard.RunRecord, len(o.runs))
	copy(runs, o.runs)

	running := 0
	for _, run := range runs {
		if run.Status == "running" {
			running++
		}
	}

	return &dashboard.OperationsData{
		Enabled:      o.enabled,
		Actions:      o.actions,
		Runs:         runs,
		RunningCount: running,
		BinaryPath:   o.binaryPath,
		ConfigPath:   o.configPath,
		DatabasePath: o.dbPath,
		LogPath:      o.logPath,
	}
}

func (o *dashboardOps) start(req operationRequest) (dashboard.RunRecord, error) {
	def, ok := o.defs[req.Action]
	if !ok {
		return dashboard.RunRecord{}, fmt.Errorf("unsupported action %q", req.Action)
	}
	if err := validateOutputFormat(req.OutputFormat); err != nil {
		return dashboard.RunRecord{}, err
	}
	if req.AllKnown && !def.SupportsAllKnown {
		return dashboard.RunRecord{}, fmt.Errorf("%s does not support all-known mode", def.Label)
	}
	if def.RequiresTarget && !req.AllKnown && strings.TrimSpace(req.Target) == "" {
		return dashboard.RunRecord{}, fmt.Errorf("%s requires a target domain", def.Label)
	}

	spec, err := def.build(req)
	if err != nil {
		return dashboard.RunRecord{}, err
	}

	id := atomic.AddInt64(&o.nextID, 1)
	run := dashboard.RunRecord{
		ID:        id,
		Action:    def.ID,
		Label:     def.Label,
		Command:   displayCommand(spec),
		Target:    strings.TrimSpace(req.Target),
		Status:    "running",
		ExitCode:  -1,
		StartedAt: time.Now(),
	}

	o.mu.Lock()
	o.runs = append([]dashboard.RunRecord{run}, o.runs...)
	if len(o.runs) > maxDashboardRuns {
		o.runs = o.runs[:maxDashboardRuns]
	}
	o.mu.Unlock()

	go o.execute(id, spec)
	return run, nil
}

func validateOutputFormat(format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json", "markdown", "html":
		return nil
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func (o *dashboardOps) execute(id int64, spec commandSpec) {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, spec.Name, spec.Args...)
	cmd.Dir = spec.Dir

	var stdout, stderr limitedBuffer
	stdout.limit = maxDashboardOutputBytes
	stderr.limit = maxDashboardOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	finished := time.Now()
	exitCode := 0
	status := "succeeded"
	errorMessage := ""
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	var finishedRun dashboard.RunRecord
	o.updateRun(id, func(run *dashboard.RunRecord) {
		run.Status = status
		run.ExitCode = exitCode
		run.FinishedAt = &finished
		run.Duration = finished.Sub(run.StartedAt).Round(time.Millisecond).String()
		run.Stdout = stdout.String()
		run.Stderr = stderr.String()
		run.Error = errorMessage
		run.Truncated = stdout.truncated || stderr.truncated
		finishedRun = *run
	})
	o.appendHistory(finishedRun)
}

func (o *dashboardOps) updateRun(id int64, fn func(*dashboard.RunRecord)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.runs {
		if o.runs[i].ID == id {
			fn(&o.runs[i])
			return
		}
	}
}

func (o *dashboardOps) loadHistory() {
	data, err := os.ReadFile(o.logPath)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	runs := make([]dashboard.RunRecord, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var run dashboard.RunRecord
		if err := json.Unmarshal([]byte(line), &run); err == nil {
			runs = append(runs, run)
			if run.ID > o.nextID {
				o.nextID = run.ID
			}
		}
	}
	for i, j := 0, len(runs)-1; i < j; i, j = i+1, j-1 {
		runs[i], runs[j] = runs[j], runs[i]
	}
	if len(runs) > maxDashboardRuns {
		runs = runs[:maxDashboardRuns]
	}
	o.runs = runs
}

func (o *dashboardOps) appendHistory(run dashboard.RunRecord) {
	if err := os.MkdirAll(filepath.Dir(o.logPath), 0755); err != nil {
		return
	}
	f, err := os.OpenFile(o.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	encoded, err := json.Marshal(run)
	if err != nil {
		return
	}
	_, _ = f.Write(append(encoded, '\n'))
}

func displayCommand(spec commandSpec) string {
	parts := append([]string{spec.Name}, spec.Args...)
	for i, part := range parts {
		parts[i] = shellQuote(part)
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if strings.ContainsAny(value, " \t\n'\"\\$&;()<>|*?[]{}!") {
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return value
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		b.limit = maxDashboardOutputBytes
	}
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
