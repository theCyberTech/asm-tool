package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Finding represents a vulnerability finding from Nuclei
type Finding struct {
	Template         string                 `json:"template"`
	TemplateID       string                 `json:"template-id"`
	TemplatePath     string                 `json:"template-path"`
	Info             TemplateInfo           `json:"info"`
	Type             string                 `json:"type"`
	Host             string                 `json:"host"`
	Matched          string                 `json:"matched-at"`
	ExtractedResults []string               `json:"extracted-results,omitempty"`
	IP               string                 `json:"ip,omitempty"`
	Timestamp        time.Time              `json:"timestamp"`
	CURLCommand      string                 `json:"curl-command,omitempty"`
	MatcherName      string                 `json:"matcher-name,omitempty"`
	MatcherStatus    bool                   `json:"matcher-status,omitempty"`
	Request          string                 `json:"request,omitempty"`
	Response         string                 `json:"response,omitempty"`
	Metadata         map[string]interface{} `json:"meta,omitempty"`
}

// TemplateInfo contains template metadata
type TemplateInfo struct {
	Name           string                 `json:"name"`
	Author         string                 `json:"author"`
	Tags           string                 `json:"tags"`
	Description    string                 `json:"description"`
	Reference      []string               `json:"reference,omitempty"`
	Severity       string                 `json:"severity"`
	Classification Classification         `json:"classification,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Classification contains CVE and CWE information
type Classification struct {
	CVEID       string  `json:"cve-id,omitempty"`
	CWEID       string  `json:"cwe-id,omitempty"`
	CVSSMetrics string  `json:"cvss-metrics,omitempty"`
	CVSSScore   float64 `json:"cvss-score,omitempty"`
}

// Result represents the scan result
type Result struct {
	Targets  []string
	Findings []*Finding
	Stats    ScanStats
	Duration time.Duration
	Errors   []string
}

// ScanStats contains scan statistics
type ScanStats struct {
	TargetsScanned   int
	TemplatesLoaded  int
	FindingsTotal    int
	FindingsCritical int
	FindingsHigh     int
	FindingsMedium   int
	FindingsLow      int
	FindingsInfo     int
}

// Scanner wraps nuclei for vulnerability scanning
type Scanner struct {
	BinaryPath       string
	TemplatesPath    string
	Timeout          time.Duration
	RateLimit        int
	BulkSize         int
	Concurrency      int
	Retries          int
	Severities       []string // critical, high, medium, low, info
	Tags             []string // specific tags to include
	ExcludeTags      []string // tags to exclude
	Templates        []string // specific template IDs
	ExcludeTemplates []string
	Headers          map[string]string
	OutputDir        string
	Silent           bool
}

// DefaultScanner creates a scanner with sensible defaults
func DefaultScanner() *Scanner {
	return &Scanner{
		BinaryPath:  findNucleiBinary(),
		Timeout:     30 * time.Minute,
		RateLimit:   150,
		BulkSize:    25,
		Concurrency: 25,
		Retries:     1,
		Severities:  []string{"critical", "high", "medium"},
		Headers:     make(map[string]string),
	}
}

// findNucleiBinary searches for nuclei in PATH and common Go binary locations
func findNucleiBinary() string {
	// First check PATH
	if path, err := exec.LookPath("nuclei"); err == nil {
		return path
	}

	// Check common Go binary locations
	homeDir, _ := os.UserHomeDir()
	commonPaths := []string{
		filepath.Join(homeDir, "go", "bin", "nuclei"),
		filepath.Join(homeDir, ".local", "bin", "nuclei"),
		"/usr/local/bin/nuclei",
		"/opt/homebrew/bin/nuclei",
	}

	// Also check GOPATH/bin if set
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		commonPaths = append([]string{filepath.Join(gopath, "bin", "nuclei")}, commonPaths...)
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Fallback to just "nuclei" and let it fail with a clear error
	return "nuclei"
}

// NewScanner creates a scanner with custom settings
func NewScanner(severities []string, rateLimit int) *Scanner {
	s := DefaultScanner()
	if len(severities) > 0 {
		s.Severities = severities
	}
	if rateLimit > 0 {
		s.RateLimit = rateLimit
	}
	return s
}

// validateBinaryPath checks that BinaryPath is safe to execute.
//
// Rules:
//   - Bare names (no '/') must resolve via PATH.
//   - Path-like values must be absolute and canonical — relative paths and
//     paths containing ".." components are rejected to prevent a compromised
//     config file from redirecting execution to an unintended binary.
//   - The resolved file must exist and be executable.
func validateBinaryPath(path string) error {
	if !strings.ContainsRune(path, '/') {
		// Bare name — let the OS resolve it via PATH.
		if _, err := exec.LookPath(path); err != nil {
			return fmt.Errorf("nuclei binary %q not found in PATH: %w", path, err)
		}
		return nil
	}

	// Path-like: must be absolute.
	if !filepath.IsAbs(path) {
		return fmt.Errorf("nuclei binary path must be absolute, got relative path: %q", path)
	}

	// Must be canonical — filepath.Clean resolves ".." and "." components.
	// If the cleaned form differs from the input, the path is non-canonical.
	if cleaned := filepath.Clean(path); cleaned != path {
		return fmt.Errorf("nuclei binary path contains non-canonical components: %q (resolves to %q)", path, cleaned)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("nuclei binary not accessible at %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("nuclei binary path %q is a directory", path)
	}
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("nuclei binary %q is not executable", path)
	}
	return nil
}

// IsInstalled checks if nuclei is available
func (s *Scanner) IsInstalled() bool {
	return validateBinaryPath(s.BinaryPath) == nil
}

// GetVersion returns the nuclei version
func (s *Scanner) GetVersion() (string, error) {
	if err := validateBinaryPath(s.BinaryPath); err != nil {
		return "", err
	}
	cmd := exec.Command(s.BinaryPath, "-version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// UpdateTemplates updates nuclei templates
func (s *Scanner) UpdateTemplates(ctx context.Context) error {
	if err := validateBinaryPath(s.BinaryPath); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, s.BinaryPath, "-update-templates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Scan runs nuclei against targets
func (s *Scanner) Scan(ctx context.Context, targets []string) (*Result, error) {
	if err := validateBinaryPath(s.BinaryPath); err != nil {
		return nil, fmt.Errorf("nuclei binary validation failed: %w", err)
	}
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	start := time.Now()
	result := &Result{
		Targets: targets,
	}

	// Create temp file for targets
	targetPath, err := writeTargetFile(targets)
	if err != nil {
		return nil, err
	}
	defer os.Remove(targetPath)

	// Build command arguments
	args := s.buildArgs(targetPath)

	// Create command
	cmd := exec.CommandContext(ctx, s.BinaryPath, args...)

	// Capture stdout for JSON output; forward stderr so nuclei's own
	// diagnostics (templates loaded, progress, resolution errors) surface.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	// Start command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting nuclei: %w", err)
	}

	// Parse JSON output line by line
	var mu sync.Mutex
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for large outputs

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var finding Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			// Not JSON, might be status message
			continue
		}

		mu.Lock()
		result.Findings = append(result.Findings, &finding)
		mu.Unlock()
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		// Nuclei returns non-zero exit codes for various reasons (no templates matched,
		// rate limiting, etc.). Always record the error so callers know the scan may be incomplete.
		result.Errors = append(result.Errors, fmt.Sprintf("nuclei exited with error: %s", err.Error()))
	}

	// Calculate stats
	result.Duration = time.Since(start)
	result.Stats = s.calculateStats(result)

	return result, nil
}

// ScanWithCallback runs nuclei and calls callback for each finding
func (s *Scanner) ScanWithCallback(ctx context.Context, targets []string, callback func(*Finding)) (*Result, error) {
	if err := validateBinaryPath(s.BinaryPath); err != nil {
		return nil, fmt.Errorf("nuclei binary validation failed: %w", err)
	}
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	start := time.Now()
	result := &Result{
		Targets: targets,
	}

	// Create temp file for targets
	targetPath, err := writeTargetFile(targets)
	if err != nil {
		return nil, err
	}
	defer os.Remove(targetPath)

	args := s.buildArgs(targetPath)
	cmd := exec.CommandContext(ctx, s.BinaryPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting nuclei: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var finding Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}

		result.Findings = append(result.Findings, &finding)
		if callback != nil {
			callback(&finding)
		}
	}

	if err := cmd.Wait(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("nuclei exited with error: %s", err.Error()))
	}
	result.Duration = time.Since(start)
	result.Stats = s.calculateStats(result)

	return result, nil
}

// writeTargetFile writes targets to a temp file and returns its path.
// The caller is responsible for removing the file via defer os.Remove(path).
func writeTargetFile(targets []string) (string, error) {
	f, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return "", fmt.Errorf("creating target file: %w", err)
	}

	for _, t := range targets {
		if _, err := f.WriteString(t + "\n"); err != nil {
			f.Close()
			os.Remove(f.Name())
			return "", fmt.Errorf("writing target %q to temp file: %w", t, err)
		}
	}

	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("closing target file: %w", err)
	}

	return f.Name(), nil
}

func (s *Scanner) buildArgs(targetFile string) []string {
	args := []string{
		"-l", targetFile,
		"-jsonl",
		"-silent",
		"-stats",
		"-rate-limit", fmt.Sprintf("%d", s.RateLimit),
		"-bulk-size", fmt.Sprintf("%d", s.BulkSize),
		"-concurrency", fmt.Sprintf("%d", s.Concurrency),
		"-retries", fmt.Sprintf("%d", s.Retries),
	}

	// Add severities
	if len(s.Severities) > 0 {
		args = append(args, "-severity", strings.Join(s.Severities, ","))
	}

	// Add tags
	if len(s.Tags) > 0 {
		args = append(args, "-tags", strings.Join(s.Tags, ","))
	}

	// Add excluded tags
	if len(s.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(s.ExcludeTags, ","))
	}

	// Add specific templates
	if len(s.Templates) > 0 {
		for _, t := range s.Templates {
			args = append(args, "-t", t)
		}
	}

	// Add excluded templates
	if len(s.ExcludeTemplates) > 0 {
		for _, t := range s.ExcludeTemplates {
			args = append(args, "-exclude", t)
		}
	}

	// Add custom templates path
	if s.TemplatesPath != "" {
		args = append(args, "-t", s.TemplatesPath)
	}

	// Add custom headers
	for k, v := range s.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}

	// Add output directory for detailed results
	if s.OutputDir != "" {
		_ = os.MkdirAll(s.OutputDir, 0755)
		args = append(args, "-output", filepath.Join(s.OutputDir, "nuclei-output.txt"))
	}

	return args
}

func (s *Scanner) calculateStats(result *Result) ScanStats {
	stats := ScanStats{
		TargetsScanned: len(result.Targets),
		FindingsTotal:  len(result.Findings),
	}

	for _, f := range result.Findings {
		switch strings.ToLower(f.Info.Severity) {
		case "critical":
			stats.FindingsCritical++
		case "high":
			stats.FindingsHigh++
		case "medium":
			stats.FindingsMedium++
		case "low":
			stats.FindingsLow++
		case "info":
			stats.FindingsInfo++
		}
	}

	return stats
}

// GetFindingsBySeverity returns findings filtered by severity
func (r *Result) GetFindingsBySeverity(severity string) []*Finding {
	var findings []*Finding
	for _, f := range r.Findings {
		if strings.EqualFold(f.Info.Severity, severity) {
			findings = append(findings, f)
		}
	}
	return findings
}

// GetFindingsByTemplate returns findings for a specific template
func (r *Result) GetFindingsByTemplate(templateID string) []*Finding {
	var findings []*Finding
	for _, f := range r.Findings {
		if f.TemplateID == templateID {
			findings = append(findings, f)
		}
	}
	return findings
}

// GetUniqueVulnerabilities returns deduplicated findings by template and host
func (r *Result) GetUniqueVulnerabilities() []*Finding {
	seen := make(map[string]bool)
	var unique []*Finding

	for _, f := range r.Findings {
		key := f.TemplateID + "|" + f.Host
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
}

// Config holds configuration for a Nuclei scan.
type Config struct {
	BinaryPath     string
	Severities     []string
	RateLimit      int
	BulkSize       int
	Concurrency    int
	Retries        int
	Timeout        time.Duration
	ExcludeTags    []string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BinaryPath:  "nuclei",
		Severities:  []string{"critical", "high", "medium"},
		RateLimit:   150,
		BulkSize:    25,
		Concurrency: 25,
		Retries:     1,
		Timeout:     30 * time.Minute,
	}
}

// ScanResult holds the result of a Nuclei scan.
type ScanResult struct {
	Findings []*Finding
	Errors   []string
	Err      error
}

// Scan runs Nuclei against hosts (converted to URLs) and returns findings.
func Scan(ctx context.Context, cfg Config, hosts []string) ([]*Finding, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	// Apply defaults.
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = DefaultConfig().RateLimit
	}

	// Convert hosts to URLs.
	targets := make([]string, 0, len(hosts)*2)
	for _, h := range hosts {
		targets = append(targets, "https://"+h, "http://"+h)
	}

	scanner := &Scanner{
		BinaryPath:  cfg.BinaryPath,
		Timeout:     cfg.Timeout,
		RateLimit:   cfg.RateLimit,
		BulkSize:    cfg.BulkSize,
		Concurrency: cfg.Concurrency,
		Retries:     cfg.Retries,
		Severities:  cfg.Severities,
		ExcludeTags: cfg.ExcludeTags,
		Silent:      true,
	}

	result, err := scanner.Scan(ctx, targets)
	if err != nil {
		return result.Findings, err
	}
	return result.Findings, nil
}
