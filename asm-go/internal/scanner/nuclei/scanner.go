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
	Template      string            `json:"template"`
	TemplateID    string            `json:"template-id"`
	TemplatePath  string            `json:"template-path"`
	Info          TemplateInfo      `json:"info"`
	Type          string            `json:"type"`
	Host          string            `json:"host"`
	Matched       string            `json:"matched-at"`
	ExtractedResults []string       `json:"extracted-results,omitempty"`
	IP            string            `json:"ip,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
	CURLCommand   string            `json:"curl-command,omitempty"`
	MatcherName   string            `json:"matcher-name,omitempty"`
	MatcherStatus bool              `json:"matcher-status,omitempty"`
	Request       string            `json:"request,omitempty"`
	Response      string            `json:"response,omitempty"`
	Metadata      map[string]interface{} `json:"meta,omitempty"`
}

// TemplateInfo contains template metadata
type TemplateInfo struct {
	Name           string            `json:"name"`
	Author         string            `json:"author"`
	Tags           string            `json:"tags"`
	Description    string            `json:"description"`
	Reference      []string          `json:"reference,omitempty"`
	Severity       string            `json:"severity"`
	Classification Classification    `json:"classification,omitempty"`
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
	Targets   []string
	Findings  []*Finding
	Stats     ScanStats
	Duration  time.Duration
	Errors    []string
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
	BinaryPath      string
	TemplatesPath   string
	Timeout         time.Duration
	RateLimit       int
	BulkSize        int
	Concurrency     int
	Retries         int
	Severities      []string // critical, high, medium, low, info
	Tags            []string // specific tags to include
	ExcludeTags     []string // tags to exclude
	Templates       []string // specific template IDs
	ExcludeTemplates []string
	Headers         map[string]string
	OutputDir       string
	Silent          bool
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

// IsInstalled checks if nuclei is available
func (s *Scanner) IsInstalled() bool {
	_, err := exec.LookPath(s.BinaryPath)
	return err == nil
}

// GetVersion returns the nuclei version
func (s *Scanner) GetVersion() (string, error) {
	cmd := exec.Command(s.BinaryPath, "-version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// UpdateTemplates updates nuclei templates
func (s *Scanner) UpdateTemplates(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.BinaryPath, "-update-templates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Scan runs nuclei against targets
func (s *Scanner) Scan(ctx context.Context, targets []string) (*Result, error) {
	if !s.IsInstalled() {
		return nil, fmt.Errorf("nuclei not found in PATH - install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	}

	start := time.Now()
	result := &Result{
		Targets: targets,
	}

	// Create temp file for targets
	targetFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("creating target file: %w", err)
	}
	defer os.Remove(targetFile.Name())

	for _, t := range targets {
		targetFile.WriteString(t + "\n")
	}
	targetFile.Close()

	// Build command arguments
	args := s.buildArgs(targetFile.Name())

	// Create command
	cmd := exec.CommandContext(ctx, s.BinaryPath, args...)

	// Capture stdout for JSON output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

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
		// Nuclei returns non-zero exit codes for various reasons
		// Check if we got findings anyway
		if len(result.Findings) == 0 {
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// Calculate stats
	result.Duration = time.Since(start)
	result.Stats = s.calculateStats(result)

	return result, nil
}

// ScanWithCallback runs nuclei and calls callback for each finding
func (s *Scanner) ScanWithCallback(ctx context.Context, targets []string, callback func(*Finding)) (*Result, error) {
	if !s.IsInstalled() {
		return nil, fmt.Errorf("nuclei not found in PATH")
	}

	start := time.Now()
	result := &Result{
		Targets: targets,
	}

	// Create temp file for targets
	targetFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("creating target file: %w", err)
	}
	defer os.Remove(targetFile.Name())

	for _, t := range targets {
		targetFile.WriteString(t + "\n")
	}
	targetFile.Close()

	args := s.buildArgs(targetFile.Name())
	cmd := exec.CommandContext(ctx, s.BinaryPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

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

	cmd.Wait()
	result.Duration = time.Since(start)
	result.Stats = s.calculateStats(result)

	return result, nil
}

func (s *Scanner) buildArgs(targetFile string) []string {
	args := []string{
		"-l", targetFile,
		"-json",
		"-silent",
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
		os.MkdirAll(s.OutputDir, 0755)
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
