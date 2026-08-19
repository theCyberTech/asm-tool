package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg == nil {
		t.Fatal("Default() returned nil")
	}

	// Check default values
	if cfg.DatabasePath != "data/asm.db" {
		t.Errorf("expected DatabasePath 'data/asm.db', got '%s'", cfg.DatabasePath)
	}

	if cfg.Scanning.RateLimit != 100 {
		t.Errorf("expected RateLimit 100, got %d", cfg.Scanning.RateLimit)
	}

	if cfg.Scanning.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}

	if cfg.Timeouts.HTTP != 10*time.Second {
		t.Errorf("expected HTTP timeout 10s, got %v", cfg.Timeouts.HTTP)
	}

	if cfg.Notifications.Email.SMTPPort != 587 {
		t.Errorf("expected SMTP port 587, got %d", cfg.Notifications.Email.SMTPPort)
	}
}

func TestParsePortString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single port",
			input:    "80",
			expected: []int{80},
		},
		{
			name:     "multiple ports",
			input:    "80,443,8080",
			expected: []int{80, 443, 8080},
		},
		{
			name:     "port range",
			input:    "80-83",
			expected: []int{80, 81, 82, 83},
		},
		{
			name:     "mixed ports and ranges",
			input:    "22,80-82,443",
			expected: []int{22, 80, 81, 82, 443},
		},
		{
			name:     "with whitespace",
			input:    " 80 , 443 , 8080 ",
			expected: []int{80, 443, 8080},
		},
		{
			name:     "duplicate ports",
			input:    "80,80,443",
			expected: []int{80, 443},
		},
		{
			name:     "invalid port (too high)",
			input:    "80,99999",
			expected: []int{80},
		},
		{
			name:     "invalid port (zero)",
			input:    "0,80",
			expected: []int{80},
		},
		{
			name:     "invalid format",
			input:    "abc,80",
			expected: []int{80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePortString(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d ports, got %d: %v", len(tt.expected), len(result), result)
				return
			}

			for i, port := range result {
				if port != tt.expected[i] {
					t.Errorf("port at index %d: expected %d, got %d", i, tt.expected[i], port)
				}
			}
		})
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("Load should not error for non-existent file: %v", err)
	}

	if cfg == nil {
		t.Fatal("Load should return default config for non-existent file")
	}

	// Should return defaults
	if cfg.DatabasePath != "data/asm.db" {
		t.Errorf("expected default DatabasePath, got '%s'", cfg.DatabasePath)
	}
}

func TestLoadValidConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
domains:
  - example.com
  - test.com

database_path: custom/path.db

scanning:
  ports: "80,443"
  rate_limit: 50
  insecure_skip_verify: true

notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/test"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify loaded values
	if len(cfg.Domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(cfg.Domains))
	}

	if cfg.DatabasePath != "custom/path.db" {
		t.Errorf("expected 'custom/path.db', got '%s'", cfg.DatabasePath)
	}

	if cfg.Scanning.RateLimit != 50 {
		t.Errorf("expected rate limit 50, got %d", cfg.Scanning.RateLimit)
	}

	if !cfg.Scanning.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}

	if !cfg.Notifications.Slack.Enabled {
		t.Error("expected Slack notifications to be enabled")
	}
}

func TestApplyEnvOverridesPrefersEnv(t *testing.T) {
	cfg := Default()
	cfg.Notifications.Email.SMTPUser = "yaml-user"
	cfg.Notifications.Email.SMTPPassword = "yaml-pass"
	cfg.Notifications.Slack.WebhookURL = "https://hooks.slack.com/yaml"

	t.Setenv("ASM_SMTP_USER", "env-user")
	t.Setenv("ASM_SMTP_PASSWORD", "env-pass")
	t.Setenv("ASM_SLACK_WEBHOOK", "https://hooks.slack.com/env")
	t.Setenv("ASM_DASHBOARD_TOKEN", "env-dash-token")

	ApplyEnvOverrides(cfg)

	if cfg.Notifications.Email.SMTPUser != "env-user" {
		t.Errorf("SMTPUser = %q, want env-user", cfg.Notifications.Email.SMTPUser)
	}
	if cfg.Notifications.Email.SMTPPassword != "env-pass" {
		t.Errorf("SMTPPassword = %q, want env-pass", cfg.Notifications.Email.SMTPPassword)
	}
	if cfg.Notifications.Slack.WebhookURL != "https://hooks.slack.com/env" {
		t.Errorf("WebhookURL = %q, want env webhook", cfg.Notifications.Slack.WebhookURL)
	}
	if cfg.Dashboard.Token != "env-dash-token" {
		t.Errorf("Dashboard.Token = %q, want env-dash-token", cfg.Dashboard.Token)
	}
}

func TestLoadReadsSMTPFromYAML(t *testing.T) {
	t.Setenv("ASM_SMTP_USER", "")
	t.Setenv("SMTP_USER", "")
	t.Setenv("ASM_SMTP_PASSWORD", "")
	t.Setenv("SMTP_PASSWORD", "")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
notifications:
  email:
    enabled: true
    smtp_host: "smtp.example.com"
    smtp_port: 465
    smtp_user: "yaml-user"
    smtp_password: "yaml-pass"
    from_addr: "alerts@example.com"
    to_addr: "security@example.com"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Notifications.Email.SMTPUser != "yaml-user" {
		t.Errorf("SMTPUser = %q, want yaml-user", cfg.Notifications.Email.SMTPUser)
	}
	if cfg.Notifications.Email.SMTPPassword != "yaml-pass" {
		t.Errorf("SMTPPassword = %q, want yaml-pass", cfg.Notifications.Email.SMTPPassword)
	}
}

func TestConfigParsePorts(t *testing.T) {
	cfg := Default()
	cfg.Scanning.Ports = "22,80,443"

	ports := cfg.ParsePorts()

	if len(ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(ports))
	}

	expected := []int{22, 80, 443}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port %d: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		input    string
		sep      string
		expected []string
	}{
		{"a,b,c", ",", []string{"a", "b", "c"}},
		{" a , b , c ", ",", []string{"a", "b", "c"}},
		{"  hello  ", ",", []string{"hello"}},
		{"", ",", nil},
		{"a,,b", ",", []string{"a", "b"}},
	}

	for _, tt := range tests {
		result := splitAndTrim(tt.input, tt.sep)
		if len(result) != len(tt.expected) {
			t.Errorf("splitAndTrim(%q): expected %v, got %v", tt.input, tt.expected, result)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("splitAndTrim(%q)[%d]: expected %q, got %q", tt.input, i, tt.expected[i], result[i])
			}
		}
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"0", 0},
		{"1", 1},
		{"123", 123},
		{"65535", 65535},
		{"abc", 0},
		{"12abc", 0},
		{"", 0},
	}

	for _, tt := range tests {
		result := parseInt(tt.input)
		if result != tt.expected {
			t.Errorf("parseInt(%q): expected %d, got %d", tt.input, tt.expected, result)
		}
	}
}

func TestFindChar(t *testing.T) {
	tests := []struct {
		s        string
		c        byte
		expected int
	}{
		{"hello", 'e', 1},
		{"hello", 'o', 4},
		{"hello", 'x', -1},
		{"", 'a', -1},
		{"80-100", '-', 2},
	}

	for _, tt := range tests {
		result := findChar(tt.s, tt.c)
		if result != tt.expected {
			t.Errorf("findChar(%q, %c): expected %d, got %d", tt.s, tt.c, tt.expected, result)
		}
	}
}
