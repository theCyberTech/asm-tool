package config

import (
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the ASM tool
type Config struct {
	Domains []string `mapstructure:"domains"`

	// Notification settings
	Notifications NotificationConfig `mapstructure:"notifications"`

	// Scanning settings
	Scanning ScanningConfig `mapstructure:"scanning"`

	// Nuclei optimization
	Nuclei NucleiConfig `mapstructure:"nuclei"`

	// Timeout settings
	Timeouts TimeoutConfig `mapstructure:"timeouts"`

	// External APIs
	Hunter HunterConfig `mapstructure:"hunter"`

	// Screenshot settings
	Screenshots ScreenshotConfig `mapstructure:"screenshots"`

	// Schedule settings
	Schedule ScheduleConfig `mapstructure:"schedule"`

	// Dashboard settings
	Dashboard DashboardConfig `mapstructure:"dashboard"`

	// Database path
	DatabasePath string `mapstructure:"database_path"`
}

type NotificationConfig struct {
	Slack SlackConfig `mapstructure:"slack"`
	Email EmailConfig `mapstructure:"email"`
}

type SlackConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	WebhookURL string `mapstructure:"webhook_url"`
}

type EmailConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUser     string `mapstructure:"smtp_user"`
	SMTPPassword string `mapstructure:"smtp_password"`
	FromAddr     string `mapstructure:"from_addr"`
	ToAddr       string `mapstructure:"to_addr"`
}

type ScanningConfig struct {
	Ports              string `mapstructure:"ports"`
	NucleiSeverity     string `mapstructure:"nuclei_severity"`
	PassiveOnly        bool   `mapstructure:"passive_only"`
	RateLimit          int    `mapstructure:"rate_limit"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"` // Skip TLS certificate verification (use with caution)
}

type NucleiConfig struct {
	Concurrency int    `mapstructure:"concurrency"`
	BatchSize   int    `mapstructure:"batch_size"`
	ExcludeTags string `mapstructure:"exclude_tags"`
	Retries     int    `mapstructure:"retries"`
}

type TimeoutConfig struct {
	Subfinder time.Duration `mapstructure:"subfinder"`
	Nmap      time.Duration `mapstructure:"nmap"`
	Nuclei    time.Duration `mapstructure:"nuclei"`
	Gau       time.Duration `mapstructure:"gau"`
	HTTP      time.Duration `mapstructure:"http"`
	DNS       time.Duration `mapstructure:"dns"`
}

type HunterConfig struct {
	APIKey string `mapstructure:"api_key"`
}

type ScreenshotConfig struct {
	Width   int `mapstructure:"width"`
	Height  int `mapstructure:"height"`
	Timeout int `mapstructure:"timeout"`
	Workers int `mapstructure:"workers"`
}

type ScheduleConfig struct {
	FullScan  string `mapstructure:"full_scan"`
	CertCheck string `mapstructure:"cert_check"`
}

type DashboardConfig struct {
	Host  string `mapstructure:"host"`
	Port  int    `mapstructure:"port"`
	Token string `mapstructure:"token"`
}

// Default returns a Config with sensible defaults
func Default() *Config {
	return &Config{
		Domains: []string{},
		Notifications: NotificationConfig{
			Slack: SlackConfig{Enabled: false},
			Email: EmailConfig{SMTPPort: 587},
		},
		Scanning: ScanningConfig{
			Ports:          "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443",
			NucleiSeverity: "medium,high,critical",
			PassiveOnly:    false,
			RateLimit:      100,
		},
		Nuclei: NucleiConfig{
			Concurrency: 25,
			BatchSize:   25,
			ExcludeTags: "dos,fuzz,brute",
			Retries:     1,
		},
		Timeouts: TimeoutConfig{
			Subfinder: 5 * time.Minute,
			Nmap:      2 * time.Second,
			Nuclei:    30 * time.Minute,
			Gau:       10 * time.Minute,
			HTTP:      10 * time.Second,
			DNS:       5 * time.Second,
		},
		Screenshots: ScreenshotConfig{
			Width:   1920,
			Height:  1080,
			Timeout: 30,
			Workers: 3,
		},
		Schedule: ScheduleConfig{
			FullScan:  "0 6 * * *",
			CertCheck: "0 */6 * * *",
		},
		Dashboard: DashboardConfig{
			Host: "127.0.0.1",
			Port: 8080,
		},
		DatabasePath: "data/asm.db",
	}
}

// Load reads configuration from a YAML file
func Load(path string) (*Config, error) {
	cfg := Default()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		applyEnvOverrides(cfg)
		return cfg, nil
	}

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	// Set defaults for nested structures before unmarshaling
	v.SetDefault("notifications.email.smtp_port", 587)
	v.SetDefault("scanning.ports", cfg.Scanning.Ports)
	v.SetDefault("scanning.nuclei_severity", cfg.Scanning.NucleiSeverity)
	v.SetDefault("scanning.rate_limit", cfg.Scanning.RateLimit)
	v.SetDefault("nuclei.concurrency", cfg.Nuclei.Concurrency)
	v.SetDefault("nuclei.batch_size", cfg.Nuclei.BatchSize)
	v.SetDefault("nuclei.exclude_tags", cfg.Nuclei.ExcludeTags)
	v.SetDefault("nuclei.retries", cfg.Nuclei.Retries)
	v.SetDefault("screenshots.width", cfg.Screenshots.Width)
	v.SetDefault("screenshots.height", cfg.Screenshots.Height)
	v.SetDefault("screenshots.timeout", cfg.Screenshots.Timeout)
	v.SetDefault("screenshots.workers", cfg.Screenshots.Workers)
	v.SetDefault("schedule.full_scan", cfg.Schedule.FullScan)
	v.SetDefault("schedule.cert_check", cfg.Schedule.CertCheck)

	// Save defaults before unmarshal may zero them (time.Duration fields don't
	// map naturally from YAML ints).
	defaultTimeouts := cfg.Timeouts

	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// Restore timeout defaults; manual YAML values override them below.
	cfg.Timeouts = defaultTimeouts

	// Handle timeout conversions from seconds (YAML) to time.Duration
	if timeouts := v.Sub("timeouts"); timeouts != nil {
		if s := timeouts.GetInt("subfinder"); s > 0 {
			cfg.Timeouts.Subfinder = time.Duration(s) * time.Second
		}
		if s := timeouts.GetInt("nmap"); s > 0 {
			cfg.Timeouts.Nmap = time.Duration(s) * time.Second
		}
		if s := timeouts.GetInt("nuclei"); s > 0 {
			cfg.Timeouts.Nuclei = time.Duration(s) * time.Second
		}
		if s := timeouts.GetInt("gau"); s > 0 {
			cfg.Timeouts.Gau = time.Duration(s) * time.Second
		}
		if s := timeouts.GetInt("http"); s > 0 {
			cfg.Timeouts.HTTP = time.Duration(s) * time.Second
		}
		if s := timeouts.GetInt("dns"); s > 0 {
			cfg.Timeouts.DNS = time.Duration(s) * time.Second
		}
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

// ApplyEnvOverrides overlays environment variables onto cfg. Non-empty env
// values win over YAML so secrets can stay out of the config file.
func ApplyEnvOverrides(cfg *Config) {
	applyEnvOverrides(cfg)
}

func applyEnvOverrides(cfg *Config) {
	if cfg == nil {
		return
	}

	if v := firstNonEmptyEnv("ASM_SMTP_USER", "SMTP_USER"); v != "" {
		cfg.Notifications.Email.SMTPUser = v
	}
	if v := firstNonEmptyEnv("ASM_SMTP_PASSWORD", "SMTP_PASSWORD"); v != "" {
		cfg.Notifications.Email.SMTPPassword = v
	}
	if v := firstNonEmptyEnv("ASM_SLACK_WEBHOOK", "SLACK_WEBHOOK_URL"); v != "" {
		cfg.Notifications.Slack.WebhookURL = v
	}
	if v := firstNonEmptyEnv("ASM_DASHBOARD_TOKEN"); v != "" {
		cfg.Dashboard.Token = v
	}
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

// ParsePorts converts the comma-separated ports string to a slice of ints
func (c *Config) ParsePorts() []int {
	return ParsePortString(c.Scanning.Ports)
}

// ParsePortString parses a port specification string into a slice of port numbers
func ParsePortString(s string) []int {
	if s == "" {
		return nil
	}

	var ports []int
	seen := make(map[int]bool)

	for _, part := range splitAndTrim(s, ",") {
		if part == "" {
			continue
		}

		// Handle ranges like "80-100"
		if idx := findChar(part, '-'); idx > 0 && idx < len(part)-1 {
			start := parseInt(part[:idx])
			end := parseInt(part[idx+1:])
			if start > 0 && end > 0 && start <= end && end <= 65535 {
				for p := start; p <= end; p++ {
					if !seen[p] {
						ports = append(ports, p)
						seen[p] = true
					}
				}
			}
		} else {
			// Single port
			p := parseInt(part)
			if p > 0 && p <= 65535 && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}

	return ports
}

func splitAndTrim(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || (len(sep) == 1 && s[i] == sep[0]) {
			part := s[start:i]
			// Trim whitespace
			for len(part) > 0 && (part[0] == ' ' || part[0] == '\t') {
				part = part[1:]
			}
			for len(part) > 0 && (part[len(part)-1] == ' ' || part[len(part)-1] == '\t') {
				part = part[:len(part)-1]
			}
			if len(part) > 0 {
				result = append(result, part)
			}
			start = i + 1
		}
	}
	return result
}

func findChar(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func parseInt(s string) int {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
