package commands

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/parallel"
	"github.com/asm-tool/asm-go/internal/scanner/ports"
)

func TestPersistScanResultWritesFindingsAndSnapshot(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "asm.db"))
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	result := &parallel.ScanResult{
		Domain:     "example.com",
		Subdomains: []string{"www.example.com"},
		Ports: []*ports.Result{{
			Host: "www.example.com",
			OpenPorts: []ports.Port{{
				Port: 443, State: "open", Service: "https",
			}},
		}},
	}
	if err := persistScanResult(db, result, "full"); err != nil {
		t.Fatalf("persistScanResult: %v", err)
	}

	domain, err := db.Domains.GetByName("example.com")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if domain == nil {
		t.Fatal("expected domain row after persist")
	}

	snapshots, err := db.GetLatestSnapshots("example.com", 2)
	if err != nil {
		t.Fatalf("GetLatestSnapshots: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snapshots))
	}
	var subs []string
	if err := json.Unmarshal([]byte(snapshots[0].Subdomains), &subs); err != nil {
		t.Fatalf("unmarshal subdomains: %v", err)
	}
	if len(subs) != 1 || subs[0] != "www.example.com" {
		t.Fatalf("snapshot subdomains = %v", subs)
	}
}

func TestPersistScanResultNilDatabaseIsNoop(t *testing.T) {
	if err := persistScanResult(nil, &parallel.ScanResult{Domain: "example.com"}, "full"); err != nil {
		t.Fatalf("persistScanResult(nil) = %v", err)
	}
}

func TestRunFullScanRejectsInvalidDomainBeforeScanning(t *testing.T) {
	err := runFullScan(nil, nil, "example.com/path", scanOptions{})
	if err == nil {
		t.Fatal("runFullScan accepted an invalid domain")
	}
	if !strings.Contains(err.Error(), "invalid target domain") {
		t.Fatalf("runFullScan error = %q, want invalid target domain", err.Error())
	}
}

func TestBuildScanConfigUsesConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Scanning.Ports = "80,443"
	cfg.Scanning.RateLimit = 25
	cfg.Scanning.NucleiSeverity = "low,medium"
	cfg.Scanning.InsecureSkipVerify = true
	cfg.Timeouts.Subfinder = 11 * time.Second
	cfg.Timeouts.Nmap = 12 * time.Second
	cfg.Timeouts.HTTP = 13 * time.Second
	cfg.Timeouts.DNS = 14 * time.Second
	cfg.Timeouts.Gau = 15 * time.Second
	cfg.Timeouts.Nuclei = 16 * time.Second
	cfg.Nuclei.BatchSize = 17
	cfg.Nuclei.Concurrency = 18
	cfg.Nuclei.Retries = 2
	cfg.Nuclei.ExcludeTags = "dos,fuzz"

	ports := cfg.ParsePorts()
	if !reflect.DeepEqual(ports, []int{80, 443}) {
		t.Fatalf("cfg.ParsePorts() = %v, want [80 443]", ports)
	}
	if cfg.Scanning.RateLimit != 25 {
		t.Fatalf("RateLimit = %d, want 25", cfg.Scanning.RateLimit)
	}
	if !cfg.Scanning.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true")
	}
}

func TestBuildEnabledModules(t *testing.T) {
	cfg := config.Default()
	cfg.Scanning.PassiveOnly = true

	enabled := buildEnabledModules(cfg, scanOptions{enableNuclei: true})

	// In passive-only, only passive modules should be enabled
	for _, mod := range []parallel.ModuleType{
		parallel.ModulePorts,
		parallel.ModuleCertificates,
		parallel.ModuleTakeover,
		parallel.ModuleTechnologies,
		parallel.ModuleAPIs,
		parallel.ModuleCloudStorage,
		parallel.ModuleNuclei,
	} {
		if enabled[mod] {
			t.Fatalf("%s enabled in passive-only mode", mod)
		}
	}

	for _, mod := range []parallel.ModuleType{
		parallel.ModuleSubdomains,
		parallel.ModuleDNS,
		parallel.ModuleURLs,
	} {
		if !enabled[mod] {
			t.Fatalf("%s disabled in passive-only mode", mod)
		}
	}
}

func TestBuildEnabledModulesNucleiOption(t *testing.T) {
	enabled := buildEnabledModules(config.Default(), scanOptions{enableNuclei: true})
	if !enabled[parallel.ModuleNuclei] {
		t.Fatal("nuclei not enabled by enableNuclei option")
	}
}

func TestScanNotifierUsesConfigAndFlagOverrides(t *testing.T) {
	cfg := config.Default()
	cfg.Timeouts.HTTP = 3 * time.Second
	cfg.Notifications.Slack.Enabled = true
	cfg.Notifications.Slack.WebhookURL = "https://hooks.slack.com/services/config"
	cfg.Notifications.Email.Enabled = true
	cfg.Notifications.Email.SMTPHost = "smtp.example.com"
	cfg.Notifications.Email.SMTPPort = 2525
	cfg.Notifications.Email.FromAddr = "alerts@example.com"
	cfg.Notifications.Email.ToAddr = "security@example.com,ops@example.com"
	cfg.Notifications.Email.SMTPUser = "smtp-user"
	cfg.Notifications.Email.SMTPPassword = "smtp-pass"

	fromConfig := scanNotifier(cfg, scanOptions{})
	if fromConfig.SlackWebhook != "https://hooks.slack.com/services/config" {
		t.Fatalf("SlackWebhook = %q, want config webhook", fromConfig.SlackWebhook)
	}
	if !reflect.DeepEqual(fromConfig.EmailTo, []string{"security@example.com", "ops@example.com"}) {
		t.Fatalf("EmailTo = %v, want config recipients", fromConfig.EmailTo)
	}
	if fromConfig.SMTPHost != "smtp.example.com" || fromConfig.SMTPPort != 2525 || fromConfig.EmailFrom != "alerts@example.com" {
		t.Fatalf("SMTP settings were not populated from config")
	}
	if fromConfig.SMTPUser != "smtp-user" || fromConfig.SMTPPassword != "smtp-pass" {
		t.Fatalf("SMTP credentials were not populated from config")
	}
	if fromConfig.HTTPClient.Timeout != 3*time.Second {
		t.Fatalf("notifier HTTP timeout = %v, want 3s", fromConfig.HTTPClient.Timeout)
	}

	fromFlags := scanNotifier(cfg, scanOptions{
		slackWebhook:      "https://hooks.slack.com/services/flag",
		slackWebhookSet:   true,
		emailRecipient:    "flag@example.com",
		emailRecipientSet: true,
	})
	if fromFlags.SlackWebhook != "https://hooks.slack.com/services/flag" {
		t.Fatalf("SlackWebhook = %q, want flag webhook", fromFlags.SlackWebhook)
	}
	if !reflect.DeepEqual(fromFlags.EmailTo, []string{"flag@example.com"}) {
		t.Fatalf("EmailTo = %v, want flag recipient", fromFlags.EmailTo)
	}
}