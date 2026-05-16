package commands

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/parallel"
)

func TestRunFullScanRejectsInvalidDomainBeforeScanning(t *testing.T) {
	err := runFullScan(nil, nil, "example.com/path", scanOptions{})
	if err == nil {
		t.Fatal("runFullScan accepted an invalid domain")
	}
	if !strings.Contains(err.Error(), "invalid target domain") {
		t.Fatalf("runFullScan error = %q, want invalid target domain", err.Error())
	}
}

func TestConfigureScanRunnerUsesConfig(t *testing.T) {
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
	cfg.Hunter.APIKey = "hunter-key"

	runner := parallel.DefaultRunner(nil)
	configureScanRunner(runner, cfg, scanOptions{
		portWorkers:  7,
		apiWorkers:   8,
		enableNuclei: true,
	})

	if !reflect.DeepEqual(runner.Ports, []int{80, 443}) {
		t.Fatalf("runner.Ports = %v, want [80 443]", runner.Ports)
	}
	if runner.PortWorkers != 7 || runner.APIWorkers != 8 {
		t.Fatalf("workers = ports:%d api:%d, want ports:7 api:8", runner.PortWorkers, runner.APIWorkers)
	}
	if runner.RateLimit != 25 || runner.NucleiRateLimit != 25 {
		t.Fatalf("rate limits = passive:%d nuclei:%d, want 25", runner.RateLimit, runner.NucleiRateLimit)
	}
	if !runner.InsecureSkipVerify {
		t.Fatal("runner.InsecureSkipVerify = false, want true")
	}
	if runner.SubdomainTimeout != 11*time.Second || runner.PortTimeout != 12*time.Second ||
		runner.HTTPTimeout != 13*time.Second || runner.DNSTimeout != 14*time.Second ||
		runner.URLTimeout != 15*time.Second || runner.NucleiTimeout != 16*time.Second {
		t.Fatalf("runner timeouts were not populated from config")
	}
	if runner.NucleiBulkSize != 17 || runner.NucleiConcurrency != 18 || runner.NucleiRetries != 2 {
		t.Fatalf("nuclei settings = bulk:%d concurrency:%d retries:%d", runner.NucleiBulkSize, runner.NucleiConcurrency, runner.NucleiRetries)
	}
	if !reflect.DeepEqual(runner.NucleiSeverities, []string{"low", "medium"}) {
		t.Fatalf("runner.NucleiSeverities = %v, want [low medium]", runner.NucleiSeverities)
	}
	if !reflect.DeepEqual(runner.NucleiExcludeTags, []string{"dos", "fuzz"}) {
		t.Fatalf("runner.NucleiExcludeTags = %v, want [dos fuzz]", runner.NucleiExcludeTags)
	}
	if runner.HunterAPIKey != "hunter-key" {
		t.Fatalf("runner.HunterAPIKey = %q, want hunter-key", runner.HunterAPIKey)
	}
	if !runner.EnabledModules[parallel.ModuleNuclei] {
		t.Fatal("nuclei module was not enabled by scan option")
	}
}

func TestConfigureScanRunnerFlagSeverityOverridesConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Scanning.NucleiSeverity = "medium"

	runner := parallel.DefaultRunner(nil)
	configureScanRunner(runner, cfg, scanOptions{
		nucleiSeverities:  []string{"critical", "high"},
		nucleiSeveritySet: true,
	})

	if !reflect.DeepEqual(runner.NucleiSeverities, []string{"critical", "high"}) {
		t.Fatalf("runner.NucleiSeverities = %v, want flag value", runner.NucleiSeverities)
	}
}

func TestConfigureScanRunnerPassiveOnlyDisablesActiveModules(t *testing.T) {
	cfg := config.Default()
	cfg.Scanning.PassiveOnly = true

	runner := parallel.DefaultRunner(nil)
	configureScanRunner(runner, cfg, scanOptions{enableNuclei: true})

	for _, mod := range []parallel.ModuleType{
		parallel.ModulePorts,
		parallel.ModuleCertificates,
		parallel.ModuleTakeover,
		parallel.ModuleTechnologies,
		parallel.ModuleAPIs,
		parallel.ModuleCloudStorage,
		parallel.ModuleNuclei,
	} {
		if runner.EnabledModules[mod] {
			t.Fatalf("%s enabled in passive-only mode", mod)
		}
	}

	for _, mod := range []parallel.ModuleType{
		parallel.ModuleSubdomains,
		parallel.ModuleDNS,
		parallel.ModuleURLs,
		parallel.ModuleEmails,
	} {
		if !runner.EnabledModules[mod] {
			t.Fatalf("%s disabled in passive-only mode", mod)
		}
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
