package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/asm-tool/asm-go/internal/config"
	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/notifier"
	"github.com/asm-tool/asm-go/internal/parallel"
	"github.com/asm-tool/asm-go/internal/persistence"
	"github.com/asm-tool/asm-go/internal/reporter"
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/asm-tool/asm-go/internal/target"
	"github.com/spf13/cobra"
)

// ScanCmd creates the scan command for full domain scanning
func ScanCmd(deps *Deps) *cobra.Command {
	var (
		skipModules      []string
		onlyModules      []string
		outputFormat     string
		outputDir        string
		slackWebhook     string
		emailRecipient   string
		portWorkers      int
		apiWorkers       int
		verbose          bool
		enableNuclei     bool
		nucleiSeverities []string
	)

	cmd := &cobra.Command{
		Use:   "scan <domain>",
		Short: "Run a full scan on a domain",
		Long: `Execute a comprehensive scan including all modules:
- Subdomain enumeration
- Port scanning
- TLS certificate analysis
- DNS record lookup
- Subdomain takeover detection
- Technology fingerprinting
- URL enumeration
- API discovery
- Cloud storage detection
- Vulnerability scanning (optional, requires nuclei)

Scanning is restricted to crewai.com and its subdomains.

Modules run in parallel where possible for optimal performance.
Results can be output to JSON, Markdown, or HTML reports.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			return runFullScan(deps.DB, deps.Cfg, domain, scanOptions{
				skipModules:       skipModules,
				onlyModules:       onlyModules,
				outputFormat:      outputFormat,
				outputDir:         outputDir,
				slackWebhook:      slackWebhook,
				slackWebhookSet:   cmd.Flags().Changed("slack"),
				emailRecipient:    emailRecipient,
				emailRecipientSet: cmd.Flags().Changed("email"),
				portWorkers:       portWorkers,
				apiWorkers:        apiWorkers,
				verbose:           verbose,
				enableNuclei:      enableNuclei,
				nucleiSeverities:  nucleiSeverities,
				nucleiSeveritySet: cmd.Flags().Changed("nuclei-severity"),
			})
		},
	}

	cmd.Flags().StringSliceVar(&skipModules, "skip", nil, "Modules to skip (subdomains,ports,certificates,dns,takeover,technologies,urls,apis,cloudstorage,nuclei)")
	cmd.Flags().StringSliceVar(&onlyModules, "only", nil, "Only run these modules")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: json, markdown, html (default: no file output)")
	cmd.Flags().StringVar(&outputDir, "output-dir", "reports", "Directory for report output")
	cmd.Flags().StringVar(&slackWebhook, "slack", "", "Slack webhook URL for notifications")
	cmd.Flags().StringVar(&emailRecipient, "email", "", "Email address for notifications")
	cmd.Flags().IntVar(&portWorkers, "port-workers", 100, "Number of port scanning workers")
	cmd.Flags().IntVar(&apiWorkers, "api-workers", 30, "Number of API discovery workers")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed progress")
	cmd.Flags().BoolVar(&enableNuclei, "nuclei", false, "Enable vulnerability scanning with Nuclei")
	cmd.Flags().StringSliceVar(&nucleiSeverities, "nuclei-severity", []string{"critical", "high"}, "Nuclei severity levels")

	return cmd
}

type scanOptions struct {
	skipModules       []string
	onlyModules       []string
	outputFormat      string
	outputDir         string
	slackWebhook      string
	slackWebhookSet   bool
	emailRecipient    string
	emailRecipientSet bool
	portWorkers       int
	apiWorkers        int
	verbose           bool
	enableNuclei      bool
	nucleiSeverities  []string
	nucleiSeveritySet bool
}

func runFullScan(db *database.Database, cfg *config.Config, domain string, opts scanOptions) error {
	normalizedDomain, err := target.NormalizeScanTarget(domain)
	if err != nil {
		return err
	}
	domain = normalizedDomain
	if cfg == nil {
		cfg = config.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts with proper cleanup to prevent goroutine leak
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sigCh:
			fmt.Println("\nInterrupted, stopping scan...")
			cancel()
		case <-done:
			// Scan completed normally, exit goroutine
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(done)
	}()

	// Print header
	fmt.Printf("\n%s Full Scan: %s\n", titleStyle.Render("[*]"), valueStyle.Render(domain))
	fmt.Println(strings.Repeat("=", 60))

	// Build config and enabled modules
	runCfg := buildScanConfig(cfg, opts)
	enabled := buildEnabledModules(cfg, opts)

	// Print enabled modules
	var enabledNames []string
	for mod, on := range enabled {
		if on {
			enabledNames = append(enabledNames, string(mod))
		}
	}
	fmt.Printf("%s Modules: %s\n", labelStyle.Render("   "), strings.Join(enabledNames, ", "))
	fmt.Printf("%s Workers: ports=%d\n", labelStyle.Render("   "), opts.portWorkers)
	if cfg.Scanning.PassiveOnly {
		fmt.Printf("%s Passive mode: active modules disabled\n", labelStyle.Render("   "))
	}
	fmt.Println(strings.Repeat("-", 60))

	// Progress callback
	moduleStatus := make(map[parallel.ModuleType]string)
	progress := func(module parallel.ModuleType, duration time.Duration, err error) {
		status := "."
		if err != nil {
			status = "!"
		}
		moduleStatus[module] = status
		if opts.verbose {
			status = lowStyle.Render("OK")
			if err != nil {
				status = highStyle.Render("ERR")
			}
			fmt.Printf("%s %-15s %s (%s)\n",
				labelStyle.Render("[*]"),
				module,
				status,
				duration.Round(time.Millisecond))
		} else {
			fmt.Print(status)
		}
	}

	// Run scan
	fmt.Printf("\n%s Scanning...\n", titleStyle.Render("[*]"))
	startTime := time.Now()
	r := parallel.Runner{}
	result := r.Run(ctx, domain, runCfg, enabled, progress)
	if !opts.verbose {
		fmt.Println() // newline after progress dots
	}

	if err := ctx.Err(); err == context.Canceled {
		fmt.Printf("%s Scan cancelled\n", highStyle.Render("[!]"))
	}
	if len(result.Errors) > 0 {
		for mod, modErr := range result.Errors {
			fmt.Printf("%s %s: %v\n", highStyle.Render("[!]"), mod, modErr)
		}
	}

	// Print results summary
	fmt.Println(strings.Repeat("-", 60))
	printScanSummary(result)

	if err := persistScanResult(db, result, "full"); err != nil {
		return fmt.Errorf("saving scan results: %w", err)
	}
	if db != nil {
		fmt.Printf("%s Results saved to database\n", lowStyle.Render("[+]"))
	}

	// Generate report if requested
	if opts.outputFormat != "" {
		rep := reporter.DefaultReporter()
		rep.OutputDir = opts.outputDir

		format, perr := reporter.ParseFormat(opts.outputFormat)
		if perr != nil {
			fmt.Printf("%s Unknown format: %s\n", highStyle.Render("[!]"), opts.outputFormat)
			return nil
		}

		path, err := rep.Generate(result, format)
		if err != nil {
			fmt.Printf("%s Report error: %v\n", highStyle.Render("[!]"), err)
		} else {
			fmt.Printf("%s Report saved: %s\n", lowStyle.Render("[+]"), path)
		}
	}

	// Send notifications
	n := scanNotifier(cfg, opts)
	if n.SlackWebhook != "" {
		if err := n.NotifySlack(result); err != nil {
			fmt.Printf("%s Slack notification failed: %v\n", highStyle.Render("[!]"), err)
		} else {
			fmt.Printf("%s Slack notification sent\n", lowStyle.Render("[+]"))
		}
	}
	if len(n.EmailTo) > 0 {
		if err := n.NotifyEmail(result); err != nil {
			fmt.Printf("%s Email notification failed: %v\n", highStyle.Render("[!]"), err)
		} else {
			fmt.Printf("%s Email notification sent\n", lowStyle.Render("[+]"))
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("%s Scan completed in %s\n", titleStyle.Render("[*]"),
		valueStyle.Render(time.Since(startTime).Round(time.Millisecond).String()))

	return nil
}

// buildScanConfig builds a RunConfig from the CLI options.
func buildScanConfig(cfg *config.Config, opts scanOptions) parallel.RunConfig {
	if cfg == nil {
		cfg = config.Default()
	}

	out := parallel.DefaultRunConfig()

	// Port config
	if opts.portWorkers > 0 {
		out.Ports.Workers = opts.portWorkers
	}
	out.Ports.Ports = cfg.ParsePorts()
	if cfg.Timeouts.Nmap > 0 {
		out.Ports.Timeout = cfg.Timeouts.Nmap
	}
	out.Ports.GrabBanner = true

	// Subdomain
	out.Subdomains.RateLimit = cfg.Scanning.RateLimit
	if cfg.Timeouts.Subfinder > 0 {
		out.Subdomains.Timeout = cfg.Timeouts.Subfinder
	}

	// HTTP timeout
	if cfg.Timeouts.HTTP > 0 {
		out.ApplyHTTPTimeout(cfg.Timeouts.HTTP)
	}

	// DNS
	if cfg.Timeouts.DNS > 0 {
		out.DNS.Timeout = cfg.Timeouts.DNS
	}

	// URL
	if cfg.Timeouts.Gau > 0 {
		out.URLs.Timeout = cfg.Timeouts.Gau
	}

	// Nuclei
	out.ApplyNucleiConfig(
		selectNucleiSeverities(cfg, opts),
		cfg.Nuclei.BatchSize,
		cfg.Nuclei.Concurrency,
		cfg.Nuclei.Retries,
	)
	out.Nuclei.RateLimit = cfg.Scanning.RateLimit
	out.Nuclei.ExcludeTags = splitCSV(cfg.Nuclei.ExcludeTags)

	// Insecure
	out.Certificates.InsecureSkipVerify = cfg.Scanning.InsecureSkipVerify
	out.Takeover.InsecureSkipVerify = cfg.Scanning.InsecureSkipVerify
	out.Technologies.InsecureSkipVerify = cfg.Scanning.InsecureSkipVerify
	out.Cloud.InsecureSkipVerify = cfg.Scanning.InsecureSkipVerify

	return out
}

// selectNucleiSeverities picks the severity list from CLI or config.
func selectNucleiSeverities(cfg *config.Config, opts scanOptions) []string {
	if opts.nucleiSeveritySet {
		return opts.nucleiSeverities
	}
	return splitCSV(cfg.Scanning.NucleiSeverity)
}

// buildEnabledModules builds the enabled module map from CLI options.
func buildEnabledModules(cfg *config.Config, opts scanOptions) map[parallel.ModuleType]bool {
	enabled := make(map[parallel.ModuleType]bool)
	// Start with all enabled
	for _, m := range parallel.AllModules() {
		enabled[m] = true
	}
	// Nuclei disabled by default
	enabled[parallel.ModuleNuclei] = false

	// Enable nuclei if flag set
	if opts.enableNuclei {
		enabled[parallel.ModuleNuclei] = true
	}

	// Apply --skip/--only
	parallel.ApplyModuleSelection(enabled, opts.onlyModules, opts.skipModules)

	// Passive mode disables active modules
	if cfg.Scanning.PassiveOnly {
		parallel.ApplyPassiveMode(enabled)
	}

	return enabled
}

// applyModuleSelection enables/disables modules based on CLI options.
// Deprecated: use parallel.ApplyModuleSelection instead.
func applyModuleSelection(enabled map[parallel.ModuleType]bool, opts scanOptions) {
	if len(opts.onlyModules) > 0 {
		for k := range enabled {
			enabled[k] = false
		}
		for _, m := range opts.onlyModules {
			if mod, ok := parseModule(m); ok {
				enabled[mod] = true
			}
		}
		return
	}

	for _, m := range opts.skipModules {
		if mod, ok := parseModule(m); ok {
			enabled[mod] = false
		}
	}
}

// applyPassiveMode disables active scanning modules.
// Deprecated: use parallel.ApplyPassiveMode instead.
func applyPassiveMode(enabled map[parallel.ModuleType]bool) {
	parallel.ApplyPassiveMode(enabled)
}

func scanNotifier(cfg *config.Config, opts scanOptions) *notifier.Notifier {
	if cfg == nil {
		cfg = config.Default()
	}

	n := notifier.DefaultNotifier()
	n.SMTPHost = cfg.Notifications.Email.SMTPHost
	n.SMTPPort = cfg.Notifications.Email.SMTPPort
	n.SMTPUser = cfg.Notifications.Email.SMTPUser
	n.SMTPPassword = cfg.Notifications.Email.SMTPPassword
	n.EmailFrom = cfg.Notifications.Email.FromAddr
	if cfg.Timeouts.HTTP > 0 && n.HTTPClient != nil {
		n.HTTPClient.Timeout = cfg.Timeouts.HTTP
	}

	if opts.slackWebhookSet || opts.slackWebhook != "" {
		n.SlackWebhook = opts.slackWebhook
	} else if cfg.Notifications.Slack.Enabled {
		n.SlackWebhook = cfg.Notifications.Slack.WebhookURL
	}

	emailRecipient := ""
	if opts.emailRecipientSet || opts.emailRecipient != "" {
		emailRecipient = opts.emailRecipient
	} else if cfg.Notifications.Email.Enabled {
		emailRecipient = cfg.Notifications.Email.ToAddr
	}
	n.EmailTo = splitCSV(emailRecipient)

	return n
}

// persistScanResult writes scan findings and a diff snapshot. A nil database
// is a no-op so validation-only tests can call runFullScan without SQLite.
func persistScanResult(db *database.Database, result *parallel.ScanResult, scanType string) error {
	if db == nil || result == nil {
		return nil
	}
	store := persistence.NewStore(db)
	if err := store.EnsureDomain(result.Domain); err != nil {
		return fmt.Errorf("ensuring domain: %w", err)
	}
	if err := store.SaveAll(result); err != nil {
		return fmt.Errorf("persisting findings: %w", err)
	}
	if err := store.SaveSnapshot(result, scanType); err != nil {
		return fmt.Errorf("saving snapshot: %w", err)
	}
	return nil
}

func splitCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseModule(name string) (parallel.ModuleType, bool) {
	switch strings.ToLower(name) {
	case "subdomains", "subdomain":
		return parallel.ModuleSubdomains, true
	case "ports", "port":
		return parallel.ModulePorts, true
	case "certificates", "certificate", "certs", "cert":
		return parallel.ModuleCertificates, true
	case "dns":
		return parallel.ModuleDNS, true
	case "takeover", "takeovers":
		return parallel.ModuleTakeover, true
	case "technologies", "technology", "tech", "fingerprint":
		return parallel.ModuleTechnologies, true
	case "urls", "url":
		return parallel.ModuleURLs, true
	case "apis", "api":
		return parallel.ModuleAPIs, true
	case "cloudstorage", "cloud", "buckets", "bucket":
		return parallel.ModuleCloudStorage, true
	case "nuclei", "vuln", "vulns", "vulnerability", "vulnerabilities":
		return parallel.ModuleNuclei, true
	default:
		return "", false
	}
}

func printScanSummary(result *parallel.ScanResult) {
	fmt.Printf("\n%s Scan Summary\n", titleStyle.Render("[*]"))

	// Asset counts
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Subdomains:", 20)), len(result.Subdomains))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Open Ports:", 20)), len(result.Ports))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Certificates:", 20)), len(result.Certificates))

	// Count technologies
	techCount := 0
	for _, t := range result.Technologies {
		techCount += len(t.Technologies)
	}
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Technologies:", 20)), techCount)

	// Count findings
	vulnTakeovers := 0
	for _, t := range result.Takeovers {
		if t.Vulnerable {
			vulnTakeovers++
		}
	}

	publicBuckets := 0
	for _, b := range result.CloudStorage {
		if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
			publicBuckets++
		}
	}

	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("URLs:", 20)), len(result.URLs))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("APIs:", 20)), len(result.APIs))
	fmt.Printf("  %s %d\n", labelStyle.Render(padRight("Cloud Buckets:", 20)), len(result.CloudStorage))

	// Count nuclei vulnerabilities by severity
	if len(result.Vulnerabilities) > 0 {
		criticalVulns, highVulns, mediumVulns := 0, 0, 0
		for _, v := range result.Vulnerabilities {
			switch strings.ToLower(v.Info.Severity) {
			case "critical":
				criticalVulns++
			case "high":
				highVulns++
			case "medium":
				mediumVulns++
			}
		}
		fmt.Printf("  %s %d (critical:%d, high:%d, medium:%d)\n",
			labelStyle.Render(padRight("Vulnerabilities:", 20)),
			len(result.Vulnerabilities), criticalVulns, highVulns, mediumVulns)
	}

	// Highlight critical findings
	if vulnTakeovers > 0 {
		fmt.Printf("\n  %s %d subdomain takeover vulnerabilities\n",
			criticalStyle.Render("[!]"),
			vulnTakeovers)
		for _, t := range result.Takeovers {
			if t.Vulnerable {
				fmt.Printf("      %s (%s - %s)\n", t.Subdomain, t.Service, t.Confidence)
			}
		}
	}

	if publicBuckets > 0 {
		fmt.Printf("\n  %s %d public cloud storage buckets\n",
			criticalStyle.Render("[!]"),
			publicBuckets)
		for _, b := range result.CloudStorage {
			if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
				fmt.Printf("      %s [%s] %s\n",
					strings.ToUpper(b.Provider),
					b.AccessLevel,
					b.BucketName)
			}
		}
	}

	// Show critical/high vulnerabilities from nuclei
	if len(result.Vulnerabilities) > 0 {
		var criticalFindings, highFindings []*nuclei.Finding
		for _, v := range result.Vulnerabilities {
			switch strings.ToLower(v.Info.Severity) {
			case "critical":
				criticalFindings = append(criticalFindings, v)
			case "high":
				highFindings = append(highFindings, v)
			}
		}

		if len(criticalFindings) > 0 {
			fmt.Printf("\n  %s Critical vulnerabilities:\n", criticalStyle.Render("[!]"))
			for _, v := range criticalFindings {
				fmt.Printf("      [%s] %s @ %s\n", v.TemplateID, v.Info.Name, v.Host)
			}
		}

		if len(highFindings) > 0 {
			fmt.Printf("\n  %s High severity vulnerabilities:\n", highStyle.Render("[!]"))
			limit := 10
			for i, v := range highFindings {
				if i >= limit {
					fmt.Printf("      ... and %d more\n", len(highFindings)-limit)
					break
				}
				fmt.Printf("      [%s] %s @ %s\n", v.TemplateID, v.Info.Name, v.Host)
			}
		}
	}

	// Show errors
	if len(result.Errors) > 0 {
		fmt.Printf("\n  %s Errors:\n", highStyle.Render("[!]"))
		for module, err := range result.Errors {
			fmt.Printf("      %s: %s\n", module, err)
		}
	}

	fmt.Printf("\n  %s %s\n", labelStyle.Render(padRight("Total Duration:", 20)),
		result.Duration.Round(time.Millisecond))
}
