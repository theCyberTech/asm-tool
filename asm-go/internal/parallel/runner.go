// Package parallel orchestrates concurrent execution of scanner modules.
// It is pure orchestration: goroutine fan-out, timing, error collection.
// All scanning logic lives in the individual scanner modules.
package parallel

import (
	"context"
	"sync"
	"time"

	"github.com/asm-tool/asm-go/internal/scanner/apis"
	"github.com/asm-tool/asm-go/internal/scanner/certificates"
	"github.com/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/asm-tool/asm-go/internal/scanner/dns"
	"github.com/asm-tool/asm-go/internal/scanner/emails"
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/asm-tool/asm-go/internal/scanner/ports"
	"github.com/asm-tool/asm-go/internal/scanner/subdomains"
	"github.com/asm-tool/asm-go/internal/scanner/takeover"
	"github.com/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/asm-tool/asm-go/internal/scanner/urls"
)

// ModuleType identifies a scanner module.
type ModuleType string

const (
	ModuleSubdomains    ModuleType = "subdomains"
	ModulePorts         ModuleType = "ports"
	ModuleCertificates  ModuleType = "certificates"
	ModuleDNS           ModuleType = "dns"
	ModuleTakeover      ModuleType = "takeover"
	ModuleTechnologies  ModuleType = "technologies"
	ModuleURLs          ModuleType = "urls"
	ModuleAPIs          ModuleType = "apis"
	ModuleEmails        ModuleType = "emails"
	ModuleCloudStorage  ModuleType = "cloudstorage"
	ModuleNuclei        ModuleType = "nuclei"
)

// ProgressCallback is called when a module completes.
type ProgressCallback func(module ModuleType, duration time.Duration, err error)

// ScanResult holds the complete scan results using scanner-specific types.
// Each field uses the output type of the corresponding scanner module.
type ScanResult struct {
	Domain          string
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	Subdomains      []string
	Ports           []*ports.Result
	Certificates    []*certificates.Certificate
	DNSRecords      []dns.Result
	Takeovers       []takeover.Finding
	Technologies    []*technologies.Result
	URLs            []urls.URL
	APIs            []apis.API
	Emails          []emails.Email
	CloudStorage    []cloud.Bucket
	Vulnerabilities []*nuclei.Finding
	Errors          map[ModuleType]error
}

// Runner is the scan orchestrator. It has no configuration state; all config
// comes through RunConfig passed to Run().
type Runner struct{}

// Run executes a full scan for the given domain using the provided
// configuration. It returns a ScanResult with per-module errors in
// result.Errors. Progress callbacks are invoked as each module completes.
func (r *Runner) Run(ctx context.Context, domain string, cfg RunConfig, enabled map[ModuleType]bool, progress ProgressCallback) *ScanResult {
	result := &ScanResult{
		Domain:    domain,
		StartTime: time.Now(),
		Errors:    make(map[ModuleType]error),
	}

	// URLs, emails, and cloud modules read the domain from cfg.Subdomains.Domain.
	applyRunDomain(&cfg, domain)

	// Phase 1: Subdomain enumeration (sequential — results feed Phase 2).
	if enabled[ModuleSubdomains] {
		runSubdomains(ctx, domain, cfg.Subdomains, progress, ModuleSubdomains, result)
	}

	// Check context after Phase 1.
	if err := ctx.Err(); err != nil {
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	// If no subdomains found, scan the domain itself.
	hosts := result.Subdomains
	if len(hosts) == 0 {
		hosts = []string{domain}
	}

	// Phase 2: Independent modules in parallel.
	var wg sync.WaitGroup
	var mu sync.Mutex

	enabledModules := enabledModules(enabled)

	for _, mod := range enabledModules {
		wg.Add(1)
		go func(m ModuleType) {
			defer wg.Done()
			start := time.Now()
			err := runModule(ctx, m, cfg, hosts, result)
			duration := time.Since(start)
			mu.Lock()
			if err != nil {
				result.Errors[m] = err
			}
			mu.Unlock()
			if progress != nil {
				progress(m, duration, err)
			}
		}(mod)
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result
}

// applyRunDomain copies the scan target onto RunConfig so modules that
// read cfg.Subdomains.Domain (urls, emails, cloud) receive the domain.
func applyRunDomain(cfg *RunConfig, domain string) {
	if cfg == nil {
		return
	}
	cfg.Subdomains.Domain = domain
}

// enabledModules returns the list of enabled module types in a stable order.
func enabledModules(enabled map[ModuleType]bool) []ModuleType {
	var mods []ModuleType
	// Fixed order for deterministic progress output.
	for _, m := range []ModuleType{
		ModulePorts,
		ModuleCertificates,
		ModuleDNS,
		ModuleTakeover,
		ModuleTechnologies,
		ModuleURLs,
		ModuleAPIs,
		ModuleEmails,
		ModuleCloudStorage,
		ModuleNuclei,
	} {
		if enabled[m] {
			mods = append(mods, m)
		}
	}
	return mods
}

// runModule dispatches to the correct scanner module.
func runModule(ctx context.Context, mod ModuleType, cfg RunConfig, hosts []string, result *ScanResult) error {
	switch mod {
	case ModulePorts:
		r := ports.Scan(ctx, cfg.Ports, hosts)
		result.Ports = r.Results
		return r.Err
	case ModuleCertificates:
		r := certificates.Scan(ctx, cfg.Certificates, hosts)
		result.Certificates = r.Certificates
		return r.Err
	case ModuleDNS:
		records, err := dns.Scan(ctx, cfg.DNS, hosts)
		if err != nil {
			return err
		}
		result.DNSRecords = records
		return nil
	case ModuleTakeover:
		r := takeover.Scan(ctx, cfg.Takeover, hosts)
		result.Takeovers = r.Findings
		return r.Err
	case ModuleTechnologies:
		results := technologies.Scan(ctx, cfg.Technologies, hosts)
		result.Technologies = results
		return nil
	case ModuleURLs:
		r := urls.Scan(ctx, cfg.URLs, cfg.Subdomains.Domain)
		result.URLs = r.URLs
		return r.Err
	case ModuleAPIs:
		r := apis.Scan(ctx, cfg.APIs, hosts)
		result.APIs = r.APIs
		return r.Err
	case ModuleEmails:
		r := emails.Scan(ctx, cfg.Emails, cfg.Subdomains.Domain)
		result.Emails = r.Emails
		return r.Err
	case ModuleCloudStorage:
		r := cloud.Scan(ctx, cfg.Cloud, cfg.Subdomains.Domain)
		result.CloudStorage = r.Buckets
		return r.Err
	case ModuleNuclei:
		results, err := nuclei.Scan(ctx, cfg.Nuclei, hosts)
		if err != nil {
			return err
		}
		result.Vulnerabilities = results
		return nil
	default:
		return nil
	}
}

// runSubdomains runs the subdomain enumeration module and records
// results on the provided ScanResult. It returns the subdomain list.
func runSubdomains(ctx context.Context, domain string, cfg subdomains.Config, progress ProgressCallback, mod ModuleType, result *ScanResult) []string {
	if progress != nil {
		progress(mod, 0, nil)
	}
	start := time.Now()
	sr := subdomains.Scan(ctx, cfg, domain)
	duration := time.Since(start)
	result.Subdomains = sr.Subdomains
	if sr.Err != nil {
		result.Errors[mod] = sr.Err
	}
	if progress != nil {
		progress(mod, duration, sr.Err)
	}
	return sr.Subdomains
}