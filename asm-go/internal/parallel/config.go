package parallel

import (
	"time"

	"github.com/asm-tool/asm-go/internal/scanner/apis"
	"github.com/asm-tool/asm-go/internal/scanner/certificates"
	"github.com/asm-tool/asm-go/internal/scanner/cloud"
	"github.com/asm-tool/asm-go/internal/scanner/dns"
	"github.com/asm-tool/asm-go/internal/scanner/nuclei"
	"github.com/asm-tool/asm-go/internal/scanner/ports"
	"github.com/asm-tool/asm-go/internal/scanner/subdomains"
	"github.com/asm-tool/asm-go/internal/scanner/takeover"
	"github.com/asm-tool/asm-go/internal/scanner/technologies"
	"github.com/asm-tool/asm-go/internal/scanner/urls"
)

// RunConfig holds all per-module configuration for a full scan.
// Each module owns its Config struct — the parallel package just carries
// them through.
type RunConfig struct {
	Subdomains   subdomains.Config
	Ports        ports.Config
	Certificates certificates.Config
	DNS          dns.Config
	Takeover     takeover.Config
	Technologies technologies.Config
	URLs         urls.Config
	APIs         apis.Config
	Cloud        cloud.Config
	Nuclei       nuclei.Config
}

// DefaultRunConfig returns a RunConfig with sensible defaults for all modules.
func DefaultRunConfig() RunConfig {
	return RunConfig{
		Subdomains: subdomains.DefaultConfig(),
		Ports:      ports.DefaultConfig(),
		Certificates: certificates.DefaultConfig(),
		DNS:        dns.DefaultConfig(),
		Takeover:   takeover.DefaultConfig(),
		Technologies: technologies.DefaultConfig(),
		URLs:       urls.DefaultConfig(),
		APIs:       apis.DefaultConfig(),
		Cloud:      cloud.DefaultConfig(),
		Nuclei:     nuclei.DefaultConfig(),
	}
}

// ApplyPortWorkers sets the port worker count and timeout.
func (c *RunConfig) ApplyPortWorkers(workers int, timeout time.Duration) {
	if workers > 0 {
		c.Ports.Workers = workers
	}
	if timeout > 0 {
		c.Ports.Timeout = timeout
	}
}

// ApplyHTTPTimeout sets the HTTP timeout for all HTTP-based modules.
func (c *RunConfig) ApplyHTTPTimeout(timeout time.Duration) {
	if timeout > 0 {
		c.Certificates.Timeout = timeout
		c.Takeover.Timeout = timeout
		c.Takeover.HTTPClientTimeout = timeout
		c.Technologies.Timeout = timeout
		c.Technologies.HTTPClientTimeout = timeout
	}
}

// ApplyRateLimit sets the rate limit for all passive HTTP sources.
func (c *RunConfig) ApplyRateLimit(rps int) {
	if rps > 0 {
		c.Subdomains.RateLimit = rps
		c.URLs.RateLimit = rps
	}
	c.Nuclei.RateLimit = rps
}

// ApplyNucleiConfig copies nuclei-specific settings from the runner-level
// fields into the Nuclei module config.
func (c *RunConfig) ApplyNucleiConfig(severities []string, bulkSize, concurrency, retries int) {
	if len(severities) > 0 {
		c.Nuclei.Severities = severities
	}
	if bulkSize > 0 {
		c.Nuclei.BulkSize = bulkSize
	}
	if concurrency > 0 {
		c.Nuclei.Concurrency = concurrency
	}
	if retries > 0 {
		c.Nuclei.Retries = retries
	}
}

// ApplyModuleSelection enables or disables modules.
func ApplyModuleSelection(enabled map[ModuleType]bool, only []string, skip []string) {
	// Start from everything enabled (if map is nil, enable all)
	if enabled == nil {
		enabled = make(map[ModuleType]bool)
		for _, m := range AllModules() {
			enabled[m] = true
		}
	}
	if len(only) > 0 {
		for k := range enabled {
			enabled[k] = false
		}
		for _, m := range only {
			if mod := ParseModule(m); mod != "" {
				enabled[mod] = true
			}
		}
	} else {
		for _, m := range skip {
			if mod := ParseModule(m); mod != "" {
				enabled[mod] = false
			}
		}
	}
}

// ApplyPassiveMode disables active scanning modules.
func ApplyPassiveMode(enabled map[ModuleType]bool) {
	for _, mod := range []ModuleType{
		ModulePorts,
		ModuleCertificates,
		ModuleTakeover,
		ModuleTechnologies,
		ModuleAPIs,
		ModuleCloudStorage,
		ModuleNuclei,
	} {
		enabled[mod] = false
	}
}

// AllModules returns every defined module type.
func AllModules() []ModuleType {
	return []ModuleType{
		ModuleSubdomains,
		ModulePorts,
		ModuleCertificates,
		ModuleDNS,
		ModuleTakeover,
		ModuleTechnologies,
		ModuleURLs,
		ModuleAPIs,
		ModuleCloudStorage,
		ModuleNuclei,
	}
}

// ParseModule converts a string to a ModuleType.
func ParseModule(name string) ModuleType {
	switch name {
	case "subdomains", "subdomain":
		return ModuleSubdomains
	case "ports", "port":
		return ModulePorts
	case "certificates", "certificate", "certs", "cert":
		return ModuleCertificates
	case "dns":
		return ModuleDNS
	case "takeover", "takeovers":
		return ModuleTakeover
	case "technologies", "technology", "tech", "fingerprint":
		return ModuleTechnologies
	case "urls", "url":
		return ModuleURLs
	case "apis", "api":
		return ModuleAPIs
	case "cloudstorage", "cloud", "buckets", "bucket":
		return ModuleCloudStorage
	case "nuclei", "vuln", "vulns", "vulnerability", "vulnerabilities":
		return ModuleNuclei
	default:
		return ""
	}
}