package commands

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/asm-tool/asm-go/internal/database"
	"github.com/asm-tool/asm-go/internal/target"
)

func errNoInScopeTargets() error {
	return fmt.Errorf("no in-scope targets to scan (allowed root: %s)", target.AllowedRootDomain)
}

func normalizeDomainList(domains []string) ([]string, error) {
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		canonical, err := target.NormalizeScanTarget(domain)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

func resolveScanDomains(db *database.Database, args []string, allKnown bool) ([]string, error) {
	if len(args) > 0 {
		normalized, err := target.NormalizeScanTarget(args[0])
		if err != nil {
			return nil, err
		}
		return []string{normalized}, nil
	}
	if !allKnown {
		return nil, fmt.Errorf("specify a domain or use --all-known")
	}
	return listAllowedKnownDomains(db)
}

func resolveScanHosts(db *database.Database, args []string, allKnown bool) ([]string, error) {
	var hosts []string
	var domain string
	if len(args) > 0 {
		normalized, err := target.NormalizeScanTarget(args[0])
		if err != nil {
			return nil, err
		}
		domain = normalized
		subs, err := db.Domains.GetSubdomainsByDomainName(normalized)
		if err == nil && len(subs) > 0 {
			filtered := target.FilterAllowedScanTargets(subs)
			if len(filtered) > 0 {
				hosts = filtered
			} else {
				hosts = []string{normalized}
			}
		} else {
			hosts = []string{normalized}
		}
	} else {
		if !allKnown {
			return nil, fmt.Errorf("specify a target or use --all-known")
		}
		var err error
		hosts, err = listAllowedKnownHosts(db)
		if err != nil {
			return nil, err
		}
		domain = target.AllowedRootDomain
	}
	return target.CapScanHosts(domain, hosts), nil
}

func resolveNucleiScanTargets(db *database.Database, args []string, allKnown bool) ([]string, error) {
	if len(args) > 0 {
		out := make([]string, 0, len(args))
		seen := make(map[string]struct{}, len(args))
		for _, raw := range args {
			normalized, err := normalizeNucleiScanTarget(raw)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			out = append(out, normalized)
		}
		return target.CapScanHosts(target.AllowedRootDomain, out), nil
	}
	if !allKnown {
		return nil, fmt.Errorf("specify targets or use --all-known")
	}
	hosts, err := listAllowedKnownHosts(db)
	if err != nil {
		return nil, err
	}
	return target.CapScanHosts(target.AllowedRootDomain, hosts), nil
}

func normalizeNucleiScanTarget(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		u, err := url.Parse(trimmed)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("invalid target domain %q", raw)
		}
		if _, err := target.NormalizeScanTarget(u.Hostname()); err != nil {
			return "", err
		}
		return trimmed, nil
	}
	return target.NormalizeScanTarget(raw)
}

func listAllowedKnownDomains(db *database.Database) ([]string, error) {
	dbDomains, err := db.Domains.List()
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	raw := make([]string, 0, len(dbDomains))
	for _, d := range dbDomains {
		raw = append(raw, d.Domain)
	}
	filtered := target.FilterAllowedScanTargets(raw)
	if len(filtered) == 0 && len(raw) > 0 {
		return nil, errNoInScopeTargets()
	}
	return filtered, nil
}

func listAllowedKnownHosts(db *database.Database) ([]string, error) {
	dbDomains, err := db.Domains.List()
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	raw := make([]string, 0, len(dbDomains))
	for _, d := range dbDomains {
		raw = append(raw, d.Domain)
	}
	allowed := target.FilterAllowedScanTargets(raw)
	if len(allowed) == 0 && len(raw) > 0 {
		return nil, errNoInScopeTargets()
	}
	var hosts []string
	for _, domain := range allowed {
		subs, _ := db.Domains.GetSubdomainsByDomainName(domain)
		hosts = append(hosts, subs...)
	}
	return target.FilterAllowedScanTargets(hosts), nil
}
