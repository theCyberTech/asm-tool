package target

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	maxDomainLength       = 253
	maxFilenamePartLength = 120
)

var (
	domainRegex          = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	filenameUnsafeRegex  = regexp.MustCompile(`[^a-z0-9._-]+`)
	filenameCollapseDash = regexp.MustCompile(`[-_]{2,}`)
)

// NormalizeTarget converts a user-supplied target into the canonical domain
// form used by scanners and rejects values that are not plain DNS names.
func NormalizeTarget(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		return "", fmt.Errorf("target domain is required")
	}
	if len(domain) > maxDomainLength {
		return "", fmt.Errorf("target domain is too long")
	}
	if !domainRegex.MatchString(domain) {
		return "", fmt.Errorf("invalid target domain %q", raw)
	}

	return domain, nil
}

// ValidateDomain reports whether raw can be normalized to a valid DNS domain.
func ValidateDomain(raw string) bool {
	_, err := NormalizeTarget(raw)
	return err == nil
}

// NormalizeSubdomain returns a canonical hostname only when it belongs to domain.
func NormalizeSubdomain(raw, domain string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}

	normalizedDomain, err := NormalizeTarget(domain)
	if err != nil {
		return ""
	}
	normalizedHost, err := NormalizeTarget(host)
	if err != nil {
		return ""
	}
	if !IsSubdomainOf(normalizedHost, normalizedDomain) {
		return ""
	}

	return normalizedHost
}

// IsSubdomainOf enforces a label boundary between host and domain.
func IsSubdomainOf(host, domain string) bool {
	normalizedHost, err := NormalizeTarget(host)
	if err != nil {
		return false
	}
	normalizedDomain, err := NormalizeTarget(domain)
	if err != nil {
		return false
	}

	return normalizedHost == normalizedDomain || strings.HasSuffix(normalizedHost, "."+normalizedDomain)
}

// SafeFilenamePart converts untrusted domain text into a single path segment.
func SafeFilenamePart(raw string) string {
	if normalized, err := NormalizeTarget(raw); err == nil {
		return normalized
	}

	part := strings.ToLower(strings.TrimSpace(raw))
	part = strings.TrimSuffix(part, ".")
	part = filenameUnsafeRegex.ReplaceAllString(part, "-")
	part = filenameCollapseDash.ReplaceAllString(part, "-")
	part = strings.Trim(part, ".-_")

	if len(part) > maxFilenamePartLength {
		part = strings.Trim(part[:maxFilenamePartLength], ".-_")
	}
	if part == "" {
		return "scan"
	}

	return part
}
