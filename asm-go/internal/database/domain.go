package database

import (
	"net"
	"net/url"
	"strings"
)

func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return s
}

// HostBelongsToDomain reports whether host is the apex domain or a subdomain of it.
func HostBelongsToDomain(host, domain string) bool {
	host = normalizeHost(host)
	domain = normalizeHost(domain)
	if host == "" || domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// URLBelongsToDomain reports whether a URL's hostname belongs to domain.
func URLBelongsToDomain(raw, domain string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if !strings.Contains(raw, "://") {
		return HostBelongsToDomain(raw, domain)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return HostBelongsToDomain(u.Hostname(), domain)
}

func domainMatchClause(column string) string {
	return "(" + column + " = ? OR " + column + " LIKE ? ESCAPE '\\')"
}

func domainMatchArgs(domain string) []any {
	return []any{domain, "%." + escapeLikePattern(domain)}
}

func sqlHostMatchesDomainColumn(hostCol, domainCol string) string {
	escaped := "REPLACE(REPLACE(REPLACE(" + domainCol + ", '\\', '\\\\'), '%', '\\%'), '_', '\\_')"
	return "(" + hostCol + " = " + domainCol + " OR " + hostCol + " LIKE '%.' || " + escaped + " ESCAPE '\\')"
}

func filterURLsByDomain(urls []URL, domain string) []URL {
	out := make([]URL, 0, len(urls))
	for _, u := range urls {
		if HostBelongsToDomain(u.Domain, domain) || URLBelongsToDomain(u.URL, domain) {
			out = append(out, u)
		}
	}
	return out
}

func filterAPIsByDomain(apis []API, domain string) []API {
	out := make([]API, 0, len(apis))
	for _, a := range apis {
		if URLBelongsToDomain(a.URL, domain) {
			out = append(out, a)
		}
	}
	return out
}
