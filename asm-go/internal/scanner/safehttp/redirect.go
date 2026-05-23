package safehttp

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ErrRedirectBlocked indicates a redirect target was rejected.
var ErrRedirectBlocked = fmt.Errorf("redirect blocked")

// NoFollow prevents the client from following HTTP redirects.
func NoFollow(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// SameHostRedirect allows up to maxRedirects when every hop stays on the original host
// and the redirect target is not a blocked address.
func SameHostRedirect(maxRedirects int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) == 0 {
			return nil
		}

		originalHost := via[0].URL.Hostname()
		targetHost := req.URL.Hostname()
		if !strings.EqualFold(originalHost, targetHost) {
			return fmt.Errorf("%w: cross-host redirect from %q to %q", ErrRedirectBlocked, originalHost, targetHost)
		}

		return validateRedirectHost(targetHost)
	}
}

func validateRedirectHost(host string) error {
	host = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(host, ".")))
	if host == "" {
		return fmt.Errorf("%w: empty redirect host", ErrRedirectBlocked)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("%w: localhost redirect blocked", ErrRedirectBlocked)
	}

	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("%w: redirect to %s blocked", ErrRedirectBlocked, ip)
		}
	}

	return nil
}

func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	return ip.Equal(net.IPv4(169, 254, 169, 254))
}
