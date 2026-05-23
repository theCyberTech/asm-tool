package safehttp

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestValidateRedirectHostBlocksPrivateAndMetadataIPs(t *testing.T) {
	t.Parallel()

	blocked := []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "localhost"}
	for _, host := range blocked {
		if err := validateRedirectHost(host); err == nil {
			t.Fatalf("validateRedirectHost(%q) expected error", host)
		}
	}

	if err := validateRedirectHost("api.example.com"); err != nil {
		t.Fatalf("validateRedirectHost(example.com) error = %v", err)
	}
}

func TestSameHostRedirectBlocksCrossHost(t *testing.T) {
	check := SameHostRedirect(2)
	req := &http.Request{URL: mustParseURL("https://evil.com/path")}
	via := []*http.Request{{URL: mustParseURL("https://example.com/start")}}

	err := check(req, via)
	if err == nil {
		t.Fatal("expected cross-host redirect to be blocked")
	}
	if !strings.Contains(err.Error(), "cross-host redirect") {
		t.Fatalf("error = %v, want cross-host redirect", err)
	}
}

func TestSameHostRedirectBlocksPrivateTarget(t *testing.T) {
	check := SameHostRedirect(2)
	req := &http.Request{URL: mustParseURL("https://127.0.0.1/admin")}
	via := []*http.Request{{URL: mustParseURL("https://127.0.0.1/start")}}

	if err := check(req, via); err == nil {
		t.Fatal("expected private redirect target to be blocked")
	}
}

func TestNoFollowStopsRedirects(t *testing.T) {
	if err := NoFollow(nil, []*http.Request{{URL: mustParseURL("https://example.com")}}); err != http.ErrUseLastResponse {
		t.Fatalf("NoFollow() = %v, want ErrUseLastResponse", err)
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
