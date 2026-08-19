// Package httpclient provides shared HTTP client construction with common
// defaults (connection pooling, TLS, rate limiting, redirect policy).
//
// Use this instead of constructing http.Client or http.Transport inline in
// scanner modules so transport settings are consistent and tunable from one
// place.
package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/theCyberTech/asm-tool/asm-go/internal/ratelimit"
)

// DefaultUserAgent is the User-Agent header sent by scanner modules.
const DefaultUserAgent = "ASM-Tool/2.0"

// Options configures the HTTP client returned by New.
type Options struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
	MaxRedirects       int // <=0 means ErrUseLastResponse on first redirect
	RateLimit          int // requests per second, 0 = unlimited
}

// New builds an *http.Client with consistent defaults:
//
//   - IdleConnTimeout: 90s
//   - MaxIdleConns: 100
//   - MaxIdleConnsPerHost: 10
//   - TLS InsecureSkipVerify when requested
//   - Rate limiting when requested
//   - Redirect handler: ErrUseLastResponse after MaxRedirects hops (or first hop when <=0)
func New(opts Options) *http.Client {
	transport := newTransport(opts)

	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if opts.MaxRedirects <= 0 || len(via) >= opts.MaxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}

	return client
}

func newTransport(opts Options) http.RoundTripper {
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if opts.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	if opts.RateLimit > 0 {
		return ratelimit.NewTransport(tr, opts.RateLimit)
	}

	return tr
}
