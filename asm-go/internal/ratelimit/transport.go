// Package ratelimit provides a rate-limiting http.RoundTripper.
package ratelimit

import (
	"net/http"
	"time"
)

// Transport is an http.RoundTripper that enforces a maximum outbound request
// rate. It uses a time.Ticker as a token source: each tick allows one request.
// If rps is 0, no limiting is applied.
type Transport struct {
	inner  http.RoundTripper
	tokens <-chan time.Time
}

// NewTransport wraps inner with a rate limiter capped at rps requests per
// second. If rps <= 0, inner is returned unchanged.
func NewTransport(inner http.RoundTripper, rps int) http.RoundTripper {
	if rps <= 0 {
		return inner
	}
	return &Transport{
		inner:  inner,
		tokens: time.NewTicker(time.Second / time.Duration(rps)).C,
	}
}

// RoundTrip waits for a token before forwarding the request. If the request's
// context is cancelled while waiting, the context error is returned immediately.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-t.tokens:
	}
	return t.inner.RoundTrip(req)
}
