// Package ratelimit provides a rate-limiting http.RoundTripper.
package ratelimit

import (
	"net/http"
	"sync"
	"time"
)

// Transport is an http.RoundTripper that enforces a maximum outbound request
// rate. It uses a time.Ticker as a token source: each tick allows one request.
// If rps is 0, no limiting is applied.
//
// Call Close when the transport is no longer needed to stop the ticker.
// After Close, RoundTrip skips the rate-limit wait and forwards the request.
type Transport struct {
	inner  http.RoundTripper
	mu     sync.Mutex
	ticker *time.Ticker
}

// NewTransport wraps inner with a rate limiter capped at rps requests per
// second. If rps <= 0, inner is returned unchanged.
func NewTransport(inner http.RoundTripper, rps int) http.RoundTripper {
	if rps <= 0 {
		return inner
	}
	return &Transport{
		inner:  inner,
		ticker: time.NewTicker(time.Second / time.Duration(rps)),
	}
}

// Close stops the rate-limiter ticker. It is safe to call on a nil Transport
// and is idempotent.
func (t *Transport) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ticker != nil {
		t.ticker.Stop()
		t.ticker = nil
	}
}

// Close stops rt if it implements Close (for example a rate-limiting
// Transport). It is a no-op for nil or non-closer round trippers.
//
// Callers that hold an *http.Client may type-assert Client.Transport or pass
// it here:
//
//	ratelimit.Close(client.Transport)
func Close(rt http.RoundTripper) {
	type closer interface{ Close() }
	if c, ok := rt.(closer); ok {
		c.Close()
	}
}

// RoundTrip waits for a token before forwarding the request. If the request's
// context is cancelled while waiting, the context error is returned immediately.
// After Close, the wait is skipped.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	ticker := t.ticker
	t.mu.Unlock()

	if ticker != nil {
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-ticker.C:
		}
	}
	return t.inner.RoundTrip(req)
}
