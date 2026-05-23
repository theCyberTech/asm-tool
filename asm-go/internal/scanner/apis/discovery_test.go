package apis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoverLimitsPathConcurrency(t *testing.T) {
	var active int32
	var maxActive int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&active, 1)
		defer atomic.AddInt32(&active, -1)

		for {
			prev := atomic.LoadInt32(&maxActive)
			if current <= prev || atomic.CompareAndSwapInt32(&maxActive, prev, current) {
				break
			}
		}

		time.Sleep(25 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	host := server.Listener.Addr().String()
	d := DefaultDiscovery()
	d.Paths = make([]string, 40)
	for i := range d.Paths {
		d.Paths[i] = "/path-" + string(rune('a'+i%26))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := d.Discover(ctx, host)
	if result.Error != "" {
		t.Fatalf("Discover() error = %q", result.Error)
	}
	if got := atomic.LoadInt32(&maxActive); got > 10 {
		t.Fatalf("max concurrent path checks = %d, want <= 10", got)
	}
}

func TestDiscoverBatchLimitsHostConcurrency(t *testing.T) {
	var active int32
	var maxActive int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&active, 1)
		defer atomic.AddInt32(&active, -1)

		for {
			prev := atomic.LoadInt32(&maxActive)
			if current <= prev || atomic.CompareAndSwapInt32(&maxActive, prev, current) {
				break
			}
		}

		time.Sleep(25 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	host := server.Listener.Addr().String()
	d := DefaultDiscovery()
	d.Workers = 3
	d.Paths = []string{"/health"}

	hosts := make([]string, 12)
	for i := range hosts {
		hosts[i] = host
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	batch := d.DiscoverBatch(ctx, hosts)
	if got := atomic.LoadInt32(&maxActive); got > 3 {
		t.Fatalf("max concurrent host scans = %d, want <= 3", got)
	}
	if len(batch.Results) != len(hosts) {
		t.Fatalf("DiscoverBatch() returned %d results, want %d", len(batch.Results), len(hosts))
	}
}
