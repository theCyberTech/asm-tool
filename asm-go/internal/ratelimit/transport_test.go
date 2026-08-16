package ratelimit

import (
	"net/http"
	"testing"
)

func TestTransport_CloseIdempotent(t *testing.T) {
	rt := NewTransport(http.DefaultTransport, 10)
	tr, ok := rt.(*Transport)
	if !ok {
		t.Fatal("NewTransport(rps>0) should return *Transport")
	}

	tr.Close()
	tr.Close() // must not panic

	Close(rt)
	Close(nil)
	Close(http.DefaultTransport)

	var nilT *Transport
	nilT.Close() // must not panic
}

func TestNewTransport_UnlimitedPassthrough(t *testing.T) {
	inner := http.DefaultTransport
	if got := NewTransport(inner, 0); got != inner {
		t.Fatal("NewTransport(rps<=0) should return inner unchanged")
	}
	if got := NewTransport(inner, -1); got != inner {
		t.Fatal("NewTransport(rps<=0) should return inner unchanged")
	}
}
