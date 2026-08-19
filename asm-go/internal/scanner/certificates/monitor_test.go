package certificates

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestScanDefaultsWorkers(t *testing.T) {
	result := Scan(context.Background(), Config{Workers: -1, Timeout: time.Second}, nil)
	if result == nil {
		t.Fatal("Scan returned nil")
	}
}

func TestCheckReadsExpiredCertificate(t *testing.T) {
	addr, closeFn := serveTLSCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired.example"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		DNSNames:     []string{"127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	defer closeFn()

	host, port := splitAddr(t, addr)
	mon := DefaultMonitor()
	mon.Timeout = 2 * time.Second
	cert := mon.Check(context.Background(), host, port)
	if cert.Fingerprint == "" {
		t.Fatalf("expected certificate metadata, got error %q", cert.Error)
	}
	if !cert.IsExpired {
		t.Fatal("expected expired certificate")
	}
	if cert.Error == "" {
		t.Fatal("expected verification error for expired/untrusted cert")
	}
}

func TestCheckValidSelfSignedWithInsecureSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, port := splitAddr(t, srv.Listener.Addr().String())
	mon := DefaultMonitor()
	mon.Timeout = 2 * time.Second
	mon.InsecureSkipVerify = true
	cert := mon.Check(context.Background(), host, port)
	if cert.Error != "" {
		t.Fatalf("Check error = %q", cert.Error)
	}
	if cert.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
}

func TestCheckBatchOnCustomPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, port := splitAddr(t, srv.Listener.Addr().String())
	mon := Monitor{Workers: 1, Timeout: 2 * time.Second, InsecureSkipVerify: true}
	result := mon.CheckBatch(context.Background(), []string{host}, port)
	if len(result.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(result.Certificates))
	}
}

func serveTLSCert(t *testing.T, tmpl *x509.Certificate) (string, func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port
}
