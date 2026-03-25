package ports

import (
	"testing"
)

func TestGuessService(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{5432, "postgresql"},
		{6379, "redis"},
		{27017, "mongodb"},
		{9999, "unknown"},
	}

	for _, tt := range tests {
		got := guessService(tt.port)
		if got != tt.want {
			t.Errorf("guessService(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		banner  string
		service string
		want    string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "ssh", "SSH-2.0-OpenSSH_8.9p1"},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n", "http", "nginx/1.18.0"},
		{"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n", "https", "Apache/2.4.54"},
		{"220 vsFTPd 3.0.3\r\n", "ftp", "vsFTPd 3.0.3"},
		{"220 mail.example.com ESMTP Postfix\r\n", "smtp", "mail.example.com ESMTP Postfix"},
		{"+OK Dovecot ready.", "pop3", "Dovecot ready."},
		{"* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "imap", "[CAPABILITY IMAP4rev1] Dovecot ready."},
		{"just some random banner", "ssh", ""},
	}

	for _, tt := range tests {
		got := extractVersion(tt.banner, tt.service)
		if got != tt.want {
			t.Errorf("extractVersion(%q, %q) = %q, want %q", tt.banner, tt.service, got, tt.want)
		}
	}
}

func TestIsTLSPort(t *testing.T) {
	tlsPorts := []int{443, 8443, 465, 636, 993, 995}
	for _, p := range tlsPorts {
		if !isTLSPort(p) {
			t.Errorf("isTLSPort(%d) = false, want true", p)
		}
	}
	plainPorts := []int{80, 22, 25, 8080, 3306}
	for _, p := range plainPorts {
		if isTLSPort(p) {
			t.Errorf("isTLSPort(%d) = true, want false", p)
		}
	}
}

func TestPortRange(t *testing.T) {
	ports := PortRange(80, 85)
	want := []int{80, 81, 82, 83, 84, 85}
	if len(ports) != len(want) {
		t.Fatalf("PortRange(80, 85) length = %d, want %d", len(ports), len(want))
	}
	for i, p := range ports {
		if p != want[i] {
			t.Errorf("PortRange(80, 85)[%d] = %d, want %d", i, p, want[i])
		}
	}
}

func TestPortRange_Invalid(t *testing.T) {
	if PortRange(85, 80) != nil {
		t.Error("PortRange with start > end should return nil")
	}
	if PortRange(0, 80) != nil {
		t.Error("PortRange with start < 1 should return nil")
	}
}

func TestCommonPorts(t *testing.T) {
	ports := CommonPorts()
	if len(ports) == 0 {
		t.Error("CommonPorts should not be empty")
	}
	// Must include key ports
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}
	for _, required := range []int{22, 80, 443, 3306, 5432} {
		if !portSet[required] {
			t.Errorf("CommonPorts missing port %d", required)
		}
	}
}
