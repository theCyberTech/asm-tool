package notifier

import (
	"strings"
	"testing"

	"github.com/asm-tool/asm-go/internal/parallel"
)

func TestIsLocalSMTPHost(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"localhost":                 true,
		"LOCALHOST":                 true,
		"127.0.0.1":                 true,
		"::1":                       true,
		"0:0:0:0:0:0:0:1":           true,
		"smtp.example.com":          false,
		"mail.internal.example.com": false,
	}

	for host, want := range cases {
		if got := isLocalSMTPHost(host); got != want {
			t.Fatalf("isLocalSMTPHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestNotifyEmailRejectsPlaintextRemoteHost(t *testing.T) {
	n := DefaultNotifier()
	n.UseTLS = false
	n.SMTPHost = "smtp.example.com"
	n.SMTPPort = 587
	n.EmailFrom = "asm@example.com"
	n.EmailTo = []string{"ops@example.com"}

	err := n.NotifyEmail(&parallel.ScanResult{Domain: "example.com"})
	if err == nil {
		t.Fatal("NotifyEmail() expected error for remote plaintext SMTP")
	}
	if !strings.Contains(err.Error(), "plaintext SMTP is only supported for localhost") {
		t.Fatalf("NotifyEmail() error = %v, want localhost-only plaintext error", err)
	}
}

func TestNotifyEmailAllowsPlaintextLocalhost(t *testing.T) {
	n := DefaultNotifier()
	n.UseTLS = false
	n.SMTPHost = "127.0.0.1"
	n.SMTPPort = 1 // closed port; we only care that localhost passes the gate
	n.EmailFrom = "asm@example.com"
	n.EmailTo = []string{"ops@example.com"}

	err := n.NotifyEmail(&parallel.ScanResult{Domain: "example.com"})
	if err == nil {
		t.Fatal("NotifyEmail() expected send failure after passing localhost gate")
	}
	if strings.Contains(err.Error(), "plaintext SMTP is only supported for localhost") {
		t.Fatalf("NotifyEmail() error = %v, did not expect localhost gate rejection", err)
	}
}
