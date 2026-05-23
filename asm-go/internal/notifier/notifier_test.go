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


func TestValidateSlackWebhookURL(t *testing.T) {
	t.Parallel()

	valid := "https://hooks.slack.com/services/T000/B000/XXXX"
	got, err := validateSlackWebhookURL(valid)
	if err != nil {
		t.Fatalf("validateSlackWebhookURL() error = %v", err)
	}
	if got != valid {
		t.Fatalf("validateSlackWebhookURL() = %q, want %q", got, valid)
	}

	cases := []string{
		"http://hooks.slack.com/services/T000/B000/XXXX",
		"https://evil.com/hooks.slack.com/services/T000/B000/XXXX",
		"https://hooks.slack.com.evil.com/services/T000/B000/XXXX",
		"https://hooks.slack.com/",
		"https://example.com/webhook",
	}
	for _, raw := range cases {
		if _, err := validateSlackWebhookURL(raw); err == nil {
			t.Fatalf("validateSlackWebhookURL(%q) expected error", raw)
		}
	}
}

func TestNotifySlackRejectsUntrustedWebhookURL(t *testing.T) {
	n := DefaultNotifier()
	n.SlackWebhook = "https://example.com/exfil"

	err := n.NotifySlack(&parallel.ScanResult{Domain: "example.com"})
	if err == nil {
		t.Fatal("NotifySlack() expected error for untrusted webhook URL")
	}
	if !strings.Contains(err.Error(), "hooks.slack.com") {
		t.Fatalf("NotifySlack() error = %v, want hooks.slack.com validation error", err)
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
