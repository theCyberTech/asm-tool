package notifier

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/asm-tool/asm-go/internal/httpclient"
	"github.com/asm-tool/asm-go/internal/parallel"
)

// Notifier sends notifications about scan results
type Notifier struct {
	SlackWebhook string
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	EmailFrom    string
	EmailTo      []string
	HTTPClient   *http.Client
	UseTLS       bool // Use TLS for SMTP connection (recommended for security)
}

// DefaultNotifier creates a notifier with default HTTP client and TLS enabled
func DefaultNotifier() *Notifier {
	return &Notifier{
		HTTPClient: httpclient.New(httpclient.Options{
			Timeout:      10 * time.Second,
			MaxRedirects: 2,
		}),
		UseTLS: true, // Enable TLS by default for secure credential transmission
	}
}

func (n *Notifier) smtpAuth() smtp.Auth {
	if n.SMTPUser == "" || n.SMTPPassword == "" {
		return nil
	}
	return smtp.PlainAuth("", n.SMTPUser, n.SMTPPassword, n.SMTPHost)
}

// NotifySlack sends a scan summary to Slack
func (n *Notifier) NotifySlack(result *parallel.ScanResult) error {
	if n.SlackWebhook == "" {
		return fmt.Errorf("slack webhook not configured")
	}

	message := n.buildSlackMessage(result)

	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshaling slack payload: %w", err)
	}

	resp, err := n.HTTPClient.Post(n.SlackWebhook, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("posting to slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

// SlackMessage represents a Slack webhook payload
type SlackMessage struct {
	Text        string       `json:"text,omitempty"`
	Blocks      []SlackBlock `json:"blocks,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackBlock struct {
	Type     string          `json:"type"`
	Text     *SlackText      `json:"text,omitempty"`
	Fields   []SlackText     `json:"fields,omitempty"`
	Elements []SlackElement  `json:"elements,omitempty"`
}

type SlackText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

type SlackElement struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type SlackAttachment struct {
	Color  string       `json:"color"`
	Blocks []SlackBlock `json:"blocks,omitempty"`
}

func (n *Notifier) buildSlackMessage(result *parallel.ScanResult) SlackMessage {
	// Count findings
	vulnTakeovers := 0
	for _, t := range result.Takeovers {
		if t.Vulnerable {
			vulnTakeovers++
		}
	}

	publicBuckets := 0
	for _, b := range result.CloudStorage {
		if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
			publicBuckets++
		}
	}

	techCount := 0
	for _, t := range result.Technologies {
		techCount += len(t.Technologies)
	}

	// Determine alert color
	color := "#36a64f" // green
	if vulnTakeovers > 0 || publicBuckets > 0 {
		color = "#dc3545" // red
	} else if len(result.Errors) > 0 {
		color = "#ffc107" // yellow
	}

	blocks := []SlackBlock{
		{
			Type: "header",
			Text: &SlackText{
				Type:  "plain_text",
				Text:  fmt.Sprintf("ASM Scan Complete: %s", result.Domain),
				Emoji: true,
			},
		},
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Duration:*\n%s", result.Duration.Round(time.Millisecond))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Scan Time:*\n%s", result.StartTime.Format("2006-01-02 15:04"))},
			},
		},
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Subdomains:* %d", len(result.Subdomains))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Open Ports:* %d", len(result.Ports))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Certificates:* %d", len(result.Certificates))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Technologies:* %d", techCount)},
			},
		},
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*URLs:* %d", len(result.URLs))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*APIs:* %d", len(result.APIs))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Emails:* %d", len(result.Emails))},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Buckets:* %d", len(result.CloudStorage))},
			},
		},
	}

	// Add warnings section
	var warnings []string
	if vulnTakeovers > 0 {
		warnings = append(warnings, fmt.Sprintf(":warning: *%d subdomain takeover vulnerabilities*", vulnTakeovers))
	}
	if publicBuckets > 0 {
		warnings = append(warnings, fmt.Sprintf(":warning: *%d public cloud storage buckets*", publicBuckets))
	}

	if len(warnings) > 0 {
		blocks = append(blocks, SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: strings.Join(warnings, "\n"),
			},
		})
	}

	// Add errors if any
	if len(result.Errors) > 0 {
		var errMsgs []string
		for module, err := range result.Errors {
			errMsgs = append(errMsgs, fmt.Sprintf("• %s: %s", module, err))
		}
		blocks = append(blocks, SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*Errors:*\n%s", strings.Join(errMsgs, "\n")),
			},
		})
	}

	return SlackMessage{
		Attachments: []SlackAttachment{
			{
				Color:  color,
				Blocks: blocks,
			},
		},
	}
}

// NotifyEmail sends a scan summary via email
func (n *Notifier) NotifyEmail(result *parallel.ScanResult) error {
	if n.SMTPHost == "" {
		return fmt.Errorf("SMTP not configured")
	}
	if len(n.EmailTo) == 0 {
		return fmt.Errorf("no email recipients configured")
	}

	subject := fmt.Sprintf("ASM Scan Complete: %s", result.Domain)
	body := n.buildEmailBody(result)

	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=\"UTF-8\"\r\n"+
		"\r\n%s",
		n.EmailFrom,
		strings.Join(n.EmailTo, ","),
		subject,
		body)

	addr := fmt.Sprintf("%s:%d", n.SMTPHost, n.SMTPPort)

	if n.UseTLS {
		return n.sendMailTLS(addr, []byte(msg))
	}

	// Fallback to plain SMTP (not recommended)
	err := smtp.SendMail(addr, n.smtpAuth(), n.EmailFrom, n.EmailTo, []byte(msg))
	if err != nil {
		return fmt.Errorf("sending email: %w", err)
	}

	return nil
}

// sendMailTLS sends email using TLS (supports both STARTTLS on port 587 and implicit TLS on port 465)
func (n *Notifier) sendMailTLS(addr string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: n.SMTPHost,
	}

	// For port 465, use implicit TLS; for port 587, use STARTTLS
	if n.SMTPPort == 465 {
		// Implicit TLS connection
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS dial failed: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, n.SMTPHost)
		if err != nil {
			return fmt.Errorf("creating SMTP client: %w", err)
		}
		defer client.Close()

		return n.sendWithClient(client, msg)
	}

	// STARTTLS for port 587 and others
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, n.SMTPHost)
	if err != nil {
		return fmt.Errorf("creating SMTP client: %w", err)
	}
	defer client.Close()

	// Upgrade to TLS
	if err := client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("STARTTLS failed: %w", err)
	}

	return n.sendWithClient(client, msg)
}

// sendWithClient sends email using an established SMTP client
func (n *Notifier) sendWithClient(client *smtp.Client, msg []byte) error {
	// Authenticate if credentials provided
	if auth := n.smtpAuth(); auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(n.EmailFrom); err != nil {
		return fmt.Errorf("setting sender: %w", err)
	}

	// Set recipients
	for _, to := range n.EmailTo {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("setting recipient %s: %w", to, err)
		}
	}

	// Send message body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("getting data writer: %w", err)
	}

	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("closing data writer: %w", err)
	}

	return client.Quit()
}

func (n *Notifier) buildEmailBody(result *parallel.ScanResult) string {
	vulnTakeovers := 0
	for _, t := range result.Takeovers {
		if t.Vulnerable {
			vulnTakeovers++
		}
	}

	publicBuckets := 0
	for _, b := range result.CloudStorage {
		if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
			publicBuckets++
		}
	}

	techCount := 0
	for _, t := range result.Technologies {
		techCount += len(t.Technologies)
	}

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: -apple-system, sans-serif; line-height: 1.6; color: #333; }
.header { background: #1a1a2e; color: white; padding: 20px; }
.content { padding: 20px; }
.stat { display: inline-block; margin: 10px 20px 10px 0; }
.stat-number { font-size: 24px; font-weight: bold; color: #1a1a2e; }
.stat-label { color: #666; font-size: 14px; }
.warning { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px; }
.critical { background: #f8d7da; border: 1px solid #dc3545; padding: 15px; margin: 15px 0; border-radius: 4px; }
table { border-collapse: collapse; width: 100%; margin: 15px 0; }
th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
th { background: #f5f5f5; }
</style>
</head>
<body>
`)

	sb.WriteString(fmt.Sprintf(`<div class="header">
<h1>ASM Scan Report</h1>
<p>Domain: %s</p>
<p>Scan Time: %s | Duration: %s</p>
</div>
<div class="content">
`, html.EscapeString(result.Domain), result.StartTime.UTC().Format(time.RFC3339), result.Duration.Round(time.Millisecond)))

	// Stats
	sb.WriteString(`<h2>Summary</h2>`)
	sb.WriteString(fmt.Sprintf(`
<div class="stat"><div class="stat-number">%d</div><div class="stat-label">Subdomains</div></div>
<div class="stat"><div class="stat-number">%d</div><div class="stat-label">Open Ports</div></div>
<div class="stat"><div class="stat-number">%d</div><div class="stat-label">Certificates</div></div>
<div class="stat"><div class="stat-number">%d</div><div class="stat-label">Technologies</div></div>
<div class="stat"><div class="stat-number">%d</div><div class="stat-label">URLs</div></div>
<div class="stat"><div class="stat-number">%d</div><div class="stat-label">APIs</div></div>
<div class="stat"><div class="stat-number">%d</div><div class="stat-label">Emails</div></div>
<div class="stat"><div class="stat-number">%d</div><div class="stat-label">Buckets</div></div>
`,
		len(result.Subdomains),
		len(result.Ports),
		len(result.Certificates),
		techCount,
		len(result.URLs),
		len(result.APIs),
		len(result.Emails),
		len(result.CloudStorage)))

	// Warnings
	if vulnTakeovers > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="critical"><strong>%d Subdomain Takeover Vulnerabilities Found</strong></div>`, vulnTakeovers))
	}
	if publicBuckets > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="critical"><strong>%d Public Cloud Storage Buckets Found</strong></div>`, publicBuckets))
	}

	// Takeover details
	if vulnTakeovers > 0 {
		sb.WriteString(`<h3>Subdomain Takeover Vulnerabilities</h3>`)
		sb.WriteString(`<table><tr><th>Host</th><th>Service</th><th>Confidence</th></tr>`)
		for _, t := range result.Takeovers {
			if t.Vulnerable {
				sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(t.Subdomain), html.EscapeString(t.Service), html.EscapeString(t.Confidence)))
			}
		}
		sb.WriteString(`</table>`)
	}

	// Public buckets
	if publicBuckets > 0 {
		sb.WriteString(`<h3>Public Cloud Storage</h3>`)
		sb.WriteString(`<table><tr><th>Provider</th><th>Bucket</th><th>Access</th></tr>`)
		for _, b := range result.CloudStorage {
			if b.AccessLevel == "listing_enabled" || b.AccessLevel == "public_read" {
				sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(strings.ToUpper(b.Provider)), html.EscapeString(b.BucketName), html.EscapeString(b.AccessLevel)))
			}
		}
		sb.WriteString(`</table>`)
	}

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString(`<div class="warning"><strong>Scan Errors:</strong><ul>`)
		for module, err := range result.Errors {
			sb.WriteString(fmt.Sprintf(`<li>%s: %s</li>`, html.EscapeString(string(module)), html.EscapeString(err.Error())))
		}
		sb.WriteString(`</ul></div>`)
	}

	sb.WriteString(`</div>
<p style="color: #666; font-size: 12px; padding: 20px;">Generated by ASM Tool</p>
</body>
</html>`)

	return sb.String()
}
