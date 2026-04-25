# ASM Tool — WSTG/OWASP Source Review

Target: `/Users/matt-a/Developer/asm-tool/asm-go`
Methodology: OWASP WSTG v4.2 applied as source-code review
Date: 2026-04-17

## Critical

### C1. HTML injection in notifier email body
- **WSTG-INPV-01 / CWE-79**
- `internal/notifier/notifier.go:373-440`
- Email HTML body assembled via `strings.Builder` + `fmt.Sprintf("…%s…")` with **no escaping**. Values come from scan results (takeover `Host`/`Service`, cloud `BucketName`, error messages, `result.Domain`):
  ```go
  sb.WriteString(fmt.Sprintf(`<div class="header"> ... <p>Domain: %s</p> ...`, result.Domain, …))
  sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`, t.Host, t.Service, t.Confidence))
  sb.WriteString(fmt.Sprintf(`<li>%s: %s</li>`, module, err))
  ```
  A hostile CNAME response, bucket name, or scan error string injects HTML/JS into the recipient's inbox. Many mail clients render inline `<img onerror>`, `<a href=javascript:>`, or SSRF tracking pixels.
- **Fix**: Use `html/template` (as `reporter.go` does) or `html.EscapeString` on every interpolation.

## High

### H1. Hunter.io API key in URL query-string
- **WSTG-ATHN-01 / CWE-598**
- `internal/scanner/emails/enumerator.go:223`
  ```go
  apiURL := fmt.Sprintf("https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s", domain, s.APIKey)
  ```
  Secrets in query strings are logged by reverse proxies, CDNs, browser history, and referrer headers; they also land in Go's default `net/http` error strings.
- **Fix**: Pass the key in a request header (`Authorization` / `X-API-Key`) or in the POST body; never the URL.

### H2. SSRF / unvalidated domain flowed into third-party URLs
- **WSTG-INPV-19 / CWE-918**
- `internal/scanner/subdomains/enumerator.go:193,246,297,347`, `internal/scanner/urls/enumerator.go:470,535,575,623`, Hunter/Skymem sources.
  `domain` is `args[0]` from the CLI, passed straight through with no validation. Values containing `@`, `#`, `?`, CRLF, or `..` are embedded verbatim via `fmt.Sprintf`, potentially redirecting requests to attacker-controlled hosts via URL-parsing differences between Go's client and upstream services. Also enables log poisoning / header injection. Same value flows into Nuclei target files and report filenames.
- **Fix**: `url.QueryEscape(domain)` and a strict regex (`^[a-z0-9.-]+$`, max 253 chars) at CLI entry. Reject anything that doesn't parse as a valid hostname.

### H3. Path traversal via `result.Domain` in report filename
- **WSTG-ATHZ-01 / CWE-22**
- `internal/reporter/reporter.go:55-70`
  ```go
  filename = fmt.Sprintf("%s-%s.html", result.Domain, timestamp)
  outputPath := filepath.Join(r.OutputDir, filename)
  os.WriteFile(outputPath, []byte(content), 0644)
  ```
  `result.Domain` is user-supplied. A value such as `../../../etc/cron.d/evil` normalises under `filepath.Join` and writes a 0644 file outside the reports directory. Same pattern for JSON/Markdown cases.
- **Fix**: `filepath.Base` + strict hostname regex before composing the filename.

### H4. Report-convert / migrate read attacker-controlled paths
- **WSTG-ATHZ-01 / CWE-22**
- `internal/cli/commands/report.go` (`runReportConvert`), `internal/cli/commands/migrate.go` (`runMigration`).
  `os.ReadFile(inputFile)` / `os.ReadFile(tinydbPath)` use raw flag values. When the binary is invoked via scheduler/CI with untrusted flag input, unbounded ReadFile + JSON decode allows reading any file the process can access plus potential OOM via large files (no size cap).
- **Fix**: Enforce an allowlisted base dir, reject `..`, cap size with `io.LimitReader`.

## Medium

### M1. `smtp.PlainAuth` fallback without TLS
- **WSTG-CRYP-03 / CWE-319**
- `internal/notifier/notifier.go` `NotifyEmail`. If `UseTLS=false`, the fallback path calls `smtp.PlainAuth` on a plaintext connection via `smtp.SendMail` with no STARTTLS upgrade. `PlainAuth` refuses non-localhost by default, but users commonly set `SMTPHost=localhost` and leak creds to an open relay.
- **Fix**: Remove the plaintext branch, or gate behind `SMTPHost == "localhost"` and document.

### M2. Slack / outbound webhook posts trust any URL
- **WSTG-INPV-19**
- `internal/notifier/notifier.go` `NotifySlack` posts to `n.SlackWebhook` with no allowlist. If an attacker edits `config.yaml`, this is a data-exfil channel.
- **Fix**: Enforce `https://hooks.slack.com/` prefix.

### M3. Unbounded goroutines in API discovery
- **WSTG-BUSL-09 / CWE-770**
- `internal/scanner/apis/discovery.go` spawns `len(d.Paths)` goroutines (~50+) per host with only an inner `sem := make(chan struct{}, 10)`. For `DiscoverBatch`, total goroutines = hosts × paths.
- **Fix**: `errgroup` with `SetLimit`.

### M4. `InsecureSkipVerify` hard-coded in port banner grab
- **WSTG-CRYP-01 / CWE-295**
- `internal/scanner/ports/scanner.go:193` — justified by `//nolint:gosec` for banner grab. Accepted (Info), but surface the flag in dashboards. Takeover/cloud/apis detectors are configurable with secure defaults (good).

## Low / Info

### L1. Dashboard error handler leaks internal errors
- **WSTG-ERRH-01** — `dashboard.go` returns `http.Error(w, "Failed to render template: "+err.Error(), …)`. Template/DB errors echoed to clients expose paths/driver strings. Mitigated by default `127.0.0.1` bind.

### L2. Dashboard `/api/stats` hand-rolls JSON via `fmt.Fprintf`
- **WSTG-INPV-04** — Numeric only today, safe. Use `json.NewEncoder(w).Encode(...)`.

### L3. `Database.Exec` is a raw-query facade
- **WSTG-INPV-05 / CWE-89** — `internal/database/database.go:485` exports a method accepting arbitrary SQL. All current in-tree callers use constant SQL with parameters; risk is latent. Unexport or remove.

### L4. Nuclei `exec.CommandContext` inputs — mostly clean
- `TemplatesPath` and `OutputDir` not path-escaped; a malicious config pointing `OutputDir=/etc` causes file writes there via `os.MkdirAll(s.OutputDir, 0755)` + nuclei `-output`. Config is local-trust, so Low.

### L5. APIs/URL/Subdomain sources don't validate TLS redirect targets
- `apis/discovery.go` `CheckRedirect` allows 2 hops. Combined with H2, widens SSRF surface.

## Clean / Acceptable
- Reporter HTML uses `html/template` with auto-escape. No XSS in the generated report file.
- Nuclei binary path validation (`validateBinaryPath`) correctly rejects relative / `..` paths.
- Repository methods in `database.go` use parameterised queries (`?` placeholders, `sqlx.Select`/`Get`).
- `sendMailTLS` sets `ServerName: n.SMTPHost` (no `InsecureSkipVerify`).

## Top remediation priorities
1. Escape the notifier email HTML (C1).
2. Move Hunter API key to a header (H1).
3. Sanitise `domain`/`host` CLI input with a regex + `url.QueryEscape` before interpolation (H2).
4. Sanitise report filenames with `filepath.Base` and a hostname regex (H3).
5. Delete the plaintext SMTP fallback or scope it to localhost (M1).
