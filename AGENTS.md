# AGENTS.md

## Project Overview

ASM Tool is a Go-based attack surface management tool. It monitors domains for
subdomains, open ports, certificates, technologies, DNS records, vulnerabilities,
URLs, subdomain takeovers, API endpoints, and cloud storage
buckets. It also provides a local web dashboard and cron-based scheduled scans
with Slack/email notifications.

## Repository Layout

- `asm.sh` - Shell wrapper around the Go CLI (preferred entry point)
- `asm-go/cmd/asm/` - CLI entry point
- `asm-go/internal/config/` - YAML configuration
- `asm-go/internal/database/` - SQLite database facade and migrations
- `asm-go/internal/persistence/` - Transactional save of scan results
- `asm-go/internal/scanner/` - Discovery and security scanning modules
- `asm-go/internal/cli/commands/` - Cobra command implementations
- `asm-go/internal/dashboard/` - Embedded TypeScript SPA and HTML templates
- `web/` - TypeScript + React dashboard source (Vite)
- `asm-go/internal/scheduler/` - Cron-based scheduled scan jobs
- `asm-go/internal/reporter/` - JSON, Markdown, and HTML reports
- `asm-go/internal/notifier/` - Slack and email notifications
- `asm-go/internal/parallel/` - Concurrent scan orchestration
- `asm-go/internal/target/` - Domain normalization and validation
- `asm-go/internal/httpclient/` - Shared HTTP client construction
- `asm-go/internal/ratelimit/` - Outbound HTTP rate limiting

## Development Commands

Run Go commands from `asm-go/` unless noted otherwise:

```bash
# Build the binary
go build -o asm-go ./cmd/asm

# Run tests
go test ./... -v

# TypeScript dashboard (from repo root)
cd ../web && npm test && npm run build

# Init, scan, and status via wrapper (repo root)
../asm.sh init
../asm.sh scan crewai.com
../asm.sh status
../asm.sh dashboard
```

## Coding Guidelines

- Follow existing Go conventions and package structure.
- Keep scanner modules self-contained and use their existing `Scan()` or
  `Enumerate()` interfaces.
- Preserve the database facade and repository boundaries when changing
  persistence behavior; prefer `internal/persistence` for saving scan results.
- Normalize and validate domains via `internal/target` before scanner requests.
- Scan entry points must use `target.NormalizeScanTarget` so only `crewai.com`
  and its subdomains can be scanned. Do not enforce this inside `NormalizeTarget`.
- Prefer `internal/httpclient` over ad-hoc `http.Client` construction in scanners.
- Add or update tests for behavior changes.
- Do not commit generated databases, build artifacts, or secrets.

## External Dependencies

`nuclei` is an optional external dependency used for vulnerability scanning.
