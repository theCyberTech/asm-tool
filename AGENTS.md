# AGENTS.md

## Project Overview

ASM Tool is a Go-based attack surface management tool. It monitors domains for
subdomains, open ports, certificates, technologies, DNS records, vulnerabilities,
URLs, subdomain takeovers, API endpoints, email addresses, and cloud storage
buckets.

## Repository Layout

- `asm-go/cmd/asm/` - CLI entry point
- `asm-go/internal/config/` - YAML configuration
- `asm-go/internal/database/` - SQLite database facade and migrations
- `asm-go/internal/scanner/` - Discovery and security scanning modules
- `asm-go/internal/cli/commands/` - Cobra command implementations
- `asm-go/internal/reporter/` - JSON, Markdown, and HTML reports
- `asm-go/internal/notifier/` - Slack and email notifications
- `asm-go/internal/parallel/` - Concurrent scan orchestration

## Development Commands

Run these commands from `asm-go/` unless noted otherwise:

```bash
# Build the binary
go build -o asm-go ./cmd/asm

# Run tests
go test ./... -v
```

## Coding Guidelines

- Follow existing Go conventions and package structure.
- Keep scanner modules self-contained and use their existing `Scan()` or
  `Enumerate()` interfaces.
- Preserve the database facade and repository boundaries when changing
  persistence behavior.
- Add or update tests for behavior changes.
- Do not commit generated databases, build artifacts, or secrets.

## External Dependencies

`nuclei` is an optional external dependency used for vulnerability scanning.
