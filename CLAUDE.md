# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ASM Tool is a Go-based attack surface management tool for security practitioners. It monitors domains for subdomains, open ports, certificates, technologies, DNS records, vulnerabilities, URLs, subdomain takeovers, API endpoints, and cloud storage buckets. It also provides a local web dashboard and cron-based scheduled scans with Slack/email notifications.

## Common Commands

```bash
# Build the Go binary
cd asm-go && go build -o asm-go ./cmd/asm

# Run tests
go test ./... -v

# TypeScript dashboard
cd web && npm test && npm run build

# Initialize project (repo root)
./asm.sh init

# Run a scan
./asm.sh scan crewai.com

# Check status
./asm.sh status

# Start the web dashboard
./asm.sh dashboard
```

## Architecture

### Layer Structure

```
web/                             # TypeScript + React dashboard (Vite)
asm-go/
├── cmd/asm/main.go              # CLI entry point (Cobra)
├── internal/
│   ├── config/config.go         # YAML config (Viper)
│   ├── database/
│   │   ├── database.go          # SQLite facade (sqlx)
│   │   └── migrations/          # SQL schema migrations
│   ├── persistence/             # Transactional scan result storage
│   ├── scanner/
│   │   ├── ports/               # Native TCP scanning
│   │   ├── subdomains/          # Multi-source enumeration
│   │   ├── certificates/        # TLS cert checking
│   │   ├── dns/                 # DNS monitoring
│   │   ├── takeover/            # Subdomain takeover detection
│   │   ├── technologies/        # Tech fingerprinting
│   │   ├── urls/                # URL enumeration
│   │   ├── apis/                # API discovery
│   │   ├── cloud/               # Cloud storage detection
│   │   └── nuclei/              # Nuclei integration
│   ├── cli/commands/            # CLI command handlers
│   ├── dashboard/               # Embedded TypeScript SPA and JSON types
│   ├── scheduler/               # Cron-based scheduled scan jobs
│   ├── reporter/                # JSON/Markdown/HTML reports
│   ├── notifier/                # Slack/email notifications
│   ├── parallel/                # Goroutine orchestration
│   ├── target/                  # Domain normalization and validation
│   ├── httpclient/              # Shared HTTP client construction
│   └── ratelimit/               # Outbound HTTP rate limiting
└── data/                        # SQLite database
```

### Key Patterns

- **Database Facade**: `internal/database/database.go` is a facade with repository structs for each entity type.
- **Persistence Store**: `internal/persistence` saves full scan results transactionally via `Store.SaveAll()`.
- **Scanner Pattern**: Each scanner in `internal/scanner/` has a struct with a `Scan()` or `Enumerate()` method.
- **CLI Structure**: Uses Cobra with subcommands. Commands defined in `internal/cli/commands/`.
- **Parallel Runner**: `internal/parallel/runner.go` orchestrates concurrent module execution.
- **Target Validation**: `internal/target` normalizes domains before scanner or network requests.
- **Shared HTTP Client**: Scanners should use `internal/httpclient` (with optional `internal/ratelimit`) instead of ad-hoc clients.

### Key Libraries

- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration
- `github.com/jmoiron/sqlx` - Database access
- `github.com/mattn/go-sqlite3` - SQLite driver
- `github.com/miekg/dns` - DNS queries
- `github.com/charmbracelet/lipgloss` - Terminal styling

## Data Flow

1. CLI command parses args via Cobra
2. Config loaded from YAML via Viper
3. Database initialized with SQLite path
4. Target domain normalized/validated via `internal/target`
5. Scanner module instantiated (HTTP via `internal/httpclient` when needed)
6. Scanner runs, returns results struct
7. Results stored via `internal/persistence` (database repositories underneath)
8. Reporter generates output in requested format; dashboard reads from SQLite

## External Tool Dependencies

- `nuclei` - vulnerability scanning (optional)
