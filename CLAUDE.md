# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ASM Tool is a Go-based attack surface management tool for security practitioners. It monitors domains for subdomains, open ports, certificates, technologies, DNS records, vulnerabilities, URLs, subdomain takeovers, API endpoints, email addresses, and cloud storage buckets.

## Common Commands

```bash
# Build the Go binary
cd asm-go && go build -o asm-go ./cmd/asm

# Run tests
go test ./... -v

# Run a scan
./asm.sh scan example.com

# Check status
./asm.sh status
```

## Architecture

### Layer Structure

```
asm-go/
├── cmd/asm/main.go              # CLI entry point (Cobra)
├── internal/
│   ├── config/config.go         # YAML config (Viper)
│   ├── database/
│   │   ├── database.go          # SQLite facade (sqlx)
│   │   └── migrations/          # SQL schema migrations
│   ├── scanner/
│   │   ├── ports/               # Native TCP scanning
│   │   ├── subdomains/          # Multi-source enumeration
│   │   ├── certificates/        # TLS cert checking
│   │   ├── dns/                 # DNS monitoring
│   │   ├── takeover/            # Subdomain takeover detection
│   │   ├── technologies/        # Tech fingerprinting
│   │   ├── urls/                # URL enumeration
│   │   ├── apis/                # API discovery
│   │   ├── emails/              # Email enumeration
│   │   ├── cloud/               # Cloud storage detection
│   │   └── nuclei/              # Nuclei integration
│   ├── cli/commands/            # CLI command implementations
│   ├── reporter/                # JSON/Markdown/HTML reports
│   ├── notifier/                # Slack/email notifications
│   └── parallel/                # Goroutine orchestration
└── data/                        # SQLite database
```

### Key Patterns

- **Database Facade**: `internal/database/database.go` is a facade with repository structs for each entity type.
- **Scanner Pattern**: Each scanner in `internal/scanner/` has a struct with a `Scan()` or `Enumerate()` method.
- **CLI Structure**: Uses Cobra with subcommands. Commands defined in `internal/cli/commands/`.
- **Parallel Runner**: `internal/parallel/runner.go` orchestrates concurrent module execution.

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
4. Scanner module instantiated
5. Scanner runs, returns results struct
6. Results stored via database repositories
7. Reporter generates output in requested format

## External Tool Dependencies

- `nuclei` - vulnerability scanning (optional)
