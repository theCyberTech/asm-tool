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

## Cursor Cloud specific instructions

Services and standard commands are documented above (see "Development Commands")
and in `README.md`. Notes below cover non-obvious environment behavior.

- Go toolchain: `go.mod` pins `go 1.25.0`, but the base image may ship an older
  Go (e.g. 1.22). `GOTOOLCHAIN=auto` (the default) makes any `go` command
  auto-download and switch to `go1.25.0` on first use, so `go build`/`go test`
  work without manually installing Go 1.25. The first invocation downloads the
  toolchain (and modules); the update script primes this via `go mod download`.
- SQLite uses CGO (`mattn/go-sqlite3`), so a C compiler (`gcc`) must be present
  to build the binary. `gcc` is available in the base image.
- The dashboard SPA in `web/` is prebuilt and committed to
  `asm-go/internal/dashboard/webdist/` and embedded via `go:embed`. The Go
  binary serves the dashboard without running the web build, so `npm run build`
  is only needed when changing the frontend (it is deterministic and rewrites
  `webdist/`; avoid committing unintended churn there).
- The `dashboard` command listens on `127.0.0.1:8080` by default. If 8080 is
  busy it auto-increments up to +100. Health check: `GET /health`; data APIs
  under `/api/*` (e.g. `/api/stats`). Run it via `./asm.sh dashboard`.
- Cloud Agent **Preview** uses Cursor's port-forward to `127.0.0.1:8080`. Keep
  the default bind (`127.0.0.1`, dual-stack `tcp` / `ListenAndServe`). Binding
  `0.0.0.0` or forcing `tcp4` breaks that preview tunnel even when `/health`
  still works from inside the VM and the Ports panel still shows 8080 green.
  After a dashboard restart, close and reopen the Preview tab so the forward
  reattaches.
- Scans are restricted to `crewai.com` and its subdomains via
  `target.NormalizeScanTarget`; other domains are rejected. Use `crewai.com`
  for any scan/e2e testing (e.g. `./asm.sh discover crewai.com`).
- The `migrate` command imports legacy Python TinyDB data; it is NOT a schema
  migration step. The SQLite schema is created automatically on first use, so
  `./asm.sh status`/`scan` work against a fresh `asm-go/data/asm.db`.
- `./asm.sh init` creates `config.yaml` (from `config.example.yaml`), `data/`,
  `reports/`, `logs/`, and builds the binary if missing. `config.yaml` and
  `asm-go/data/` are gitignored.
- Nuclei is optional and is **not** installed by the update script. Dashboard
  Operations → Nuclei and `./asm.sh nuclei` fail with `nuclei not found in PATH`
  until the binary exists. Install once with
  `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` (current
  `latest` needs Go 1.26; the Go toolchain auto-downloads it). The binary lands
  in `$HOME/go/bin`. `findNucleiBinary` also checks `$HOME/go/bin/nuclei`, and
  this VM has a `/usr/local/bin/nuclei` symlink so PATH-less dashboard children
  can find it. After install, run `./asm.sh nuclei --update` once to fetch
  templates into `$HOME/nuclei-templates`. `$HOME/go/bin` is on PATH via
  `~/.bashrc`. Do not use `--all-known` as a first smoke test: it scans every
  discovered subdomain with the default template set and can run for a long
  time.
