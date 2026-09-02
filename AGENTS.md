# AGENTS.md

## 1. What this repo is

ASM Tool is a local-first Go CLI that maps the attack surface of `crewai.com` (and its subdomains): subdomains, ports, certs, DNS, techs, URLs, APIs, takeovers, cloud buckets, and optional Nuclei vulns.

A TypeScript React dashboard is embedded in the binary; scans can also run on a cron schedule with Slack/email notifications.

## 2. Setup & checks

Prerequisites: Go 1.25+ (see `asm-go/go.mod`; `GOTOOLCHAIN=auto` downloads it), `gcc` (CGO/SQLite), Node 22+ only if you change the dashboard. Nuclei is optional.

```bash
# One-time init (creates config.yaml, data/, reports/, logs/; builds the binary if missing)
./asm.sh init

# Go (from asm-go/)
cd asm-go
go build -o asm-go ./cmd/asm
go vet ./...
go test ./...

# TypeScript dashboard (from repo root; only required when changing web/)
cd web && npm ci && npm test && npm run build

# Smoke via wrapper (repo root; scans are restricted to crewai.com)
./asm.sh status
./asm.sh scan crewai.com
./asm.sh dashboard
```

CI (`.github/workflows/ci.yml`) is the source of truth: `npm ci && npm test && npm run build` in `web/`, then `go vet ./...` and `go test ./...` in `asm-go/`.

## 3. Repo map

| Path | Role |
| --- | --- |
| `asm.sh` | Preferred CLI entry; wraps `asm-go/asm-go --db asm-go/data/asm.db` |
| `asm-go/cmd/asm/` | Cobra binary (`github.com/asm-tool/asm-go/cmd/asm`) |
| `asm-go/internal/cli/commands/` | Command handlers and dashboard HTTP mux |
| `asm-go/internal/config/` | YAML config (Viper); `config.example.yaml` at repo root |
| `asm-go/internal/target/` | Domain normalize/validate; **scan** scope lives here |
| `asm-go/internal/scanner/` | Self-contained modules (`Scan` / `Enumerate`) |
| `asm-go/internal/parallel/` | Concurrent module orchestration → `ScanResult` |
| `asm-go/internal/persistence/` | Transactional `Store.SaveAll` / snapshots |
| `asm-go/internal/database/` | SQLite facade + repositories + `migrations/` |
| `asm-go/internal/httpclient/` | Shared `http.Client` (+ optional `internal/ratelimit`) |
| `asm-go/internal/dashboard/` | Embedded SPA (`webdist/`) and JSON DTO types |
| `web/` | React + Vite source; build writes `asm-go/internal/dashboard/webdist/` |
| `asm-go/internal/reporter/` | JSON / Markdown / HTML reports |
| `asm-go/internal/notifier/` | Slack + email |
| `asm-go/internal/scheduler/` | Cron jobs |
| `asm-go/data/` | Local SQLite (`asm.db`); gitignored |

**Public surface (keep stable):**

- **CLI**: `asm.sh` / `asm` subcommands (`scan`, `discover`, `portscan`, `certificates`, `dns`, `takeover`, `fingerprint`, `urls`, `apis`, `cloudstorage`, `nuclei`, `report`, `diff`, `schedule`, `dashboard`, `status`, `migrate`).
- **Dashboard HTTP**: `GET /health`; JSON under `/api/*` — `/api/stats`, `/api/overview`, `/api/domains`, `/api/domains/:name`, `/api/domains/:name/assets/:kind`, `/api/assets/:kind`, `/api/operations`, `/api/runs`, `POST /api/runs/start`. DTOs: `asm-go/internal/dashboard/json.go` and `web/src/api/types.ts`.
- **Go module**: everything else is `internal/`. Cross-package contracts are `persistence.Store`, each scanner’s `Scan()`/`Enumerate()`, and `database.Database` repositories — do not bypass them.

## 4. Coding conventions

**Typing**

- Go: typed result structs per scanner; `parallel.ScanResult` is the aggregate. Prefer concrete types over `any`/`interface{}` except JSON-shaped dashboard lists.
- TypeScript: `strict` + `noUncheckedIndexedAccess`. Share shapes via `web/src/api/types.ts`; keep them aligned with Go JSON tags.

**Errors**

- Return errors; wrap with `fmt.Errorf("verb noun: %w", err)`.
- CLI `RunE` returns the error (Cobra prints it). User-facing validation can be a plain `fmt.Errorf` without `%w`.
- Collect multi-step failures (`errors.Join` or an error slice) rather than dropping later errors.

**Logging**

- CLI progress: `fmt.Printf` + lipgloss styles in `internal/cli/commands` (not a structured logger).
- Long-running services (scheduler): `log.Logger.Printf`. Tests pass `log.New(io.Discard, "", 0)`.
- Do not introduce `slog` or ad-hoc `log.Fatal` in library packages.

**Deprecation**

- Mark replaced helpers with `// Deprecated: use pkg.Func instead.` and leave a thin wrapper until callers move (see `applyModuleSelection` → `parallel.ApplyModuleSelection`).
- Do not add new call sites to deprecated helpers.

**Boundaries**

- Normalize user domains with `target.NormalizeTarget`. Scan entry points must use `target.NormalizeScanTarget` (crewai.com only). Do **not** put that restriction inside `NormalizeTarget`.
- Scanners stay self-contained; build HTTP clients with `httpclient.New`, not inline `http.Client`/`http.Transport`.
- Persist through `internal/persistence`, not by poking repositories from commands except for reads/status.
- Do not commit generated DBs, the `asm-go/asm-go` binary, `config.yaml`, secrets, or drive-by `webdist/` churn.

## 5. Testing conventions

**Layout**

- Go: `*_test.go` in the same package (`package foo`, not `foo_test` unless you need to test as a client).
- TypeScript: colocate `*.test.ts(x)` next to the unit (`web/src/api/client.test.ts`, `web/src/pages/DashboardPage.test.tsx`). Vitest + Testing Library + jsdom (`web/src/test/setup.ts`).

**Table tests and fixtures**

- Prefer table-driven `t.Run` cases. SQLite tests use `t.TempDir()` — never the real `asm-go/data/asm.db`.
- There are **no VCR/cassettes**. Stub outbound HTTP with `net/http/httptest` (Go) or `vi.stubGlobal("fetch", vi.fn()...)` (TS). Restore with `vi.unstubAllGlobals()` / `restoreMocks: true`.
- Dashboard handlers: `httptest.NewRequest` + `httptest.NewRecorder` against `newDashboardMux`.

**Async / context**

- Scanner and runner APIs take `context.Context`. Tests use `context.Background()` or a cancelled ctx for stop-path coverage.
- CLI scan wires `signal.NotifyContext`; do not start real network scans in unit tests.
- Frontend tests are `async`/`await` against mocked `fetch`; render with `MemoryRouter`.

**When to add tests**

- Any behavior change to target validation, persistence, dashboard JSON, or module selection needs a test. Match existing assertion style (`t.Fatalf` / `expect`).

## 6. Known pitfalls

- **Scan scope is hardcoded.** Only `crewai.com` and its subdomains are allowed (`target.AllowedRootDomain`). CLI, dashboard Operations, scheduler, and config loader all reject other domains. Use `crewai.com` (or `app.crewai.com`) in tests and smoke scans.
- **`NormalizeTarget` ≠ `NormalizeScanTarget`.** The former only canonicalizes a DNS name. Enforcing crewai.com in `NormalizeTarget` breaks unit tests that use `example.com` as a dummy host.
- **`migrate` is not a schema migration.** It imports legacy Python TinyDB data. SQLite schema is applied automatically in `database.New`. Fresh `./asm.sh status` / `scan` is enough.
- **CGO is required.** `mattn/go-sqlite3` needs `gcc`. Pure-Go builds will fail.
- **Go version vs image.** `go.mod` pins `1.25.0`; older images still work because `GOTOOLCHAIN=auto` fetches the toolchain on first `go` command (slow once).
- **`webdist/` is committed and embedded** (`go:embed`). `npm run build` is deterministic and rewrites hashed assets — skip the build unless you changed `web/`, and do not mix unrelated `webdist/` diffs into a Go-only PR.
- **Dashboard bind.** Default `127.0.0.1:8080`; if busy, port auto-increments up to +100. Health: `GET /health`.
- **Nuclei is optional and not installed by `./asm.sh init`.** `./asm.sh nuclei` and Operations → Nuclei fail with `nuclei not found in PATH` until `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` (current `latest` may need a newer Go; toolchain auto-downloads). Then `./asm.sh nuclei --update` for templates. Do **not** smoke-test with `--all-known` (every known subdomain × default templates; very long).
- **Host cap.** `target.HostScanLimit` (25) caps live host modules (ports, certs, fingerprint, APIs, takeover, nuclei).
- **`config.yaml` and `asm-go/data/` are gitignored.** Init copies `config.example.yaml`. SMTP/Slack secrets prefer `ASM_SMTP_USER` / `ASM_SMTP_PASSWORD` / `ASM_SLACK_WEBHOOK`.
- **Dashboard children may not inherit PATH.** Nuclei lookup also checks `$HOME/go/bin/nuclei`; some VMs add a `/usr/local/bin/nuclei` symlink.

## 7. Docs

User-facing usage, config, and architecture live in `README.md`. Claude-oriented architecture notes are in `CLAUDE.md` — keep `AGENTS.md` as the agent runbook; do not duplicate long usage examples here.

**Cursor Cloud / this VM** (tightened from the previous environment notes):

- First `go` invocation downloads Go 1.25 (and modules). `gcc` is present.
- Binary serves the prebuilt SPA; `npm run build` only when changing `web/`.
- Run the dashboard with `./asm.sh dashboard`. APIs are `/api/*`.
- Restrict e2e scans to `crewai.com`. Nuclei is **not** provisioned by the update script; install and `--update` templates before Operations / `nuclei` commands. `$HOME/go/bin` is on PATH via `~/.bashrc`.
- Schema is created on first DB open; do not run `migrate` unless importing TinyDB.

## 8. PR conventions

- Branch off `main`. CI on every PR: `web` `npm ci` / `npm test` / `npm run build`, then `asm-go` `go vet ./...` and `go test ./...`.
- Include tests for behavior changes. A green `go test ./...` and, if `web/` changed, `npm test` is the minimum local check.
- Keep PRs scoped. Do not commit `config.yaml`, `asm-go/data/`, `reports/`, `logs/`, binaries, or secrets. Avoid unrelated `webdist/` rewrites.
- Match existing style: conventional-ish subjects (`fix:`, `refactor:`, `docs:`), imperative mood, what/why in the body. No new markdown files unless asked.
- If you change dashboard JSON, update **both** `internal/dashboard` DTOs and `web/src/api/types.ts`.
- If you add a scanner module, give it `Scan()`/`Enumerate()`, wire it through `parallel`, persist via `Store.SaveAll`, and keep scan targets behind `NormalizeScanTarget`.
