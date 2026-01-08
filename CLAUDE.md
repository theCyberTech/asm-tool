# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ASM Tool is a Docker-based attack surface management tool for security practitioners. It monitors domains for subdomains, open ports, certificates, technologies, DNS records, vulnerabilities, URLs, subdomain takeovers, API endpoints, and email addresses.

## Common Commands

```bash
# Run tests (requires 90% coverage)
pytest tests/unit/ -v

# Run a single test file
pytest tests/unit/test_database.py -v

# Run with coverage report
pytest tests/ --cov=asm --cov-report=term-missing

# Run integration tests
pytest tests/integration/ -v

# Run tests by marker
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m "not external" # Skip tests requiring external tools

# Build Docker image
docker build -t asm-tool .

# Run inside container
./asm.sh shell
python -m asm discover example.com
```

## Architecture

### Layer Structure

```
asm/
├── __main__.py          # CLI (Click framework)
├── core/                # Business logic layer
│   ├── config.py        # YAML config loading
│   ├── database.py      # Facade for all repositories
│   ├── helpers.py       # Shared utilities (resolve_targets)
│   ├── notifier.py      # Slack/email notifications
│   ├── reporter.py      # Multi-format report generation
│   └── scheduler.py     # Cron job management
├── repositories/        # Data access layer (TinyDB)
│   ├── base.py          # BaseRepository class
│   ├── domain.py        # Domain/subdomain storage
│   ├── asset.py         # Ports, certs, tech, DNS
│   ├── finding.py       # Vulnerabilities, takeovers
│   ├── discovery.py     # URLs, APIs, emails
│   └── analytics.py     # Snapshots, trends, change events
├── modules/             # Scanning modules
│   ├── subdomains.py    # SubdomainEnumerator (subfinder, assetfinder, crt.sh)
│   ├── ports.py         # PortScanner (nmap wrapper)
│   ├── certificates.py  # CertificateMonitor (SSL/TLS)
│   ├── technologies.py  # TechnologyFingerprinter
│   ├── dns_monitor.py   # DNSMonitor (dnspython)
│   ├── nuclei_scanner.py # NucleiScanner
│   ├── urls.py          # URLEnumerator (gau wrapper)
│   ├── takeover.py      # TakeoverDetector
│   ├── api_discovery.py # APIDiscovery (Swagger/GraphQL)
│   └── emails.py        # EmailEnumerator
└── constants/           # Extracted constants
    ├── api_paths.py     # Common API paths to probe
    └── takeover_fingerprints.py  # Service fingerprints
```

### Key Patterns

- **Database Facade**: `asm/core/database.py` is a facade over multiple repository classes. All data access goes through `Database`, which delegates to specialized repositories.
- **Repository Pattern**: Each repository in `asm/repositories/` handles one domain concept. They inherit from `BaseRepository` and use TinyDB tables.
- **CLI Structure**: Uses Click with `@click.group()`. Commands accept domain/--all-known pattern. Use `resolve_targets()` helper to normalize target lists.
- **Module Pattern**: Scanning modules take a `Config` object, have an `enumerate()` or `scan()` method, and return structured dicts.

### Testing Approach

- Unit tests use mocks for external tools (nmap, subfinder, nuclei, gau)
- `tests/conftest.py` provides `mock_db` and `mock_config` fixtures
- Markers: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.external`
- Coverage threshold: 90% (enforced in pytest.ini)

## Data Flow

1. CLI command parses args, loads Config from YAML
2. Database facade is initialized with TinyDB path
3. Module class is instantiated with Config
4. Module runs scan, returns results dict
5. Results stored via Database facade methods (e.g., `db.add_subdomain()`)
6. Changes tracked via snapshots and change events for trend analysis

## External Tool Dependencies

The tool wraps several external binaries that must be available in PATH (or Docker):
- `subfinder`, `assetfinder` - subdomain enumeration
- `nmap` - port scanning
- `nuclei` - vulnerability scanning
- `gau` - URL enumeration from web archives
