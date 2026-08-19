# ASM Tool

A fast, local-first attack surface management tool for security teams. Find and monitor your external attack surface: subdomains, open ports, certificates, vulnerabilities, and more.

![Go 1.25+](https://img.shields.io/badge/go-1.25+-00ADD8.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- **Subdomain Enumeration** — Find subdomains from many sources (crt.sh, Google Transparency, HackerTarget, urlscan.io, AlienVault OTX, and more)
- **Port Scanning** — Fast native TCP scanning with service detection. 10–20x faster than nmap
- **Certificate Monitoring** — Track TLS certificates and get alerts before they expire
- **Vulnerability Scanning** — Find vulnerabilities automatically with Nuclei
- **URL & API Discovery** — Find historical URLs and detect OpenAPI, Swagger, and GraphQL endpoints
- **Technology Fingerprinting** — Identify frameworks, CDNs, libraries, and servers
- **DNS Monitoring** — Track DNS record changes and check email security (SPF, DKIM, DMARC)
- **Subdomain Takeover Detection** — Find DNS records that point to unclaimed services
- **Email & Cloud Enumeration** — Find exposed email addresses and public cloud buckets (S3, Azure, GCS)
- **Reporting** — Export findings as JSON, Markdown, or HTML
- **Scheduled Scans** — Run scans on a cron schedule, with Slack or email notifications
- **Dashboard** — Browse findings in a lightweight web UI

## Installation

### Prerequisites

- **Go 1.25+** (see `asm-go/go.mod`)
- Optional: [Nuclei](https://github.com/projectdiscovery/nuclei) for vulnerability scanning

### Linux / macOS

```bash
# Clone the repository
git clone https://github.com/theCyberTech/asm-tool.git
cd asm-tool

# Build the CLI binary (asm.sh expects asm-go/asm-go)
cd asm-go
go build -o asm-go ./cmd/asm
cd ..

# Initialize the project (creates config, data dirs)
chmod +x asm.sh
./asm.sh init
```

### Using Go Install (CLI only)

```bash
go install github.com/theCyberTech/asm-tool/asm-go/cmd/asm@latest
```

### Install Nuclei (optional)

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Quick Start

```bash
# Initialize config and database
./asm.sh init

# Run a full scan
./asm.sh scan example.com

# Check results
./asm.sh status

# View the dashboard
./asm.sh dashboard
```

## Usage

### Scanning

```bash
# Full scan (all enabled modules)
./asm.sh scan example.com

# Scan with vulnerability detection
./asm.sh scan example.com --nuclei

# Skip or limit modules
./asm.sh scan example.com --skip ports,dns
./asm.sh scan example.com --only subdomains,ports

# Generate a report inline
./asm.sh scan example.com --output html   # HTML report
./asm.sh scan example.com --output json   # JSON report
./asm.sh scan example.com --output markdown  # Markdown report
```

### Individual Modules

```bash
./asm.sh discover example.com          # Subdomain enumeration
./asm.sh portscan example.com          # Port scanning
./asm.sh portscan --all-known          # Scan all discovered subdomains
./asm.sh certificates example.com      # Check SSL/TLS certificates
./asm.sh dns example.com               # DNS record lookup
./asm.sh takeover example.com          # Subdomain takeover detection
./asm.sh fingerprint example.com       # Technology fingerprinting
./asm.sh urls example.com              # URL enumeration
./asm.sh apis example.com              # API endpoint discovery
./asm.sh emails example.com            # Email enumeration
./asm.sh cloudstorage example.com      # Cloud bucket detection
./asm.sh nuclei example.com            # Vulnerability scanning
```

### Dashboard

```bash
# Start the web dashboard (default: localhost:8080)
./asm.sh dashboard

# Custom port
./asm.sh dashboard --port 3000

# Bind off loopback only with a token
# ASM_DASHBOARD_TOKEN=secret ./asm.sh dashboard --host 0.0.0.0
```

### Reporting

```bash
# Generate a report for a scanned domain
./asm.sh report example.com --format html --output ./reports/
./asm.sh report example.com --format markdown
./asm.sh report example.com --format json
```

### Scheduled Scans

```bash
# Start the scheduler (runs in foreground)
./asm.sh schedule start

# Run a scheduled job manually
./asm.sh schedule run full_scan
./asm.sh schedule run cert_check example.com

# View schedule and history
./asm.sh schedule
./asm.sh schedule history

# Compare the last two persisted scans
./asm.sh diff example.com
```

## Configuration

Edit `config.yaml` (created by `asm.sh init`):

```yaml
# Domains to monitor
domains:
  - example.com
  - api.example.com

# Scanning options
scanning:
  ports: "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443"
  nuclei_severity: "medium,high,critical"
  rate_limit: 100

# Nuclei (vulnerability scanner)
nuclei:
  concurrency: 25
  batch_size: 25
  exclude_tags: "dos,fuzz,brute"
  retries: 1

# Notifications
# SMTP credentials prefer env vars ASM_SMTP_USER / ASM_SMTP_PASSWORD
# (fallbacks: SMTP_USER / SMTP_PASSWORD). Slack webhook can use ASM_SLACK_WEBHOOK.
notifications:
  slack:
    enabled: false
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
  email:
    enabled: false
    smtp_host: "smtp.example.com"
    smtp_port: 587
    from_addr: "alerts@example.com"
    to_addr: "security@example.com"

# Scheduling
schedule:
  full_scan: "0 6 * * *"       # Daily at 6 AM
  cert_check: "0 */6 * * *"   # Every 6 hours

# External API keys (optional)
hunter:
  api_key: "your-hunter-api-key"
```

## Architecture

```
asm-go/
├── cmd/asm/main.go              # CLI entry point (Cobra)
├── internal/
│   ├── config/                  # YAML config (Viper)
│   ├── database/                # SQLite ORM (sqlx)
│   ├── scanner/                 # 11 scanning modules
│   │   ├── subdomains/          # Multi-source enumeration
│   │   ├── ports/               # Native TCP scanning
│   │   ├── certificates/        # TLS monitoring
│   │   ├── dns/                 # DNS record tracking
│   │   ├── takeover/            # Subdomain takeover
│   │   ├── technologies/        # Tech fingerprinting
│   │   ├── urls/                # URL discovery
│   │   ├── apis/                # API detection
│   │   ├── emails/              # Email enumeration
│   │   ├── cloud/               # Cloud bucket detection
│   │   └── nuclei/              # Vuln scanning
│   ├── persistence/             # Unified Store interface
│   ├── parallel/                # Goroutine orchestration
│   ├── reporter/                # JSON/Markdown/HTML reports
│   ├── notifier/                # Slack/email alerts
│   ├── scheduler/               # Cron-based scheduling
│   └── cli/commands/            # CLI command handlers
├── data/                        # SQLite database
└── reports/                     # Generated reports
```

## Data Storage

All findings are stored in a local SQLite database at `asm-go/data/asm.db`. The database uses WAL mode, so multiple processes can access it safely at the same time. Reports are written to the `./reports/` directory.

## Security Considerations

- **Only scan domains you own or have permission to test**
- Keep API keys out of version control. Use environment variables or a separate `.env` file
- Respect rate limits so you do not overload target systems

## License

MIT