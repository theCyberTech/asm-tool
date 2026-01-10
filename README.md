# ASM Tool - Attack Surface Management

![Go 1.21+](https://img.shields.io/badge/go-1.21+-00ADD8.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

A high-performance attack surface management tool for security practitioners. Written in Go for speed and efficiency.

## Features

- **Subdomain Enumeration** - Multiple sources: crt.sh, HackerTarget, VirusTotal, SecurityTrails
- **Port Scanning** - Native TCP scanning with service detection (10-20x faster than nmap)
- **Certificate Monitoring** - SSL/TLS cert tracking, expiry alerts
- **Technology Fingerprinting** - Identify web technologies, frameworks, CDNs
- **DNS Monitoring** - Track DNS record changes, email security (SPF/DKIM/DMARC)
- **Vulnerability Scanning** - Nuclei integration for automated vuln detection
- **URL Enumeration** - Historical URL discovery from Wayback Machine
- **Subdomain Takeover Detection** - Identify vulnerable subdomains
- **API Discovery** - Automatic detection of Swagger, OpenAPI, and GraphQL endpoints
- **Email Enumeration** - Discover email addresses for target domains
- **Cloud Storage Detection** - Find exposed S3, Azure, and GCS buckets
- **Reporting** - Generate reports in JSON, Markdown, and HTML formats
- **Parallel Execution** - Goroutine-based concurrent scanning

## Quick Start

```bash
# Build the Go binary
cd asm-go
go build -o asm-go ./cmd/asm

# Initialize (creates config and directories)
cd ..
./asm.sh init

# Run a full scan
./asm.sh scan example.com

# Check database status
./asm.sh status
```

## Commands

```bash
# Database status
./asm.sh status

# Full scan (all modules)
./asm.sh scan example.com
./asm.sh scan example.com --nuclei              # Include vulnerability scanning
./asm.sh scan example.com --output html         # Generate HTML report
./asm.sh scan example.com --skip ports,dns      # Skip specific modules
./asm.sh scan example.com --only subdomains,ports  # Run only specific modules

# Individual modules
./asm.sh discover example.com                   # Subdomain enumeration
./asm.sh portscan example.com                   # Port scanning
./asm.sh portscan --all-known                   # Scan all known subdomains
./asm.sh portscan example.com --ports 80,443,8080
./asm.sh certificates example.com               # Certificate checking
./asm.sh dns example.com                        # DNS record lookup
./asm.sh takeover example.com                   # Subdomain takeover detection
./asm.sh fingerprint example.com                # Technology fingerprinting
./asm.sh urls example.com                       # URL enumeration
./asm.sh apis example.com                       # API discovery
./asm.sh emails example.com                     # Email enumeration
./asm.sh cloudstorage example.com               # Cloud storage detection

# Vulnerability scanning (requires nuclei installed)
./asm.sh nuclei example.com
./asm.sh nuclei --all-known --severity critical,high
./asm.sh nuclei --all-known --tags cve

# Reporting
./asm.sh report --format html
./asm.sh report --format markdown
./asm.sh report --format json
```

## Configuration

Edit `config.yaml` to customize:

```yaml
# Domains to monitor
domains:
  - example.com

# Notification settings
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Scanning configuration
scanning:
  ports: "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443"
  rate_limit: 100

# External API integrations (optional)
virustotal:
  api_key: "your-virustotal-api-key"

securitytrails:
  api_key: "your-securitytrails-api-key"

hunter:
  api_key: "your-hunter-api-key"
```

## Architecture

```
asm-go/
├── cmd/asm/main.go              # CLI entry point (Cobra)
├── internal/
│   ├── config/config.go         # YAML config (Viper)
│   ├── database/
│   │   ├── database.go          # SQLite facade (sqlx)
│   │   └── migrations/          # SQL migrations
│   ├── scanner/
│   │   ├── ports/               # Native TCP scanning
│   │   ├── subdomains/          # Multi-source enumeration
│   │   ├── certificates/        # TLS cert checking
│   │   ├── dns/                 # DNS monitoring
│   │   ├── takeover/            # Subdomain takeover
│   │   ├── technologies/        # Tech fingerprinting
│   │   ├── urls/                # URL enumeration
│   │   ├── apis/                # API discovery
│   │   ├── emails/              # Email enumeration
│   │   ├── cloud/               # Cloud storage detection
│   │   └── nuclei/              # Nuclei integration
│   ├── cli/commands/            # CLI commands
│   ├── reporter/                # JSON/Markdown/HTML reports
│   ├── notifier/                # Slack/email notifications
│   └── parallel/                # Goroutine orchestration
└── data/                        # SQLite database
```

## Data Storage

Data is stored in SQLite at `asm-go/data/asm.db` with WAL mode for concurrent access.

Reports are saved to `./reports`.

## Scheduling

For automated scans, add to your crontab:

```bash
# Run full scan daily at 6 AM
0 6 * * * cd /path/to/asm-tool && ./asm.sh scan example.com >> logs/scan.log 2>&1

# Certificate check every 6 hours
0 */6 * * * cd /path/to/asm-tool && ./asm.sh certificates --all-known >> logs/certs.log 2>&1
```

## Dependencies

- Go 1.21+
- Nuclei (optional, for vulnerability scanning)

Install Nuclei:
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Security Considerations

- Only scan domains you own or have permission to test
- Protect API keys in config.yaml (don't commit to git)
- Consider rate limiting when scanning production systems

## License

MIT
