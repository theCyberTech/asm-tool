# ASM Tool - Attack Surface Management

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)

A self-contained, Docker-based attack surface management tool designed for security practitioners managing small-to-medium organizations.

## Features

- **Subdomain Enumeration** - Multiple sources: subfinder, assetfinder, crt.sh, HackerTarget
- **Port Scanning** - nmap-based scanning with service detection
- **Certificate Monitoring** - SSL/TLS cert tracking, expiry alerts, CT log monitoring
- **Technology Fingerprinting** - Identify web technologies, frameworks, CDNs
- **DNS Monitoring** - Track DNS record changes, email security (SPF/DKIM/DMARC)
- **Vulnerability Scanning** - Nuclei integration for automated vuln detection
- **URL Enumeration** - Historical URL discovery from Wayback, CommonCrawl, and other sources
- **Subdomain Takeover Detection** - Identify vulnerable subdomains susceptible to takeover
- **API Discovery** - Automatic detection of Swagger, OpenAPI, and GraphQL endpoints
- **Email Enumeration** - Discover email addresses and patterns for target domains
- **Alerting** - Slack and email notifications for findings
- **Reporting** - Generate reports in multiple formats (JSON, Markdown, HTML)
- **Persistence** - Track changes over time with local database
- **Trend Analysis** - Historical trend tracking and change detection over time
- **Parallel Execution** - Run multiple scans concurrently with configurable workers

## Quick Start

### Prerequisites

- Docker Desktop (macOS, Linux, or Windows with WSL2)
- ~2GB disk space for the Docker image
- Python 3.11+ (only required if running outside Docker)

### Installation

```bash
# Clone or download this directory
cd asm-tool

# Initialize (creates config, builds image)
./asm.sh init

# Edit your configuration
nano config.yaml
```

### Basic Usage

```bash
# Run a full scan on a domain
./asm.sh scan example.com

# Run with parallel execution (faster)
./asm.sh shell
python -m asm scan example.com --parallel --workers 5

# Or run individual modules
./asm.sh discover example.com    # Subdomain enumeration
./asm.sh ports example.com       # Port scanning
./asm.sh certs example.com       # Certificate checks
./asm.sh vulns example.com       # Vulnerability scan
./asm.sh takeover example.com    # Subdomain takeover detection
./asm.sh apis example.com        # API endpoint discovery
./asm.sh emails example.com      # Email enumeration
./asm.sh urls example.com        # Historical URL discovery
./asm.sh trends example.com      # Trend analysis

# Check status
./asm.sh status

# Generate report
./asm.sh report
```

### Interactive Mode

```bash
# Drop into a shell inside the container
./asm.sh shell

# Then run commands directly
python -m asm discover example.com
python -m asm portscan --all-known
python -m asm vulnscan --severity critical,high
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
  
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    from_addr: "alerts@yourdomain.com"
    to_addr: "security@yourdomain.com"

# Scanning configuration
scanning:
  # Common ports to scan
  ports: "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,8080,8443,8888,9000,9443"
  
  # Nuclei severity filter
  nuclei_severity: "medium,high,critical"
  
  # Use only passive reconnaissance (no active scanning)
  passive_only: false
  
  # Rate limit for scans (requests per second)
  rate_limit: 100

# External API integrations (optional)
shodan:
  enabled: false
  api_key: "your-shodan-api-key"

censys:
  api_id: "your-censys-api-id"
  api_secret: "your-censys-api-secret"

virustotal:
  api_key: "your-virustotal-api-key"

hunter:
  api_key: "your-hunter-api-key"

# Scheduling (cron expressions)
schedule:
  # Full scan daily at 6 AM
  full_scan: "0 6 * * *"
  
  # Certificate check every 6 hours
  cert_check: "0 */6 * * *"
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `discover <domain>` | Enumerate subdomains |
| `portscan <domain>` | Scan ports on discovered assets |
| `certificates <domain>` | Check SSL/TLS certificates |
| `fingerprint <domain>` | Identify technologies |
| `dns <domain>` | Check DNS records |
| `vulnscan <domain>` | Run Nuclei vulnerability scan |
| `urls <domain>` | Enumerate historical URLs from web archives |
| `takeover <domain>` | Detect subdomain takeover vulnerabilities |
| `apis <domain>` | Discover API endpoints and specifications |
| `emails <domain>` | Enumerate email addresses for domain |
| `scan <domain>` | Run all of the above |
| `report` | Generate a report |
| `status` | Show database statistics |
| `trends <domain>` | Show historical trend analysis and change tracking |

### Options

```bash
# Full scan with options
python -m asm scan example.com --parallel --workers 5  # Parallel execution
python -m asm scan example.com --notify                # Send notifications on findings

# Subdomain discovery
python -m asm discover example.com --passive-only

# Port scanning
python -m asm portscan example.com -p 80,443,8080
python -m asm portscan --all-known           # Scan all discovered subdomains
python -m asm portscan --all-known --workers 10  # Parallel port scanning

# Certificate monitoring
python -m asm certificates --all-known --days-warning 14

# Vulnerability scanning
python -m asm vulnscan --severity critical,high
python -m asm vulnscan --templates cves  # Specific template tags

# Historical trend analysis
python -m asm trends example.com                    # Show all trends (last 30 days)
python -m asm trends example.com --days 60           # Show trends over last 60 days
python -m asm trends example.com --type subdomains  # Show subdomain trends only
python -m asm trends example.com --type ports        # Show port trends only
python -m asm trends example.com --type vulnerabilities # Show vulnerability trends only
python -m asm trends example.com --format json     # Output as JSON
python -m asm trends example.com --alert-threshold critical  # Highlight critical changes only

# Reporting
python -m asm report --format html --output /app/reports/report.html
python -m asm report --format json > report.json
```

The `--all-known` flag is a powerful pattern used across multiple commands to operate on all previously discovered subdomains for a domain.

## Data Persistence

All data is stored in the `./data` directory:

- `asm.db` - TinyDB database with all discovered assets
- `schedules.json` - Scheduled scan configurations

Reports are saved to `./reports`.

## Scheduling

For automated scans, you have several options:

### Option 1: Host cron (recommended)

Add to your Mac's crontab:

```bash
# Run full scan daily at 6 AM
0 6 * * * cd /path/to/asm-tool && ./asm.sh scan example.com >> logs/scan.log 2>&1

# Certificate check every 6 hours
0 */6 * * * cd /path/to/asm-tool && ./asm.sh certs >> logs/certs.log 2>&1
```

### Option 2: Docker compose with scheduler

```bash
# Start the scheduler service
docker compose --profile scheduled up -d
```

### Option 3: launchd (macOS)

Create `~/Library/LaunchAgents/com.asm.scan.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.asm.scan</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/asm-tool/asm.sh</string>
        <string>scan</string>
        <string>example.com</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>6</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
</dict>
</plist>
```

Then: `launchctl load ~/Library/LaunchAgents/com.asm.scan.plist`

## Notifications

### Slack

1. Create a Slack webhook: https://api.slack.com/messaging/webhooks
2. Add to config.yaml:

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

### Email

```yaml
notifications:
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    from_addr: "alerts@yourdomain.com"
    to_addr: "security@yourdomain.com"
```

**Note**: For Gmail, you'll need to generate an app password for SMTP authentication.

## External API Integrations

### Shodan (optional)

Adds passive reconnaissance via Shodan's database:

```yaml
shodan:
  enabled: true
  api_key: "your-shodan-api-key"
```

## Troubleshooting

### Build fails

```bash
# Rebuild without cache
docker build --no-cache -t asm-tool .
```

### Scan times out

Increase timeouts or reduce scope:

```bash
# Scan specific ports only
./asm.sh shell
python -m asm portscan example.com -p 80,443
```

### Permission denied

```bash
chmod +x asm.sh
```

### Port scanning doesn't work

On macOS, Docker runs in a VM. For accurate port scanning, ensure `network_mode: host` is set (which it is by default in the compose file).

## Architecture

```
asm-tool/
├── asm/
│   ├── __init__.py
│   ├── __main__.py              # CLI entry point (Click framework)
│   ├── core/                    # Business logic layer
│   │   ├── config.py            # YAML configuration management
│   │   ├── database.py          # Database facade (delegates to repositories)
│   │   ├── helpers.py           # Shared utilities (resolve_targets)
│   │   ├── notifier.py          # Slack/email notifications
│   │   ├── reporter.py          # Multi-format report generation
│   │   ├── scheduler.py         # Cron job management
│   │   ├── validation.py        # Input validation
│   │   ├── error_handler.py     # Error handling utilities
│   │   └── parallel_runner.py   # Parallel execution orchestration
│   ├── repositories/            # Data access layer (TinyDB)
│   │   ├── base.py              # BaseRepository class
│   │   ├── domain.py            # Domain/subdomain storage
│   │   ├── asset.py             # Ports, certs, tech, DNS
│   │   ├── finding.py           # Vulnerabilities, takeovers
│   │   ├── discovery.py         # URLs, APIs, emails
│   │   └── analytics.py         # Snapshots, trends, change events
│   ├── modules/                 # Scanning modules
│   │   ├── subdomains.py        # Subdomain enumeration
│   │   ├── ports.py             # Port scanning (nmap)
│   │   ├── certificates.py      # SSL/TLS monitoring
│   │   ├── technologies.py      # Tech fingerprinting
│   │   ├── dns_monitor.py       # DNS record tracking
│   │   ├── nuclei_scanner.py    # Vulnerability scanning
│   │   ├── urls.py              # URL enumeration (gau)
│   │   ├── takeover.py          # Subdomain takeover detection
│   │   ├── api_discovery.py     # API endpoint discovery
│   │   ├── emails.py            # Email enumeration
│   │   └── change_tracker.py    # Change tracking
│   └── constants/               # Extracted constants
│       ├── api_paths.py         # Common API paths to probe
│       └── takeover_fingerprints.py  # Service fingerprints
├── tests/
│   ├── conftest.py              # Shared fixtures (mock_db, mock_config)
│   ├── unit/                    # Unit tests
│   └── integration/             # Integration tests
├── data/                        # Persistent data (asm.db)
├── reports/                     # Generated reports
├── Dockerfile
├── docker-compose.yaml
├── requirements.txt
├── config.example.yaml
├── asm.sh                       # Helper script
└── README.md
```

## Security Considerations

- This tool performs active scanning - only use on domains you own or have permission to test
- API keys in config.yaml should be protected (don't commit to git)
- The container runs with host networking for accurate scanning
- Consider rate limiting when scanning production systems

## API Reference

The ASM Tool follows a modular architecture with well-defined public APIs:

### Core Modules (`asm/core/`)

#### Database (`database.py`)
```python
from asm.core.database import Database

db = Database(Path('/app/data/asm.db'))

# Subdomain management
db.add_subdomain('example.com', 'www.example.com')  # -> bool
subdomains = db.get_subdomains('example.com')  # -> List[str]

# Port management
db.add_port('www.example.com', 443, 'https', 'nginx/1.18.0')  # -> bool
ports = db.get_ports('www.example.com')  # -> List[Dict]

# Certificate management
db.add_certificate('www.example.com', cert_info)  # -> bool (new cert)
certs = db.get_expiring_certificates(days=30)  # -> List[Dict]

# URL management
urls_data = db.add_urls_bulk('example.com', url_results)  # -> Dict[str, int]
all_urls = db.get_urls('example.com')  # -> List[Dict]

# Takeover management
is_new_takeover = db.add_takeover(takeover_data)  # -> bool
takeovers = db.get_takeovers('example.com')  # -> List[Dict]

# API management
is_new_api = db.add_api(api_spec)  # -> bool
apis = db.get_apis('example.com')  # -> List[Dict]

# Email management
email_counts = db.add_emails_bulk('example.com', email_results)  # -> Dict[str, int]
emails = db.get_emails('example.com')  # -> List[Dict]
```

#### Configuration (`config.py`)
```python
from asm.core.config import Config

config = Config.from_file(Path('/app/config.yaml'))

# Access configuration
domains = config.domains  # List[str]
slack_enabled = config.slack_enabled  # bool
nuclei_severity = config.nuclei_severity  # str
hunter_api_key = config.hunter_api_key  # str (for email enumeration)
shodan_enabled = config.shodan_enabled  # bool
```

#### Scheduler (`scheduler.py`)
```python
from asm.core.scheduler import Scheduler

scheduler = Scheduler(config, data_dir)

# Add scheduled job
scheduler.add_job(('example.com', 'test.com'), '0 6 * * *', 'full')

# List all jobs
jobs = scheduler.list_jobs()  # -> List[dict]

# Generate crontab entries
crontab_content = scheduler.generate_crontab()  # -> str
scheduler.export_crontab(Path('/path/to/crontab'))
```

#### Notifier (`notifier.py`)
```python
from asm.core.notifier import Notifier

notifier = Notifier(config)

# Send Slack notification
notifier.send_slack("Critical vulnerability found!", webhook_url)

# Send email notification
notifier.send_email("Scan Report", report_content, recipients)

# Send summary notification
notifier.send_summary('example.com', scan_results)
```

#### Reporter (`reporter.py`)
```python
from asm.core.reporter import Reporter

reporter = Reporter(db)

# Generate reports in different formats
table_report = reporter.generate(data, format='table')
json_report = reporter.generate(data, format='json')
markdown_report = reporter.generate(data, format='markdown')
html_report = reporter.generate(data, format='html')
```

#### Scanning Modules (`asm/modules/`)

All scanning modules follow a consistent pattern:
```python
from asm.modules.subdomains import SubdomainEnumerator
from asm.modules.urls import URLEnumerator
from asm.modules.takeover import TakeoverDetector
from asm.modules.api_discovery import APIDiscovery
from asm.modules.emails import EmailEnumerator
from asm.core.config import Config

config = Config()

# Subdomain enumeration
enumerator = SubdomainEnumerator(config)
subdomains = enumerator.enumerate('example.com', passive_only=False)

# URL enumeration
url_enum = URLEnumerator(config)
urls = url_enum.enumerate('example.com', include_subdomains=True)

# Takeover detection
detector = TakeoverDetector(config)
vulns = detector.check_subdomains(['sub1.example.com', 'sub2.example.com'])

# API discovery
api_disc = APIDiscovery(config)
apis = api_disc.discover(['api.example.com', 'app.example.com'])

# Email enumeration
email_enum = EmailEnumerator(config)
emails = email_enum.enumerate('example.com')
```

### CLI Entry Point (`__main__.py`)

Commands are organized using Click:
```bash
# Subdomain enumeration
python -m asm discover example.com

# Port scanning
python -m asm portscan example.com --ports 80,443

# URL enumeration
python -m asm urls example.com --include-subs --interesting-only

# Takeover detection
python -m asm takeover example.com --all-known --verbose

# API discovery
python -m asm apis example.com --all-known

# Email enumeration
python -m asm emails example.com

# Full scan (all modules)
python -m asm scan example.com
```

## Developer Guide

### Development Workflow

1. **Setup Development Environment**
   ```bash
   # Clone repository
   git clone https://github.com/yourusername/asm-tool.git
   cd asm-tool

   # Create virtual environment
   python -m venv venv
   source venv/bin/activate

   # Install dependencies
   pip install -r requirements.txt
   ```

2. **Run Tests During Development**
   ```bash
   # Run unit tests (mock external dependencies)
   pytest tests/unit/ -v

   # Run with coverage
   pytest tests/ --cov=asm --cov-report=html
   ```

3. **Code Style Guidelines**

   - **PEP 8 Compliant**: Follow Python style guide
   - **Type Hints**: Use type annotations for all public methods
   - **Docstrings**: Add docstrings for all public classes and functions
   - **Error Handling**: Use proper exception handling with context
   - **Constants**: Extract magic values to `asm/constants/` files
   - **Testing**: Write tests for new functionality before implementing
   - **Git Commits**: Use conventional commit format (feat:, fix:, refactor:, docs:)

4. **Module Development**

   When adding a new scanning module:

   a. Create module file in `asm/modules/your_module.py`
   b. Import required dependencies from `asm.core.config` and `asm.core.database`
   c. Inherit from appropriate base class if applicable
   d. Add comprehensive docstrings
   e. Write unit tests in `tests/unit/test_your_module.py`
   f. Update `tests/conftest.py` with shared fixtures if needed
   g. Run all tests to ensure nothing breaks
   h. Update this README and `CONTRIBUTING.md` with usage examples

5. **Testing Strategy**

   - **Unit Tests**: Mock external tools (nmap, subfinder, nuclei, etc.)
   - **Integration Tests**: Test cross-module interactions
   - **Coverage Target**: Maintain 90%+ coverage (enforced in pytest.ini)
   - **Markers**: Use `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.external`

6. **Architecture Decisions**

   - **TinyDB**: Chosen for simplicity and self-contained deployment
   - **Click Framework**: CLI interface for consistent command structure
   - **Threading**: Used for parallel scans (subdomains, API discovery)
   - **Rich Library**: Terminal output formatting and progress bars

### Adding New Features

1. Create feature branch
2. Implement feature with tests
3. Update documentation
4. Submit pull request with clear description
5. Link PR to issue (if applicable)

### Project Structure Reference

```
asm-tool/
├── asm/
│   ├── __init__.py
│   ├── __main__.py              # CLI entry point (Click framework)
│   ├── core/                    # Business logic layer
│   │   ├── config.py            # Configuration management
│   │   ├── database.py          # Database facade
│   │   ├── helpers.py           # Shared utilities
│   │   ├── notifier.py          # Slack/email alerts
│   │   ├── reporter.py          # Report generation
│   │   ├── scheduler.py         # Cron scheduling
│   │   ├── validation.py        # Input validation
│   │   ├── error_handler.py     # Error handling
│   │   └── parallel_runner.py   # Parallel execution
│   ├── repositories/            # Data access layer
│   │   ├── base.py              # BaseRepository class
│   │   ├── domain.py            # Domain/subdomain storage
│   │   ├── asset.py             # Ports, certs, tech, DNS
│   │   ├── finding.py           # Vulnerabilities, takeovers
│   │   ├── discovery.py         # URLs, APIs, emails
│   │   └── analytics.py         # Snapshots, trends
│   ├── constants/               # Extracted constants
│   │   ├── api_paths.py         # Common API paths
│   │   └── takeover_fingerprints.py  # Service fingerprints
│   └── modules/                 # Scanning modules
│       ├── subdomains.py        # Subdomain enumeration
│       ├── ports.py             # Port scanning
│       ├── certificates.py      # SSL/TLS monitoring
│       ├── technologies.py      # Tech fingerprinting
│       ├── dns_monitor.py       # DNS record tracking
│       ├── nuclei_scanner.py    # Vulnerability scanning
│       ├── urls.py              # URL enumeration
│       ├── takeover.py          # Subdomain takeover detection
│       ├── api_discovery.py     # API endpoint discovery
│       ├── emails.py            # Email enumeration
│       └── change_tracker.py    # Change tracking
├── tests/
│   ├── conftest.py              # Shared fixtures (mock_db, mock_config)
│   ├── unit/                    # Unit tests
│   └── integration/             # Integration tests
├── data/                        # Persistent data (asm.db)
├── reports/                     # Generated reports
├── Dockerfile                   # Container definition
├── docker-compose.yaml          # Docker orchestration
├── requirements.txt             # Python dependencies
├── config.example.yaml          # Example configuration
├── pytest.ini                   # Test configuration (90% coverage)
├── README.md                    # Project documentation
├── CONTRIBUTING.md              # Contribution guide
└── CHANGELOG.md                 # Version history
```

### Common Issues and Solutions

**Port Scanning in Docker**
- **Issue**: nmap may show different results in container
- **Solution**: Use `network_mode: host` in docker-compose.yaml (already configured)

**Subfinder Not Found**
- **Issue**: Subfinder binary not in PATH
- **Solution**: Install via package manager: `brew install subfinder` (macOS)

**Permission Denied on nmap**
- **Issue**: nmap requires privileges for certain scan types
- **Solution**: Use `-sT` (TCP connect scan) instead of `-sS` (SYN scan)

## License

MIT

## Contributing

Pull requests welcome. For major changes, please open an issue first.
