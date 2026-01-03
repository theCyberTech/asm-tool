# ASM Tool - Attack Surface Management

A self-contained, Docker-based attack surface management tool designed for security practitioners managing small-to-medium organizations.

## Features

- **Subdomain Enumeration** - Multiple sources: subfinder, assetfinder, crt.sh, HackerTarget
- **Port Scanning** - nmap-based scanning with service detection
- **Certificate Monitoring** - SSL/TLS cert tracking, expiry alerts, CT log monitoring
- **Technology Fingerprinting** - Identify web technologies, frameworks, CDNs
- **DNS Monitoring** - Track DNS record changes, email security (SPF/DKIM/DMARC)
- **Vulnerability Scanning** - Nuclei integration for automated vuln detection
- **Alerting** - Slack and email notifications for findings
- **Reporting** - Generate reports in multiple formats (JSON, Markdown, HTML)
- **Persistence** - Track changes over time with local database

## Quick Start

### Prerequisites

- Docker Desktop for Mac
- ~2GB disk space for the image

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
./asm.sh scan crewai.com

# Or run individual modules
./asm.sh discover crewai.com    # Subdomain enumeration
./asm.sh ports crewai.com       # Port scanning
./asm.sh certs crewai.com       # Certificate checks
./asm.sh vulns crewai.com       # Vulnerability scan

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
python -m asm discover crewai.com
python -m asm portscan --all-known
python -m asm vulnscan --severity critical,high
```

## Configuration

Edit `config.yaml` to customize:

```yaml
# Domains to monitor
domains:
  - crewai.com

# Slack notifications
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/..."

# Scanning settings
scanning:
  ports: "21,22,80,443,3306,8080,8443"
  nuclei_severity: "medium,high,critical"
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
| `scan <domain>` | Run all of the above |
| `report` | Generate a report |
| `status` | Show database statistics |

### Options

```bash
# Subdomain discovery
python -m asm discover crewai.com --passive-only

# Port scanning
python -m asm portscan crewai.com -p 80,443,8080
python -m asm portscan --all-known  # Scan all discovered subdomains

# Certificate monitoring
python -m asm certificates --all-known --days-warning 14

# Vulnerability scanning
python -m asm vulnscan --severity critical,high
python -m asm vulnscan --templates cves  # Specific template tags

# Reporting
python -m asm report --format html --output /app/reports/report.html
python -m asm report --format json > report.json
```

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
0 6 * * * cd /path/to/asm-tool && ./asm.sh scan crewai.com >> logs/scan.log 2>&1

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
        <string>crewai.com</string>
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
    webhook_url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
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
python -m asm portscan crewai.com -p 80,443
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
│   ├── __main__.py          # CLI entry point
│   ├── core/
│   │   ├── config.py        # Configuration management
│   │   ├── database.py      # TinyDB persistence
│   │   ├── notifier.py      # Slack/email alerts
│   │   ├── reporter.py      # Report generation
│   │   └── scheduler.py     # Cron scheduling
│   └── modules/
│       ├── subdomains.py    # Subdomain enumeration
│       ├── ports.py         # Port scanning
│       ├── certificates.py  # SSL/TLS monitoring
│       ├── technologies.py  # Tech fingerprinting
│       ├── dns_monitor.py   # DNS record tracking
│       └── nuclei_scanner.py # Vulnerability scanning
├── Dockerfile
├── docker-compose.yaml
├── requirements.txt
├── config.example.yaml
├── asm.sh                   # Helper script
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
```

#### Configuration (`config.py`)
```python
from asm.core.config import Config

config = Config.from_file(Path('/app/config.yaml'))

# Access configuration
domains = config.domains  # List[str]
slack_enabled = config.slack_enabled  # bool
nuclei_severity = config.nuclei_severity  # str
```

#### Scanning Modules (`asm/modules/`)

All scanning modules follow a consistent pattern:
```python
from asm.modules.subdomains import SubdomainEnumerator
from asm.core.config import Config

config = Config()
enumerator = SubdomainEnumerator(config)

results = enumerator.enumerate('example.com', passive_only=False)
```

### CLI Entry Point (`__main__.py`)

Commands are organized using Click:
```bash
# Subdomain enumeration
python -m asm discover example.com

# Port scanning
python -m asm portscan example.com --ports 80,443

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
   f. Update `tests/fixtures.py` with test data if needed
   g. Run all tests to ensure nothing breaks
   h. Update this README and `CONTRIBUTING.md` with usage examples

5. **Testing Strategy**

   - **Unit Tests**: Mock external tools (nmap, subfinder, nuclei, etc.)
   - **Integration Tests**: Test cross-module interactions
   - **Coverage Target**: Maintain 70%+ coverage for modules

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
│   ├── __main__.py          # CLI entry point
│   ├── core/
│   │   ├── config.py        # Configuration management
│   │   ├── database.py      # TinyDB persistence
│   │   ├── notifier.py      # Slack/email alerts
│   │   ├── reporter.py      # Report generation
│   │   └── scheduler.py     # Cron scheduling
│   ├── constants/
│   │   ├── __init__.py
│   │   ├── api_paths.py
│   │   └── timeouts.py
│   └── modules/
│       ├── subdomains.py    # Subdomain enumeration
│       ├── ports.py         # Port scanning
│       ├── certificates.py  # SSL/TLS monitoring
│       ├── technologies.py  # Tech fingerprinting
│       ├── dns_monitor.py   # DNS record tracking
│       ├── nuclei_scanner.py # Vulnerability scanning
│       ├── urls.py          # URL enumeration
│       ├── takeover.py      # Subdomain takeover detection
│       ├── api_discovery.py # API endpoint discovery
│       └── emails.py        # Email enumeration
├── tests/
│   ├── fixtures.py           # Test data and utilities
│   └── unit/              # Unit tests for core modules
├── data/                   # Persistent data (asm.db)
├── reports/                # Generated reports
├── Dockerfile              # Container definition
├── docker-compose.yaml      # Docker orchestration
├── requirements.txt         # Python dependencies
├── config.example.yaml     # Example configuration
├── pytest.ini              # Test configuration
├── README.md               # Project documentation
├── REFACTOR_PLAN.md        # Refactoring roadmap
├── CONTRIBUTING.md         # Contribution guide
└── CHANGELOG.md            # Version history
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
