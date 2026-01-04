"""
Configuration management for ASM Tool
"""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class Config:
    """Configuration container for ASM tool"""

    domains: List[str] = field(default_factory=list)

    # Notification settings
    slack_webhook: str = ""
    slack_enabled: bool = False
    email_enabled: bool = False
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    email_from: str = ""
    email_to: str = ""

    # Scanning settings
    default_ports: str = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
    nuclei_severity: str = "medium,high,critical"
    passive_only: bool = False
    scan_rate_limit: int = 100  # requests per second

    # External API keys
    shodan_api_key: str = ""
    shodan_enabled: bool = False
    censys_api_id: str = ""
    censys_api_secret: str = ""
    virustotal_api_key: str = ""
    hunter_api_key: str = ""

    # Schedule settings
    full_scan_cron: str = "0 6 * * *"
    cert_check_cron: str = "0 */6 * * *"

    # Tool paths (usually auto-detected)
    nmap_path: str = "nmap"
    subfinder_path: str = "subfinder"
    httpx_path: str = "httpx"
    nuclei_path: str = "nuclei"

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        """Load configuration from YAML file"""
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        config = cls()

        # Map YAML structure to flat config
        config.domains = data.get("domains", [])

        # Notifications
        notif = data.get("notifications", {})
        slack = notif.get("slack", {})
        config.slack_enabled = slack.get("enabled", False)
        config.slack_webhook = slack.get("webhook_url", "")

        email = notif.get("email", {})
        config.email_enabled = email.get("enabled", False)
        config.email_smtp_host = email.get("smtp_host", "")
        config.email_smtp_port = email.get("smtp_port", 587)
        config.email_from = email.get("from_addr", "")
        config.email_to = email.get("to_addr", "")

        # Scanning
        scanning = data.get("scanning", {})
        config.default_ports = scanning.get("ports", config.default_ports)
        config.nuclei_severity = scanning.get("nuclei_severity", config.nuclei_severity)
        config.passive_only = scanning.get("passive_only", False)
        config.scan_rate_limit = scanning.get("rate_limit", 100)

        # External APIs
        shodan = data.get("shodan", {})
        config.shodan_enabled = shodan.get("enabled", False)
        config.shodan_api_key = shodan.get("api_key", "")

        censys = data.get("censys", {})
        config.censys_api_id = censys.get("api_id", "")
        config.censys_api_secret = censys.get("api_secret", "")

        config.virustotal_api_key = data.get("virustotal", {}).get("api_key", "")
        config.hunter_api_key = data.get("hunter", {}).get("api_key", "")

        # Schedule
        schedule = data.get("schedule", {})
        config.full_scan_cron = schedule.get("full_scan", config.full_scan_cron)
        config.cert_check_cron = schedule.get("cert_check", config.cert_check_cron)

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            "domains": self.domains,
            "notifications": {
                "slack": {
                    "enabled": self.slack_enabled,
                    "webhook_url": self.slack_webhook,
                },
                "email": {
                    "enabled": self.email_enabled,
                    "smtp_host": self.email_smtp_host,
                    "smtp_port": self.email_smtp_port,
                    "from_addr": self.email_from,
                    "to_addr": self.email_to,
                },
            },
            "scanning": {
                "ports": self.default_ports,
                "nuclei_severity": self.nuclei_severity,
                "passive_only": self.passive_only,
                "rate_limit": self.scan_rate_limit,
            },
            "shodan": {"enabled": self.shodan_enabled, "api_key": self.shodan_api_key},
            "schedule": {
                "full_scan": self.full_scan_cron,
                "cert_check": self.cert_check_cron,
            },
        }
