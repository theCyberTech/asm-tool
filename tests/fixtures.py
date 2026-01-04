"""
Test fixtures and utilities for ASM Tool tests
"""

import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock
import json
from datetime import datetime, timedelta, timezone

# Test data
TEST_DOMAIN = "example.com"
TEST_SUBDOMAINS = ["www.example.com", "api.example.com", "test.example.com"]
TEST_PORTS = [80, 443, 8080]
TEST_CERT_INFO = {
    "host": "www.example.com",
    "port": 443,
    "subject": "www.example.com",
    "issuer": "Let's Encrypt Authority X3",
    "serial_number": "123456789",
    "not_before": datetime.now(timezone.utc).isoformat(),
    "not_after": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
    "days_until_expiry": 90,
    "fingerprint": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
    "san": ["www.example.com", "example.com"],
    "signature_algorithm": "sha256WithRSAEncryption",
    "version": "v3",
}

TEST_TECH_INFO = {
    "host": "www.example.com",
    "status_code": 200,
    "title": "Example Website",
    "technologies": ["Nginx", "React", "Node.js"],
    "server": "nginx/1.18.0",
    "content_length": 12345,
    "redirect_url": "",
    "headers": {"Server": "nginx/1.18.0", "Content-Type": "text/html"},
}

TEST_FINDING = {
    "host": TEST_DOMAIN,
    "template_id": "cve-2021-1234",
    "name": "Test Vulnerability",
    "severity": "high",
    "matched_at": f"https://{TEST_DOMAIN}/vuln",
    "extracted_results": ["sensitive_data"],
    "description": "Test vulnerability description",
    "reference": ["https://cve.mitre.org/CGI-BIN/CVE.cgi?CVE-2021-1234"],
}

TEST_CONFIG_DATA = {
    "domains": [TEST_DOMAIN],
    "notifications": {
        "slack": {"enabled": False, "webhook_url": ""},
        "email": {
            "enabled": False,
            "smtp_host": "",
            "smtp_port": 587,
            "from_addr": "",
            "to_addr": "",
        },
    },
    "scanning": {
        "ports": "80,443,8080",
        "nuclei_severity": "medium,high,critical",
        "passive_only": False,
        "rate_limit": 100,
    },
    "shodan": {"enabled": False, "api_key": ""},
    "schedule": {"full_scan": "0 6 * * *", "cert_check": "0 */6 * * *"},
}


class MockConfig:
    """Mock configuration for testing"""

    def __init__(self, **kwargs):
        self.domains = kwargs.get("domains", [TEST_DOMAIN])
        self.slack_webhook = kwargs.get("slack_webhook", "")
        self.slack_enabled = kwargs.get("slack_enabled", False)
        self.email_enabled = kwargs.get("email_enabled", False)
        self.email_smtp_host = kwargs.get("email_smtp_host", "")
        self.email_smtp_port = kwargs.get("email_smtp_port", 587)
        self.email_from = kwargs.get("email_from", "")
        self.email_to = kwargs.get("email_to", "")
        self.default_ports = kwargs.get("default_ports", "80,443,8080")
        self.nuclei_severity = kwargs.get("nuclei_severity", "medium,high,critical")
        self.passive_only = kwargs.get("passive_only", False)
        self.scan_rate_limit = kwargs.get("scan_rate_limit", 100)
        self.shodan_api_key = kwargs.get("shodan_api_key", "")
        self.shodan_enabled = kwargs.get("shodan_enabled", False)
        self.censys_api_id = kwargs.get("censys_api_id", "")
        self.censys_api_secret = kwargs.get("censys_api_secret", "")
        self.virustotal_api_key = kwargs.get("virustotal_api_key", "")
        self.hunter_api_key = kwargs.get("hunter_api_key", "")
        self.full_scan_cron = kwargs.get("full_scan_cron", "0 6 * * *")
        self.cert_check_cron = kwargs.get("cert_check_cron", "0 */6 * * *")
        self.nmap_path = kwargs.get("nmap_path", "nmap")
        self.subfinder_path = kwargs.get("subfinder_path", "subfinder")
        self.httpx_path = kwargs.get("httpx_path", "httpx")
        self.nuclei_path = kwargs.get("nuclei_path", "nuclei")


class TempDirectory:
    """Context manager for temporary directories"""

    def __init__(self):
        self.temp_dir = None

    def __enter__(self):
        self.temp_dir = tempfile.mkdtemp()
        return Path(self.temp_dir)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir:
            shutil.rmtree(self.temp_dir, ignore_errors=True)


def create_mock_database():
    """Create a mock database with test data"""
    mock_db = Mock()
    mock_db.add_subdomain = Mock(return_value=True)
    mock_db.get_subdomains = Mock(return_value=TEST_SUBDOMAINS)
    mock_db.get_all_subdomains = Mock(return_value=TEST_SUBDOMAINS)
    mock_db.add_port = Mock(return_value=True)
    mock_db.get_port = Mock(return_value=None)
    mock_db.add_certificate = Mock(return_value=True)
    mock_db.get_certificate = Mock(return_value=TEST_CERT_INFO)
    mock_db.add_technologies = Mock()
    mock_db.get_technologies = Mock(return_value=TEST_TECH_INFO)
    mock_db.add_finding = Mock(return_value=True)
    mock_db.get_statistics = Mock(
        return_value={
            "domains": 1,
            "subdomains": len(TEST_SUBDOMAINS),
            "ports": 3,
            "certificates": 1,
            "findings": 1,
            "last_scan": datetime.utcnow().isoformat(),
        }
    )
    mock_db.close = Mock()
    return mock_db


def create_sample_nmap_xml():
    """Create sample nmap XML output for testing"""
    return """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -p 80,443,8080 example.com">
<host>
<status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" product="nginx" version="1.18.0" method="probed" conf="10"></service>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="https" product="nginx" version="1.18.0" method="probed" conf="10"></service>
</port>
</ports>
</host>
</nmaprun>"""


def create_sample_subfinder_output():
    """Create sample subfinder output for testing"""
    return "\n".join(TEST_SUBDOMAINS)


def create_sample_httpx_json():
    """Create sample httpx JSON output for testing"""
    return json.dumps(
        [
            {
                "url": f"https://{TEST_DOMAIN}",
                "status_code": 200,
                "title": "Example Website",
                "tech": ["Nginx", "React"],
                "webserver": "nginx/1.18.0",
                "content_length": 12345,
                "final_url": f"https://{TEST_DOMAIN}",
            }
        ]
    )


def create_sample_nuclei_json():
    """Create sample nuclei JSON output for testing"""
    return json.dumps(
        [
            {
                "template-id": "cve-2021-1234",
                "info": {
                    "name": "Test Vulnerability",
                    "severity": "high",
                    "description": "Test vulnerability description",
                },
                "host": TEST_DOMAIN,
                "matched-at": f"https://{TEST_DOMAIN}/vuln",
                "extracted-results": ["sensitive_data"],
                "reference": ["https://cve.mitre.org/CGI-BIN/CVE.cgi?CVE-2021-1234"],
            }
        ]
    )
