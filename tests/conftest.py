"""
Shared pytest fixtures for unit tests
"""

import pytest
from unittest.mock import Mock, MagicMock


@pytest.fixture
def mock_db():
    """Create a mock database object with common methods"""
    db = MagicMock()

    # Default return values for common methods
    db.get_all_subdomains.return_value = []
    db.get_subdomains.return_value = []
    db.get_all_domains.return_value = []
    db.get_ports.return_value = []
    db.get_all_ports.return_value = []
    db.get_certificates.return_value = []
    db.get_all_certificates.return_value = []
    db.get_findings.return_value = []
    db.get_all_findings.return_value = []
    db.get_urls.return_value = []
    db.get_all_urls.return_value = []
    db.get_takeovers.return_value = []
    db.get_apis.return_value = []
    db.get_emails.return_value = []
    db.get_trend_summary.return_value = {}
    db.get_attack_surface_summary.return_value = {
        "domains": 0,
        "subdomains": 0,
        "ports": 0,
        "certificates": 0,
        "urls": 0,
        "interesting_urls": 0,
        "apis": 0,
        "emails": 0,
        "takeovers": 0,
        "findings": 0,
        "last_scan": None,
    }

    return db


@pytest.fixture
def mock_config():
    """Create a mock configuration object"""
    config = MagicMock()
    config.domains = ["example.com"]
    config.data_dir = "/tmp/asm-test"
    config.output_dir = "/tmp/asm-test/output"
    config.threads = 10
    config.timeout = 30
    config.notifications = MagicMock()
    config.notifications.enabled = False

    # Timeout settings
    config.timeout_subfinder = 300
    config.timeout_nmap = 120
    config.timeout_nuclei = 1800
    config.timeout_gau = 600
    config.timeout_http = 10
    config.timeout_dns = 5

    # Nuclei optimization settings
    config.nuclei_concurrency = 25
    config.nuclei_batch_size = 25
    config.nuclei_exclude_tags = "dos,fuzz,brute"
    config.nuclei_retries = 1
    config.scan_rate_limit = 100

    return config
