"""
Unit tests for ASM Core Database module
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, Mock

from asm.core.database import Database
from tests.fixtures import (
    TEST_DOMAIN,
    TEST_SUBDOMAINS,
    TEST_CERT_INFO,
    TEST_TECH_INFO,
    TEST_FINDING,
    TempDirectory,
)


class TestDatabase:
    """Test cases for Database class"""

    def test_database_initialization(self):
        """Test database initialization with temporary file"""
        with TempDirectory() as temp_dir:
            db_path = temp_dir / "test.db"
            db = Database(db_path)

            assert db.db_path == db_path
            assert db.db is not None
            assert hasattr(db, "subdomains")
            assert hasattr(db, "ports")
            assert hasattr(db, "certificates")
            assert hasattr(db, "technologies")
            assert hasattr(db, "dns_records")
            assert hasattr(db, "findings")
            assert hasattr(db, "scan_history")
            assert hasattr(db, "domains")
            assert hasattr(db, "urls")
            assert hasattr(db, "takeovers")
            assert hasattr(db, "apis")
            assert hasattr(db, "emails")

            db.close()

    def test_add_domain_new(self):
        """Test adding a new domain"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            result = db.add_domain(TEST_DOMAIN)

            assert result is True
            domains = db.get_domains()
            assert TEST_DOMAIN in domains

            db.close()

    def test_add_domain_existing(self):
        """Test adding an existing domain"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add domain first time
            db.add_domain(TEST_DOMAIN)

            # Add same domain again
            result = db.add_domain(TEST_DOMAIN)

            assert result is False
            domains = db.get_domains()
            assert len(domains) == 1
            assert TEST_DOMAIN in domains

            db.close()

    def test_add_subdomain_new(self):
        """Test adding a new subdomain"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            result = db.add_subdomain(TEST_DOMAIN, TEST_SUBDOMAINS[0])

            assert result is True
            subdomains = db.get_subdomains(TEST_DOMAIN)
            assert TEST_SUBDOMAINS[0] in subdomains

            # Should also add the root domain
            domains = db.get_domains()
            assert TEST_DOMAIN in domains

            db.close()

    def test_add_subdomain_existing(self):
        """Test adding an existing subdomain"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add subdomain first time
            db.add_subdomain(TEST_DOMAIN, TEST_SUBDOMAINS[0])

            # Add same subdomain again
            result = db.add_subdomain(TEST_DOMAIN, TEST_SUBDOMAINS[0])

            assert result is False
            subdomains = db.get_subdomains(TEST_DOMAIN)
            assert len(subdomains) == 1

            db.close()

    def test_add_port_new(self):
        """Test adding a new port"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            result = db.add_port("www.example.com", 80, "http", "nginx/1.18.0")

            assert result is True
            port_info = db.get_port("www.example.com", 80)
            assert port_info is not None
            assert port_info["port"] == 80
            assert port_info["service"] == "http"
            assert port_info["version"] == "nginx/1.18.0"
            assert port_info["state"] == "open"

            db.close()

    def test_add_port_existing(self):
        """Test adding an existing port with updated info"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add port first time
            db.add_port("www.example.com", 80, "http", "nginx/1.18.0")

            # Add same port with updated version
            result = db.add_port("www.example.com", 80, "http", "nginx/1.20.0")

            assert result is False
            port_info = db.get_port("www.example.com", 80)
            assert port_info["version"] == "nginx/1.20.0"  # Should be updated

            db.close()

    def test_add_certificate_new(self):
        """Test adding a new certificate"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            result = db.add_certificate("www.example.com", TEST_CERT_INFO)

            assert result is True
            cert_info = db.get_certificate("www.example.com")
            assert cert_info is not None
            assert cert_info["host"] == "www.example.com"
            assert cert_info["issuer"] == TEST_CERT_INFO["issuer"]
            assert cert_info["days_until_expiry"] == TEST_CERT_INFO["days_until_expiry"]

            db.close()

    def test_add_certificate_updated(self):
        """Test adding a certificate with updated fingerprint"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add certificate first time
            db.add_certificate("www.example.com", TEST_CERT_INFO)

            # Update certificate with different fingerprint
            updated_cert = TEST_CERT_INFO.copy()
            updated_cert["fingerprint"] = (
                "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:EE"
            )
            updated_cert["issuer"] = "Different CA"

            result = db.add_certificate("www.example.com", updated_cert)

            assert result is True  # Should return True when certificate changed
            cert_info = db.get_certificate("www.example.com")
            assert cert_info["fingerprint"] == updated_cert["fingerprint"]
            assert cert_info["issuer"] == "Different CA"

            db.close()

    def test_add_technologies(self):
        """Test adding technology fingerprint"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            db.add_technologies("www.example.com", TEST_TECH_INFO)

            tech_info = db.get_technologies("www.example.com")
            assert tech_info is not None
            assert tech_info["host"] == "www.example.com"
            assert tech_info["status_code"] == TEST_TECH_INFO["status_code"]
            assert tech_info["title"] == TEST_TECH_INFO["title"]
            assert set(tech_info["technologies"]) == set(TEST_TECH_INFO["technologies"])

            db.close()

    def test_save_and_get_dns_records(self):
        """Test saving and retrieving DNS records"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            records = {
                "A": ["192.168.1.1", "192.168.1.2"],
                "MX": ["mail.example.com"],
                "TXT": ["v=spf1 include:_spf.google.com ~all"],
            }

            db.save_dns_records(TEST_DOMAIN, records)

            # Note: DNS records are stored internally, need to check changes
            changes = db.check_dns_changes(TEST_DOMAIN, records)
            assert changes["new"] == {}
            assert changes["removed"] == {}

            db.close()

    def test_check_dns_changes_new_records(self):
        """Test DNS change detection with new records"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Save initial records
            initial_records = {"A": ["192.168.1.1"]}
            db.save_dns_records(TEST_DOMAIN, initial_records)

            # Check with additional records
            new_records = {
                "A": ["192.168.1.1", "192.168.1.2"],  # Added one
                "MX": ["mail.example.com"],  # New type
            }

            changes = db.check_dns_changes(TEST_DOMAIN, new_records)

            assert "192.168.1.2" in changes["new"]["A"]
            assert "mail.example.com" in changes["new"]["MX"]
            assert changes["removed"] == {}

            db.close()

    def test_check_dns_changes_removed_records(self):
        """Test DNS change detection with removed records"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Save initial records
            initial_records = {
                "A": ["192.168.1.1", "192.168.1.2"],
                "MX": ["mail.example.com"],
            }
            db.save_dns_records(TEST_DOMAIN, initial_records)

            # Check with fewer records
            new_records = {"A": ["192.168.1.1"]}  # Removed A record and MX

            changes = db.check_dns_changes(TEST_DOMAIN, new_records)

            assert changes["new"] == {}
            assert "192.168.1.2" in changes["removed"]["A"]
            assert "mail.example.com" in changes["removed"]["MX"]

            db.close()

    def test_add_url_new(self):
        """Test adding a new URL"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            result = db.add_url(TEST_DOMAIN, "https://www.example.com/page")

            assert result is True
            urls = db.get_urls(TEST_DOMAIN)
            assert "https://www.example.com/page" in urls

            db.close()

    def test_add_url_existing(self):
        """Test adding an existing URL"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add URL first time
            db.add_url(TEST_DOMAIN, "https://www.example.com/page")

            # Add same URL again
            result = db.add_url(TEST_DOMAIN, "https://www.example.com/page")

            assert result is False
            urls = db.get_urls(TEST_DOMAIN)
            assert len(urls) == 1

            db.close()

    def test_add_url_interesting(self):
        """Test adding an interesting URL"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            result = db.add_url(
                TEST_DOMAIN, "https://www.example.com/admin", interesting=True
            )

            assert result is True
            interesting_urls = db.get_urls(TEST_DOMAIN, interesting_only=True)
            assert "https://www.example.com/admin" in interesting_urls

            db.close()

    def test_add_finding_new(self):
        """Test adding a new vulnerability finding"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            result = db.add_finding(TEST_FINDING)

            assert result is True
            findings = db.get_findings(host=TEST_DOMAIN)
            assert len(findings) == 1
            assert findings[0]["template_id"] == TEST_FINDING["template_id"]

            db.close()

    def test_add_finding_existing(self):
        """Test adding an existing finding"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add finding first time
            db.add_finding(TEST_FINDING)

            # Add same finding again
            result = db.add_finding(TEST_FINDING)

            assert result is False
            findings = db.get_findings(host=TEST_DOMAIN)
            assert len(findings) == 1

            db.close()

    def test_get_statistics(self):
        """Test getting database statistics"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add some test data
            db.add_domain(TEST_DOMAIN)
            db.add_subdomain(TEST_DOMAIN, TEST_SUBDOMAINS[0])
            db.add_port("www.example.com", 80)
            db.add_certificate("www.example.com", TEST_CERT_INFO)
            db.add_finding(TEST_FINDING)

            stats = db.get_statistics()

            assert stats["domains"] == 1
            assert stats["subdomains"] == 1
            assert stats["ports"] == 1
            assert stats["certificates"] == 1
            assert stats["findings"] == 1
            assert "last_scan" in stats

            db.close()

    def test_get_expiring_certificates(self):
        """Test getting certificates expiring within N days"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add certificate that expires in 20 days
            expiring_cert = TEST_CERT_INFO.copy()
            expiring_cert["days_until_expiry"] = 20
            db.add_certificate("www.example.com", expiring_cert)

            # Add certificate that expires in 40 days
            future_cert = TEST_CERT_INFO.copy()
            future_cert["host"] = "future.example.com"
            future_cert["days_until_expiry"] = 40
            db.add_certificate("future.example.com", future_cert)

            expiring = db.get_expiring_certificates(30)

            assert len(expiring) == 1
            assert expiring[0]["host"] == "www.example.com"

            db.close()

    def test_get_open_findings(self):
        """Test getting only open findings"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Add open finding
            db.add_finding(TEST_FINDING)

            open_findings = db.get_open_findings()

            assert len(open_findings) == 1
            assert open_findings[0]["status"] == "open"

            db.close()

    def test_close_database(self):
        """Test closing database connection"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Should not raise an exception
            db.close()

    def test_database_persistence(self):
        """Test that data persists across database instances"""
        with TempDirectory() as temp_dir:
            db_path = temp_dir / "test.db"

            # Create first instance and add data
            db1 = Database(db_path)
            db1.add_domain(TEST_DOMAIN)
            db1.add_subdomain(TEST_DOMAIN, TEST_SUBDOMAINS[0])
            db1.close()

            # Create second instance and verify data exists
            db2 = Database(db_path)
            domains = db2.get_domains()
            subdomains = db2.get_subdomains(TEST_DOMAIN)

            assert TEST_DOMAIN in domains
            assert TEST_SUBDOMAINS[0] in subdomains

            db2.close()

    def test_edge_case_empty_database_operations(self):
        """Test operations on empty database"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            # Operations on empty data should return empty results
            assert db.get_domains() == []
            assert db.get_subdomains(TEST_DOMAIN) == []
            assert db.get_port("nonexistent.com", 80) is None
            assert db.get_certificate("nonexistent.com") is None
            assert db.get_technologies("nonexistent.com") is None
            assert db.get_findings() == []

            stats = db.get_statistics()
            assert stats["domains"] == 0
            assert stats["subdomains"] == 0

            db.close()

    def test_edge_case_very_long_domain_name(self):
        """Test handling very long domain names"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            long_domain = "a" * 100 + ".com"
            result = db.add_subdomain(long_domain, "sub." + long_domain)

            assert result is True
            subdomains = db.get_subdomains(long_domain)
            assert len(subdomains) == 1

            db.close()

    def test_edge_case_special_characters_in_data(self):
        """Test handling special characters in stored data"""
        with TempDirectory() as temp_dir:
            db = Database(temp_dir / "test.db")

            special_domain = "test-üñîçødé.com"
            special_title = "Test & Special <Characters> 'Quotes'"

            result = db.add_subdomain(special_domain, "www." + special_domain)
            assert result is True

            # Add technology with special characters
            tech_info = TEST_TECH_INFO.copy()
            tech_info["title"] = special_title
            db.add_technologies("www." + special_domain, tech_info)

            retrieved = db.get_technologies("www." + special_domain)
            assert retrieved["title"] == special_title

            db.close()
