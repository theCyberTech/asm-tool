"""
Unit tests for ChangeDetector module
"""

import pytest
from unittest.mock import Mock

from asm.modules.change_tracker import ChangeDetector


@pytest.fixture
def mock_db():
    """Create a mock database instance"""
    db = Mock()
    return db


@pytest.fixture
def detector(mock_db):
    """Create a ChangeDetector instance with mock database"""
    return ChangeDetector(mock_db)


class TestChangeDetector:
    """Test suite for ChangeDetector class"""

    def test_initialization(self, mock_db):
        """Test that ChangeDetector initializes correctly"""
        det = ChangeDetector(mock_db)
        assert det.db == mock_db

    def test_detect_changes_first_scan(self, detector, mock_db):
        """Test change detection with no previous snapshot"""
        mock_db.get_latest_snapshot.return_value = None

        current_state = {
            "subdomains": ["sub1.example.com", "sub2.example.com"],
            "ports": ["sub1.example.com:80"],
            "risk_score": 10,
        }

        changes = detector.detect_changes("example.com", current_state)

        assert changes["is_first_scan"] == True
        assert changes["new_subdomains"] == current_state["subdomains"]
        assert changes["removed_subdomains"] == []
        assert changes["new_ports"] == current_state["ports"]
        assert changes["closed_ports"] == []
        assert changes["risk_delta"] == 0

    def test_detect_changes_with_history(self, detector, mock_db):
        """Test change detection with previous snapshot"""
        mock_db.get_latest_snapshot.return_value = {
            "subdomains": ["sub1.example.com", "sub2.example.com"],
            "ports": ["sub1.example.com:80"],
            "certificates": [{"host": "sub1.example.com", "fingerprint": "old-fp"}],
            "risk_score": 10,
        }

        current_state = {
            "subdomains": ["sub1.example.com", "sub2.example.com", "sub3.example.com"],
            "ports": ["sub1.example.com:80", "sub2.example.com:443"],
            "certificates": [{"host": "sub1.example.com", "fingerprint": "new-fp"}],
            "risk_score": 15,
        }

        changes = detector.detect_changes("example.com", current_state)

        assert "sub3.example.com" in changes["new_subdomains"]
        assert len(changes["new_subdomains"]) == 1
        assert len(changes["removed_subdomains"]) == 0
        assert "sub2.example.com:443" in changes["new_ports"]
        assert len(changes["new_ports"]) == 1
        assert changes["risk_delta"] == 5

    def test_detect_certificate_changes(self, detector, mock_db):
        """Test certificate change detection"""
        mock_db.get_latest_snapshot.return_value = {
            "certificates": [{"host": "sub1.example.com", "fingerprint": "old-fp"}],
        }

        current_state = {
            "certificates": [{"host": "sub1.example.com", "fingerprint": "new-fp"}],
        }

        changes = detector.detect_changes("example.com", current_state)

        assert len(changes["certificate_changes"]) == 1
        cert_change = changes["certificate_changes"][0]
        assert cert_change["host"] == "sub1.example.com"
        assert cert_change["type"] == "changed"
        assert cert_change["previous_fingerprint"] == "old-fp"
        assert cert_change["new_fingerprint"] == "new-fp"

    def test_detect_removed_assets(self, detector, mock_db):
        """Test detection of removed assets"""
        mock_db.get_latest_snapshot.return_value = {
            "subdomains": ["sub1.example.com", "sub2.example.com"],
            "ports": ["sub1.example.com:80", "sub2.example.com:443"],
            "risk_score": 10,
        }

        current_state = {
            "subdomains": ["sub1.example.com"],
            "ports": ["sub1.example.com:80"],
            "risk_score": 5,
        }

        changes = detector.detect_changes("example.com", current_state)

        assert "sub2.example.com" in changes["removed_subdomains"]
        assert "sub2.example.com:443" in changes["closed_ports"]
        assert len(changes["removed_subdomains"]) == 1
        assert len(changes["closed_ports"]) == 1

    def test_calculate_risk(self, detector):
        """Test risk score calculation"""
        vulnerabilities = {"critical": 2, "high": 3, "medium": 5, "low": 10}
        asset_count = 25

        risk = detector.calculate_risk(vulnerabilities, asset_count)

        expected_base = 2 * 10 + 3 * 5 + 5 * 2 + 10 * 1
        density_factor = min(25 / 50.0, 2.0)
        expected = expected_base * (1 + density_factor * 0.1)

        assert abs(risk - expected) < 0.01

    def test_calculate_risk_no_assets(self, detector):
        """Test risk calculation with zero assets"""
        vulnerabilities = {"critical": 1, "high": 0, "medium": 0, "low": 0}
        asset_count = 0

        risk = detector.calculate_risk(vulnerabilities, asset_count)

        expected = 10 * (1 + 0 * 0.1)
        assert abs(risk - expected) < 0.01

    def test_generate_change_events_new_subdomain(self, detector):
        """Test event generation for new subdomain"""
        changes = {
            "new_subdomains": ["new.example.com"],
            "removed_subdomains": [],
            "new_ports": [],
            "closed_ports": [],
            "new_vulnerabilities": [],
            "certificate_changes": [],
            "risk_delta": 5,
        }

        events = detector.generate_change_events("example.com", changes)

        subdomain_events = [e for e in events if e["change_type"] == "subdomain_added"]
        assert len(subdomain_events) == 1
        assert (
            subdomain_events[0]["description"]
            == "New subdomain discovered: new.example.com"
        )
        assert subdomain_events[0]["severity"] == "info"

    def test_generate_change_events_risk_increase(self, detector):
        """Test event generation for risk increase"""
        changes = {
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_ports": [],
            "closed_ports": [],
            "new_vulnerabilities": [],
            "certificate_changes": [],
            "risk_delta": 15,
        }

        events = detector.generate_change_events("example.com", changes)

        risk_events = [e for e in events if "risk" in e["change_type"]]
        assert len(risk_events) == 1
        assert risk_events[0]["change_type"] == "risk_increased"
        assert risk_events[0]["severity"] == "high"
        assert "15" in risk_events[0]["description"]

    def test_identify_significant_changes_critical_vuln(self, detector):
        """Test identification of critical vulnerability changes"""
        changes = {
            "new_vulnerabilities": [
                {"severity": "critical", "count": 1, "type": "count_increase"}
            ],
        }

        significant = detector._identify_significant_changes(
            changes, previous_risk=10, current_risk=10
        )

        critical_vulns = [
            s for s in significant if s["type"] == "critical_vulnerabilities"
        ]
        assert len(critical_vulns) == 1
        assert critical_vulns[0]["severity"] == "critical"

    def test_identify_significant_changes_risk_spike(self, detector):
        """Test identification of risk spikes"""
        changes = {
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_ports": [],
            "closed_ports": [],
            "new_vulnerabilities": [],
            "certificate_changes": [],
            "risk_delta": 25,
        }

        significant = detector._identify_significant_changes(
            changes, previous_risk=10, current_risk=35
        )

        risk_spikes = [s for s in significant if s["type"] == "risk_spike"]
        assert len(risk_spikes) == 1
        assert risk_spikes[0]["severity"] == "critical"

    def test_identify_significant_changes_subdomain_surge(self, detector):
        """Test identification of subdomain surges"""
        changes = {
            "new_subdomains": ["sub1", "sub2", "sub3", "sub4", "sub5", "sub6"],
            "removed_subdomains": [],
        }

        significant = detector._identify_significant_changes(
            changes, previous_risk=10, current_risk=10
        )

        surges = [s for s in significant if s["type"] == "subdomain_surge"]
        assert len(surges) == 1
        assert surges[0]["severity"] == "medium"

    def test_generate_change_events_new_vulnerabilities(self, detector):
        """Test event generation for new vulnerabilities"""
        changes = {
            "new_vulnerabilities": [
                {"severity": "critical", "count": 1, "type": "count_increase"},
                {"severity": "high", "count": 2, "type": "count_increase"},
            ],
        }

        events = detector.generate_change_events("example.com", changes)

        vuln_events = [e for e in events if e["change_type"] == "vulnerability_added"]
        assert len(vuln_events) == 2

        critical_events = [e for e in vuln_events if e["severity"] == "critical"]
        assert len(critical_events) == 1

        high_events = [e for e in vuln_events if e["severity"] == "high"]
        assert len(high_events) == 1
