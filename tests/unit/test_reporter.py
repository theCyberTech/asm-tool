"""
Unit tests for ASM Reporter module
"""

import pytest
import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from asm.core.reporter import Reporter
from tests.fixtures import (
    TEST_DOMAIN,
    TEST_SUBDOMAINS,
    TEST_PORTS,
    TEST_FINDING,
    TEST_CERT_INFO,
)


class TestReporter:
    """Test cases for Reporter class"""

    def test_reporter_initialization(self):
        """Test reporter initialization with database"""
        mock_db = Mock()
        reporter = Reporter(mock_db)

        assert reporter.db == mock_db

    def test_generate_json_format(self):
        """Test JSON report generation"""
        mock_db = Mock()
        test_data = {"test": "data", "number": 42}
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="json")

        parsed = json.loads(result)
        assert parsed == test_data

    def test_generate_table_format(self):
        """Test ASCII table report generation"""
        mock_db = Mock()
        test_data = {
            "statistics": {
                "domains": 1,
                "subdomains": len(TEST_SUBDOMAINS),
                "ports": len(TEST_PORTS),
                "certificates": 1,
                "findings": 1,
            },
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomain_count": len(TEST_SUBDOMAINS),
                    "subdomains": TEST_SUBDOMAINS,
                    "findings": [TEST_FINDING],
                    "certificates": [TEST_CERT_INFO],
                }
            ],
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="table")

        assert "Attack Surface Summary" in result
        assert TEST_DOMAIN in result
        assert "1" in result  # domain count
        assert str(len(TEST_SUBDOMAINS)) in result  # subdomain count

    def test_generate_table_format_empty_data(self):
        """Test table report generation with empty data"""
        mock_db = Mock()
        test_data = {"statistics": {}, "domains": []}
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="table")

        assert "Attack Surface Summary" in result
        assert "0" in result  # Should show zeros

    def test_generate_markdown_format(self):
        """Test Markdown report generation"""
        mock_db = Mock()
        test_data = {
            "statistics": {
                "domains": 1,
                "subdomains": 5,
                "ports": 3,
                "certificates": 1,
                "findings": 2,
            },
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomain_count": 3,
                    "subdomains": TEST_SUBDOMAINS[:3],
                    "findings": [TEST_FINDING],
                    "certificates": [TEST_CERT_INFO],
                }
            ],
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="markdown")

        assert "# Attack Surface Management Report" in result
        assert "## Summary" in result
        assert f"## Domain: {TEST_DOMAIN}" in result
        assert "| Domains Tracked | 1 |" in result
        assert "| Subdomains Discovered | 5 |" in result
        assert f"- {TEST_SUBDOMAINS[0]}" in result
        assert "### Findings" in result
        assert "### Certificates" in result

    def test_generate_markdown_format_many_subdomains(self):
        """Test Markdown report with truncated subdomain list"""
        mock_db = Mock()
        many_subdomains = [f"sub{i}.{TEST_DOMAIN}" for i in range(25)]
        test_data = {
            "statistics": {"domains": 1, "subdomains": 25},
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomain_count": 25,
                    "subdomains": many_subdomains,
                    "findings": [],
                }
            ],
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="markdown")

        assert "- ... and 5 more" in result

    def test_generate_html_format(self):
        """Test HTML report generation"""
        mock_db = Mock()
        test_data = {
            "statistics": {"domains": 1, "subdomains": 5, "ports": 3, "findings": 2},
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomain_count": 3,
                    "subdomains": TEST_SUBDOMAINS[:3],
                    "findings": [TEST_FINDING],
                }
            ],
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="html")

        assert "<!DOCTYPE html>" in result
        assert "<title>Attack Surface Report</title>" in result
        assert "Attack Surface Management Report" in result
        assert TEST_DOMAIN in result
        assert "<table>" in result
        assert "<th>Subdomain</th>" in result

    def test_generate_default_format(self):
        """Test default report format (should be table)"""
        mock_db = Mock()
        test_data = {"statistics": {}}
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data)

        # Should default to table format
        assert "Attack Surface Summary" in result

    def test_generate_invalid_format(self):
        """Test report generation with invalid format"""
        mock_db = Mock()
        test_data = {"statistics": {}}
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="invalid")

        # Should default to table format for invalid input
        assert "Attack Surface Summary" in result

    def test_timestamp_inclusion(self):
        """Test that reports include timestamps"""
        mock_db = Mock()
        test_data = {
            "statistics": {},
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomain_count": 1,
                    "subdomains": TEST_SUBDOMAINS[:1],
                    "findings": [],
                }
            ],
        }
        reporter = Reporter(mock_db)

        # Test Markdown
        result_md = reporter.generate(test_data, format="markdown")
        assert "Generated:" in result_md
        assert "T" in result_md

        # Test HTML
        result_html = reporter.generate(test_data, format="html")
        assert "Generated:" in result_html
        assert "T" in result_html

    def test_edge_case_empty_findings_list(self):
        """Test report with empty findings list"""
        mock_db = Mock()
        test_data = {
            "statistics": {"domains": 1, "subdomains": 3, "findings": 0},
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomains": TEST_SUBDOMAINS[:3],
                    "findings": [],  # Empty findings
                }
            ],
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="table")

        assert "Attack Surface Summary" in result
        assert "0" in result

    def test_edge_case_missing_statistics(self):
        """Test report with missing statistics"""
        mock_db = Mock()
        test_data = {
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomain_count": len(TEST_SUBDOMAINS[:2]),
                    "subdomains": TEST_SUBDOMAINS[:2],
                    "findings": [],
                }
            ]
            # Missing 'statistics' key
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="markdown")

        # Should handle missing statistics gracefully
        assert TEST_DOMAIN in result
        assert "| Domains Tracked | 0 |" in result  # Should default to 0

    def test_edge_case_very_long_domain_names(self):
        """Test report with very long domain names"""
        mock_db = Mock()
        long_domain = "a" * 50 + ".com"
        test_data = {
            "statistics": {"domains": 1, "subdomains": 1},
            "domains": [
                {"domain": long_domain, "subdomains": [long_domain], "findings": []}
            ],
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="html")

        # Should include long domain names
        assert long_domain in result

    def test_edge_case_special_characters_in_findings(self):
        """Test report with special characters in finding names"""
        mock_db = Mock()
        special_finding = TEST_FINDING.copy()
        special_finding["name"] = 'Test <script>alert("XSS")</script> & "quotes"'
        special_finding["severity"] = "critical"

        test_data = {
            "statistics": {"domains": 1, "findings": 1},
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomains": TEST_SUBDOMAINS[:1],
                    "findings": [special_finding],
                }
            ],
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="html")

        # Should properly escape special characters in HTML
        assert "&quot;" in result or "&lt;" in result
        assert special_finding["template_id"] in result

    def test_findings_sorted_by_severity(self):
        """Test that findings are sorted by severity in table format"""
        mock_db = Mock()

        critical_finding = TEST_FINDING.copy()
        critical_finding["severity"] = "critical"
        critical_finding["template_id"] = "critical-1"

        medium_finding = TEST_FINDING.copy()
        medium_finding["severity"] = "medium"
        medium_finding["template_id"] = "medium-1"

        low_finding = TEST_FINDING.copy()
        low_finding["severity"] = "low"
        low_finding["template_id"] = "low-1"

        test_data = {
            "statistics": {"domains": 1, "findings": 3},
            "domains": [
                {
                    "domain": TEST_DOMAIN,
                    "subdomains": TEST_SUBDOMAINS[:1],
                    "findings": [
                        low_finding,
                        critical_finding,
                        medium_finding,
                    ],  # Unordered
                }
            ],
        }
        reporter = Reporter(mock_db)

        result = reporter.generate(test_data, format="table")

        # Critical should appear before high, which appears before medium, etc.
        critical_pos = result.find("critical-1")
        medium_pos = result.find("medium-1")
        low_pos = result.find("low-1")

        assert critical_pos < medium_pos < low_pos
