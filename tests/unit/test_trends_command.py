"""
Unit tests for trends CLI command
"""

import pytest
import tempfile
import os
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from asm.__main__ import cli


@pytest.fixture
def runner():
    """Create a Click test runner"""
    return CliRunner()


@pytest.fixture
def temp_data_dir():
    """Create a temporary directory for test data"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestTrendsCommand:
    """Test suite for trends CLI command"""

    def test_trends_no_history(self, runner, mock_db, temp_data_dir):
        """Test trends command with no historical data"""
        mock_db.get_trend_summary.return_value = {
            "has_history": False,
            "message": "No historical data available",
        }

        with patch("asm.__main__.Database", return_value=mock_db):
            with patch("asm.__main__.Path.mkdir"):
                result = runner.invoke(
                    cli, ["--data-dir", temp_data_dir, "trends", "example.com"]
                )

        assert result.exit_code == 0
        assert "No historical scan data available for example.com" in result.output

    def test_trends_json_format(self, runner, mock_db, temp_data_dir):
        """Test trends command with JSON output"""
        mock_db.get_trend_summary.return_value = {
            "has_history": True,
            "domain": "example.com",
            "days": 30,
        }

        with patch("asm.__main__.Database", return_value=mock_db):
            with patch("asm.__main__.Path.mkdir"):
                result = runner.invoke(
                    cli,
                    [
                        "--data-dir",
                        temp_data_dir,
                        "trends",
                        "example.com",
                        "--format",
                        "json",
                    ],
                )

        assert result.exit_code == 0
        assert '"domain": "example.com"' in result.output
        assert '"days": 30' in result.output

    def test_trends_type_filter_subdomains_only(self, runner, mock_db, temp_data_dir):
        """Test filtering by asset type"""
        mock_db.get_trend_summary.return_value = {
            "has_history": True,
            "subdomains": {
                "current": 15,
                "previous": 10,
                "delta": 5,
            },
            "ports": {"current": 8, "previous": 5, "delta": 3},
            "certificates": {"current": 3, "previous": 2, "delta": 1},
            "vulnerabilities": {
                "current": {"total": 20},
                "previous": {"total": 15},
                "delta": {"total": 5},
            },
        }

        with patch("asm.__main__.Database", return_value=mock_db):
            with patch("asm.__main__.Path.mkdir"):
                result = runner.invoke(
                    cli,
                    [
                        "--data-dir",
                        temp_data_dir,
                        "trends",
                        "example.com",
                        "--type",
                        "subdomains",
                    ],
                )

        assert result.exit_code == 0
        assert "Subdomains" in result.output

    def test_trends_alert_threshold(self, runner, mock_db, temp_data_dir):
        """Test different alert thresholds"""
        changes = [
            {"severity": "critical", "description": "Critical issue"},
            {"severity": "high", "description": "High issue"},
            {"severity": "medium", "description": "Medium issue"},
        ]

        mock_db.get_trend_summary.return_value = {
            "has_history": True,
            "recent_changes": changes,
        }

        with patch("asm.__main__.Database", return_value=mock_db):
            with patch("asm.__main__.Path.mkdir"):
                result = runner.invoke(
                    cli,
                    [
                        "--data-dir",
                        temp_data_dir,
                        "trends",
                        "example.com",
                        "--alert-threshold",
                        "critical",
                    ],
                )

        assert result.exit_code == 0

        with patch("asm.__main__.Database", return_value=mock_db):
            with patch("asm.__main__.Path.mkdir"):
                result = runner.invoke(
                    cli,
                    [
                        "--data-dir",
                        temp_data_dir,
                        "trends",
                        "example.com",
                        "--alert-threshold",
                        "high",
                    ],
                )

        assert result.exit_code == 0

        with patch("asm.__main__.Database", return_value=mock_db):
            with patch("asm.__main__.Path.mkdir"):
                result = runner.invoke(
                    cli,
                    [
                        "--data-dir",
                        temp_data_dir,
                        "trends",
                        "example.com",
                        "--alert-threshold",
                        "medium",
                    ],
                )

        assert result.exit_code == 0
