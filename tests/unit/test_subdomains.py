"""
Unit tests for Subdomains module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from asm.modules.subdomains import SubdomainEnumerator


class TestSubdomainEnumerator:
    """Test cases for SubdomainEnumerator class"""

    def test_subdomain_enumerator_initialization(self):
        """Test enumerator initialization"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        assert enumerator.config == config

    @patch("subprocess.run")
    def test_run_subfinder_success(self, mock_run):
        """Test subfinder execution with successful result"""
        mock_run.return_value = MagicMock(stdout="sub1.example.com\nsub2.example.com\n")

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._run_subfinder("example.com")

        expected = {"sub1.example.com", "sub2.example.com"}
        assert result == expected
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_run_subfinder_not_found(self, mock_run):
        """Test subfinder execution when tool not found"""
        mock_run.side_effect = FileNotFoundError()

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._run_subfinder("example.com")

        assert result == set()

    @patch("subprocess.run")
    def test_run_assetfinder_success(self, mock_run):
        """Test assetfinder execution with successful result"""
        mock_run.return_value = MagicMock(
            stdout="asset1.example.com\nasset2.example.com\n"
        )

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._run_assetfinder("example.com")

        expected = {"asset1.example.com", "asset2.example.com"}
        assert result == expected
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_run_assetfinder_not_found(self, mock_run):
        """Test assetfinder execution when tool not found"""
        mock_run.side_effect = FileNotFoundError()

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._run_assetfinder("example.com")

        assert result == set()

    def test_filter_results_valid(self):
        """Test filtering of valid subdomains"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        subdomains = {
            "www.example.com",
            "api.example.com",
            "*.example.com",
            "test.example.com",
        }

        result = enumerator._filter_results(subdomains, "example.com")

        assert "*.example.com" not in result
        assert "www.example.com" in result

    def test_filter_results_empty_list(self):
        """Test filtering of empty list"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._filter_results(set(), "example.com")

        assert result == set()

    def test_filter_results_all_wildcards(self):
        """Test filtering when all are wildcards"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        subdomains = {"*.example.com", "*.test.example.com", "*.dev.example.com"}

        result = enumerator._filter_results(subdomains, "example.com")

        assert result == set()

    def test_filter_results_case_insensitive(self):
        """Test filtering is case-insensitive"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        subdomains = {"WWW.example.com", "API.example.com", "test.EXAMPLE.COM"}

        result = enumerator._filter_results(subdomains, "example.com")

        assert len(result) >= 2

    def test_filter_results_removes_long_domains(self):
        """Test filtering removes domains over 253 chars"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        long_domain = "a" * 254 + ".example.com"
        subdomains = {long_domain, "www.example.com"}

        result = enumerator._filter_results(subdomains, "example.com")

        assert long_domain not in result
        assert "www.example.com" in result

    def test_filter_results_removes_invalid_chars(self):
        """Test filtering removes domains with invalid characters"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        subdomains = {"www.example.com", "test$example.com", "user@example.com"}

        result = enumerator._filter_results(subdomains, "example.com")

        assert "test$example.com" not in result
        assert "user@example.com" not in result
        assert "www.example.com" in result

    def test_filter_results_requires_domain_suffix(self):
        """Test filtering requires subdomain to end with target domain"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        subdomains = {"www.example.com", "www.test.com", "www.other.com"}

        result = enumerator._filter_results(subdomains, "example.com")

        assert "www.example.com" in result
        assert "www.test.com" not in result
        assert "www.other.com" not in result

    @patch("asm.modules.subdomains.requests.get")
    def test_query_crtsh_success(self, mock_get):
        """Test crt.sh query with successful result"""
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com"},
        ]
        mock_get.return_value = mock_response

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._query_crtsh("example.com")

        assert "sub1.example.com" in result
        assert "sub2.example.com" in result

    @patch("asm.modules.subdomains.requests.get")
    def test_query_crtsh_handles_multiline(self, mock_get):
        """Test crt.sh query handles multiline entries"""
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {"name_value": "sub1.example.com\nsub2.example.com"}
        ]
        mock_get.return_value = mock_response

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._query_crtsh("example.com")

        assert "sub1.example.com" in result
        assert "sub2.example.com" in result

    @patch("asm.modules.subdomains.requests.get")
    def test_query_crtsh_exception(self, mock_get):
        """Test crt.sh query with exception"""
        mock_get.side_effect = Exception("Network error")

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._query_crtsh("example.com")

        assert result == set()

    def test_query_shodan_no_api_key(self):
        """Test Shodan query when API key not configured"""
        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._query_shodan("example.com")

        assert result == set()

    @patch("asm.modules.subdomains.requests.get")
    def test_query_hackertarget_success(self, mock_get):
        """Test HackerTarget query with successful result"""
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.text = "sub1.example.com,other-data\nsub2.example.com,other-data"

        mock_get.return_value = mock_response

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._query_hackertarget("example.com")

        assert "sub1.example.com" in result
        assert "sub2.example.com" in result

    @patch("asm.modules.subdomains.requests.get")
    def test_query_hackertarget_error_in_response(self, mock_get):
        """Test HackerTarget query with error in response"""
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.text = "error message"

        mock_get.return_value = mock_response

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator._query_hackertarget("example.com")

        assert result == set()

    @patch("asm.modules.subdomains.SubdomainEnumerator._run_subfinder")
    @patch("asm.modules.subdomains.SubdomainEnumerator._run_assetfinder")
    @patch("asm.modules.subdomains.SubdomainEnumerator._query_crtsh")
    @patch("asm.modules.subdomains.SubdomainEnumerator._query_hackertarget")
    def test_enumerate_passive_mode(
        self, mock_hackertarget, mock_crtsh, mock_assetfinder, mock_subfinder
    ):
        """Test enumeration in passive mode only"""
        mock_subfinder.return_value = {"sub.example.com"}
        mock_assetfinder.return_value = set()
        mock_crtsh.return_value = set()
        mock_hackertarget.return_value = set()

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator.enumerate("example.com", passive_only=True)

        assert "sub.example.com" in result
        mock_subfinder.assert_called_once_with("example.com")

    @patch("asm.modules.subdomains.SubdomainEnumerator._run_subfinder")
    @patch("asm.modules.subdomains.SubdomainEnumerator._run_assetfinder")
    @patch("asm.modules.subdomains.SubdomainEnumerator._query_crtsh")
    @patch("asm.modules.subdomains.SubdomainEnumerator._query_hackertarget")
    def test_enumerate_empty_results(
        self, mock_hackertarget, mock_crtsh, mock_assetfinder, mock_subfinder
    ):
        """Test enumeration with no results"""
        mock_subfinder.return_value = set()
        mock_assetfinder.return_value = set()
        mock_crtsh.return_value = set()
        mock_hackertarget.return_value = set()

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator.enumerate("example.com", passive_only=True)

        assert result == []

    @patch("asm.modules.subdomains.SubdomainEnumerator._run_subfinder")
    @patch("asm.modules.subdomains.SubdomainEnumerator._run_assetfinder")
    @patch("asm.modules.subdomains.SubdomainEnumerator._query_crtsh")
    @patch("asm.modules.subdomains.SubdomainEnumerator._query_hackertarget")
    def test_enumerate_duplicate_removal(
        self, mock_hackertarget, mock_crtsh, mock_assetfinder, mock_subfinder
    ):
        """Test that duplicate subdomains are removed"""
        mock_subfinder.return_value = {
            "sub.example.com",
            "sub.example.com",
            "www.example.com",
        }
        mock_assetfinder.return_value = set()
        mock_crtsh.return_value = set()
        mock_hackertarget.return_value = set()

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator.enumerate("example.com", passive_only=True)

        assert len(result) == 2
        assert "sub.example.com" in result
        assert "www.example.com" in result

    @patch("asm.modules.subdomains.SubdomainEnumerator._run_subfinder")
    @patch("asm.modules.subdomains.SubdomainEnumerator._run_assetfinder")
    @patch("asm.modules.subdomains.SubdomainEnumerator._query_crtsh")
    @patch("asm.modules.subdomains.SubdomainEnumerator._query_hackertarget")
    def test_enumerate_concurrent_execution(
        self, mock_hackertarget, mock_crtsh, mock_assetfinder, mock_subfinder
    ):
        """Test that all tools run concurrently"""
        mock_subfinder.return_value = {"sub1.example.com"}
        mock_assetfinder.return_value = {"sub2.example.com"}
        mock_crtsh.return_value = {"sub3.example.com"}
        mock_hackertarget.return_value = {"sub4.example.com"}

        config = Mock()
        config.shodan_enabled = False
        config.shodan_api_key = ""
        enumerator = SubdomainEnumerator(config)

        result = enumerator.enumerate("example.com", passive_only=True)

        assert len(result) == 4
        assert mock_subfinder.called
        assert mock_assetfinder.called
        assert mock_crtsh.called
        assert mock_hackertarget.called
