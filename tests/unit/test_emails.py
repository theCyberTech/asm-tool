import pytest
from unittest.mock import patch, MagicMock
from asm.modules.emails import EmailEnumerator


class TestEmailEnumerator:

    @pytest.fixture
    def enumerator(self, mock_config):
        return EmailEnumerator(mock_config)

    def test_enumerate_parallel_execution(self, enumerator):
        """Test that enumerate runs sources in parallel"""
        call_order = []

        def mock_phonebook(domain):
            call_order.append("phonebook")
            return {"phonebook@example.com"}

        def mock_skymem(domain):
            call_order.append("skymem")
            return {"skymem@example.com"}

        def mock_ct_logs(domain):
            call_order.append("ct_logs")
            return {"ct@example.com"}

        with patch.object(enumerator, "_query_phonebook", side_effect=mock_phonebook):
            with patch.object(enumerator, "_query_skymem", side_effect=mock_skymem):
                with patch.object(enumerator, "_search_ct_logs", side_effect=mock_ct_logs):
                    result = enumerator.enumerate("example.com")

        # All sources should have been called
        assert "phonebook" in call_order
        assert "skymem" in call_order
        assert "ct_logs" in call_order

        # Results should include all emails
        assert result["total"] == 3
        assert "phonebook@example.com" in result["emails"]
        assert "skymem@example.com" in result["emails"]
        assert "ct@example.com" in result["emails"]

    def test_enumerate_with_hunter_api_key(self, mock_config):
        """Test enumerate includes Hunter when API key is set"""
        mock_config.hunter_api_key = "test_key"
        enumerator = EmailEnumerator(mock_config)

        def mock_hunter(domain, api_key):
            return ({"hunter@example.com"}, {"pattern": "{first}.{last}"})

        def mock_empty(domain):
            return set()

        with patch.object(enumerator, "_query_hunter", side_effect=mock_hunter):
            with patch.object(enumerator, "_query_phonebook", return_value=set()):
                with patch.object(enumerator, "_query_skymem", return_value=set()):
                    with patch.object(enumerator, "_search_ct_logs", return_value=set()):
                        result = enumerator.enumerate("example.com")

        assert "hunter@example.com" in result["emails"]
        assert "hunter.io" in result["sources"]
        assert "{first}.{last}" in result["patterns"]

    def test_enumerate_handles_source_failures(self, enumerator):
        """Test enumerate continues when individual sources fail"""
        def mock_phonebook(domain):
            raise Exception("Network error")

        def mock_skymem(domain):
            return {"skymem@example.com"}

        def mock_ct_logs(domain):
            raise Exception("Timeout")

        with patch.object(enumerator, "_query_phonebook", side_effect=mock_phonebook):
            with patch.object(enumerator, "_query_skymem", side_effect=mock_skymem):
                with patch.object(enumerator, "_search_ct_logs", side_effect=mock_ct_logs):
                    result = enumerator.enumerate("example.com")

        # Should still get results from working source
        assert result["total"] == 1
        assert "skymem@example.com" in result["emails"]
        assert "skymem.info" in result["sources"]
        # Failed sources should not be in sources list
        assert "phonebook.cz" not in result["sources"]
        assert "ct_logs" not in result["sources"]

    def test_enumerate_empty_results(self, enumerator):
        """Test enumerate handles all sources returning empty"""
        with patch.object(enumerator, "_query_phonebook", return_value=set()):
            with patch.object(enumerator, "_query_skymem", return_value=set()):
                with patch.object(enumerator, "_search_ct_logs", return_value=set()):
                    result = enumerator.enumerate("example.com")

        assert result["total"] == 0
        assert result["emails"] == []
        assert result["sources"] == []

    def test_is_valid_email(self, enumerator):
        """Test email validation"""
        # Valid emails (note: example.com is in invalid patterns)
        assert enumerator._is_valid_email("user@company.org") is True
        assert enumerator._is_valid_email("first.last@company.org") is True

        # Invalid emails
        assert enumerator._is_valid_email("") is False
        assert enumerator._is_valid_email("noat") is False
        assert enumerator._is_valid_email("test@example.com") is False  # example.com filtered
        assert enumerator._is_valid_email("noreply@company.org") is False  # noreply filtered

    def test_extract_emails_from_text(self, enumerator):
        """Test email extraction from text"""
        text = """
        Contact us at john@company.org or jane@company.org
        Also check other@different.com for more info
        Invalid: notanemail, @company.org
        """
        emails = enumerator._extract_emails_from_text(text, "company.org")

        assert "john@company.org" in emails
        assert "jane@company.org" in emails
        # Should not include email from different domain
        assert "other@different.com" not in emails

    def test_detect_pattern(self, enumerator):
        """Test email pattern detection"""
        emails = {
            "john.smith@company.org",
            "jane.doe@company.org",
            "bob.wilson@company.org",
        }
        pattern = enumerator._detect_pattern(emails, "company.org")
        assert "first.last" in pattern

    def test_verify_email(self, enumerator):
        """Test email verification"""
        result = enumerator.verify_email("user@company.org")
        assert result["valid_format"] is True
        assert result["role_account"] is False

        result = enumerator.verify_email("admin@company.org")
        assert result["role_account"] is True

        result = enumerator.verify_email("support@company.org")
        assert result["role_account"] is True

    def test_enumerate_multiple(self, enumerator):
        """Test enumerating multiple domains in parallel"""
        def mock_enumerate(domain):
            return {
                "domain": domain,
                "emails": [f"user@{domain}"],
                "total": 1,
                "by_source": {},
                "patterns": [],
                "sources": [],
            }

        with patch.object(enumerator, "enumerate", side_effect=mock_enumerate):
            result = enumerator.enumerate_multiple(
                ["example1.com", "example2.com"], workers=2
            )

        assert result["total_emails"] == 2
        assert "example1.com" in result["domains"]
        assert "example2.com" in result["domains"]
