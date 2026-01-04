"""
Unit tests for ASM Core Notifier module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
import smtplib

from asm.core.notifier import Notifier, WebhookNotifier
from asm.core.config import Config
from tests.fixtures import MockConfig, TEST_DOMAIN


class TestNotifier:
    """Test cases for Notifier class"""

    def test_notifier_initialization(self):
        """Test notifier initialization with config"""
        config = MockConfig()
        notifier = Notifier(config)

        assert notifier.config == config

    @patch("asm.core.notifier.requests.post")
    def test_send_slack_summary_success(self, mock_post):
        """Test successful Slack summary notification"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        config = MockConfig(
            slack_enabled=True, slack_webhook="https://hooks.slack.com/test"
        )
        notifier = Notifier(config)

        summary = {
            "subdomains_total": 10,
            "findings_critical": 2,
            "findings_high": 1,
            "findings_total": 5,
            "certs_expiring": 1,
        }

        notifier._send_slack_summary(TEST_DOMAIN, summary)

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://hooks.slack.com/test"
        assert call_args[1]["timeout"] == 10

        # Check payload structure
        payload = call_args[1]["json"]
        assert "attachments" in payload
        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["color"] == "#dc3545"  # Red for critical

    @patch("asm.core.notifier.requests.post")
    def test_send_slack_summary_no_findings(self, mock_post):
        """Test Slack summary with no findings"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        config = MockConfig(
            slack_enabled=True, slack_webhook="https://hooks.slack.com/test"
        )
        notifier = Notifier(config)

        summary = {
            "subdomains_total": 10,
            "findings_critical": 0,
            "findings_high": 0,
            "findings_total": 0,
            "certs_expiring": 0,
        }

        notifier._send_slack_summary(TEST_DOMAIN, summary)

        # Should be green color for no findings
        payload = mock_post.call_args[1]["json"]
        assert payload["attachments"][0]["color"] == "#36a64f"

    @patch("asm.core.notifier.requests.post")
    def test_send_slack_summary_failure(self, mock_post):
        """Test Slack notification failure handling"""
        mock_post.side_effect = Exception("Network error")

        config = MockConfig(
            slack_enabled=True, slack_webhook="https://hooks.slack.com/test"
        )
        notifier = Notifier(config)

        summary = {"subdomains_total": 10, "findings_critical": 0, "findings_high": 0}

        # Should not raise an exception
        notifier._send_slack_summary(TEST_DOMAIN, summary)
        mock_post.assert_called_once()

    @patch("asm.core.notifier.requests.post")
    def test_send_slack_alert(self, mock_post):
        """Test Slack alert notification"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        config = MockConfig(
            slack_enabled=True, slack_webhook="https://hooks.slack.com/test"
        )
        notifier = Notifier(config)

        notifier._send_slack_alert("Test Alert", "Something happened", "critical")

        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["attachments"][0]["color"] == "#dc3545"  # Red for critical

    @patch("asm.core.notifier.smtplib.SMTP")
    def test_send_email_summary(self, mock_smtp):
        """Test email summary notification"""
        mock_server = Mock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        config = MockConfig(
            email_enabled=True,
            email_smtp_host="smtp.example.com",
            email_smtp_port=587,
            email_from="alerts@example.com",
            email_to="security@example.com",
        )
        notifier = Notifier(config)

        summary = {
            "subdomains_total": 10,
            "findings_critical": 2,
            "findings_high": 1,
            "findings_total": 5,
            "certs_expiring": 1,
        }

        notifier._send_email_summary(TEST_DOMAIN, summary)

        mock_smtp.assert_called_once_with("smtp.example.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.send_message.assert_called_once()

    @patch("asm.core.notifier.smtplib.SMTP")
    def test_send_email_alert(self, mock_smtp):
        """Test email alert notification"""
        mock_server = Mock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        config = MockConfig(
            email_enabled=True,
            email_smtp_host="smtp.example.com",
            email_smtp_port=587,
            email_from="alerts@example.com",
            email_to="security@example.com",
        )
        notifier = Notifier(config)

        notifier._send_email_alert("Test Alert", "Something happened", "high")

        mock_server.send_message.assert_called_once()

    def test_send_email_incomplete_config(self):
        """Test email sending with incomplete configuration"""
        config = MockConfig(
            email_enabled=True,
            email_smtp_host="",  # Missing
            email_from="alerts@example.com",
            email_to="security@example.com",
        )
        notifier = Notifier(config)

        # Should not raise an exception
        notifier._send_email("Test", "Body")

    @patch("asm.core.notifier.smtplib.SMTP")
    def test_send_email_failure(self, mock_smtp):
        """Test email sending failure handling"""
        mock_smtp.side_effect = Exception("SMTP error")

        config = MockConfig(
            email_enabled=True,
            email_smtp_host="smtp.example.com",
            email_from="alerts@example.com",
            email_to="security@example.com",
        )
        notifier = Notifier(config)

        # Should not raise an exception
        notifier._send_email("Test", "Body")

    @patch.object(Notifier, "_send_slack_summary")
    @patch.object(Notifier, "_send_email_summary")
    def test_send_summary_slack_enabled(self, mock_email, mock_slack):
        """Test send_summary with Slack enabled"""
        config = MockConfig(
            slack_enabled=True, slack_webhook="https://hooks.slack.com/test"
        )
        notifier = Notifier(config)

        summary = {"subdomains_total": 10}
        notifier.send_summary(TEST_DOMAIN, summary)

        mock_slack.assert_called_once_with(TEST_DOMAIN, summary)
        mock_email.assert_not_called()

    @patch.object(Notifier, "_send_slack_summary")
    @patch.object(Notifier, "_send_email_summary")
    def test_send_summary_email_enabled(self, mock_email, mock_slack):
        """Test send_summary with email enabled"""
        config = MockConfig(
            email_enabled=True,
            email_smtp_host="smtp.example.com",
            email_from="alerts@example.com",
            email_to="security@example.com",
        )
        notifier = Notifier(config)

        summary = {"subdomains_total": 10}
        notifier.send_summary(TEST_DOMAIN, summary)

        mock_email.assert_called_once_with(TEST_DOMAIN, summary)
        mock_slack.assert_not_called()

    @patch.object(Notifier, "_send_slack_alert")
    @patch.object(Notifier, "_send_email_alert")
    def test_send_alert_both_enabled(self, mock_email, mock_slack):
        """Test send_alert with both Slack and email enabled"""
        config = MockConfig(
            slack_enabled=True,
            slack_webhook="https://hooks.slack.com/test",
            email_enabled=True,
            email_smtp_host="smtp.example.com",
            email_from="alerts@example.com",
            email_to="security@example.com",
        )
        notifier = Notifier(config)

        notifier.send_alert("Test Alert", "Something happened", "high")

        mock_slack.assert_called_once_with("Test Alert", "Something happened", "high")
        mock_email.assert_called_once_with("Test Alert", "Something happened", "high")

    @patch.object(Notifier, "_send_slack_alert")
    @patch.object(Notifier, "_send_email_alert")
    def test_send_alert_disabled(self, mock_email, mock_slack):
        """Test send_alert with all notifications disabled"""
        config = MockConfig(slack_enabled=False, email_enabled=False)
        notifier = Notifier(config)

        notifier.send_alert("Test Alert", "Something happened", "high")

        mock_slack.assert_not_called()
        mock_email.assert_not_called()


class TestWebhookNotifier:
    """Test cases for WebhookNotifier class"""

    def test_webhook_notifier_initialization(self):
        """Test webhook notifier initialization"""
        webhook_url = "https://example.com/webhook"
        notifier = WebhookNotifier(webhook_url)

        assert notifier.webhook_url == webhook_url
        assert notifier.headers == {"Content-Type": "application/json"}

    def test_webhook_notifier_custom_headers(self):
        """Test webhook notifier with custom headers"""
        custom_headers = {
            "Authorization": "Bearer token",
            "Content-Type": "application/json",
        }
        notifier = WebhookNotifier("https://example.com/webhook", custom_headers)

        assert notifier.headers == custom_headers

    @patch("asm.core.notifier.requests.post")
    def test_webhook_send_success(self, mock_post):
        """Test successful webhook notification"""
        mock_response = Mock()
        mock_response.ok = True
        mock_post.return_value = mock_response

        notifier = WebhookNotifier("https://example.com/webhook")
        data = {"message": "test", "severity": "high"}

        result = notifier.send(data)

        assert result is True
        mock_post.assert_called_once_with(
            "https://example.com/webhook",
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )

    @patch("asm.core.notifier.requests.post")
    def test_webhook_send_failure(self, mock_post):
        """Test failed webhook notification"""
        mock_response = Mock()
        mock_response.ok = False
        mock_post.return_value = mock_response

        notifier = WebhookNotifier("https://example.com/webhook")
        data = {"message": "test", "severity": "high"}

        result = notifier.send(data)

        assert result is False

    @patch("asm.core.notifier.requests.post")
    def test_webhook_send_exception(self, mock_post):
        """Test webhook notification with network exception"""
        mock_post.side_effect = Exception("Network error")

        notifier = WebhookNotifier("https://example.com/webhook")
        data = {"message": "test", "severity": "high"}

        result = notifier.send(data)

        assert result is False

    def test_edge_case_empty_webhook_url(self):
        """Test webhook notifier with empty URL"""
        notifier = WebhookNotifier("")

        assert notifier.webhook_url == ""
        assert notifier.headers == {"Content-Type": "application/json"}

    def test_edge_case_large_payload(self):
        """Test webhook notifier with large payload"""
        large_data = {"data": "x" * 10000}  # 10KB payload

        with patch("asm.core.notifier.requests.post") as mock_post:
            mock_response = Mock()
            mock_response.ok = True
            mock_post.return_value = mock_response

            notifier = WebhookNotifier("https://example.com/webhook")
            result = notifier.send(large_data)

            assert result is True
            mock_post.assert_called_once()

    def test_edge_case_special_characters_in_data(self):
        """Test webhook notifier with special characters"""
        special_data = {
            "message": "Test with émojis 🚨 and üñîçødé characters",
            "unicode": "测试中文",
        }

        with patch("asm.core.notifier.requests.post") as mock_post:
            mock_response = Mock()
            mock_response.ok = True
            mock_post.return_value = mock_response

            notifier = WebhookNotifier("https://example.com/webhook")
            result = notifier.send(special_data)

            assert result is True
            # Ensure data is properly JSON serialized
            call_args = mock_post.call_args
            assert call_args[1]["json"] == special_data
