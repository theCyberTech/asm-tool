"""
Notification module for ASM Tool - Slack, email, and other alerting
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional
import requests

from .config import Config


class Notifier:
    """
    Handle notifications via various channels

    Supports:
    - Slack webhooks with rich formatting
    - Email notifications via SMTP
    - Automatic summary and alert routing

    Note: Email authentication should be configured in production environments.
    """

    def __init__(self, config: Config):
        """
        Initialize notifier with configuration

        Args:
            config: Configuration object containing notification settings
        """
        self.config = config

    def send_summary(self, domain: str, summary: Dict) -> None:
        """
        Send scan summary via configured channels

        Automatically routes to configured notification channels (Slack, email).
        Formats summary with appropriate severity coloring and structure.

        Args:
            domain: Target domain for the scan
            summary: Dictionary containing scan results and statistics

        Expected summary format:
            {
                'subdomains_total': int,
                'findings_total': int,
                'findings_critical': int,
                'findings_high': int,
                'certs_expiring': int
            }
        """
        if self.config.slack_enabled and self.config.slack_webhook:
            self._send_slack_summary(domain, summary)

        if self.config.email_enabled:
            self._send_email_summary(domain, summary)

    def send_alert(self, title: str, message: str, severity: str = "medium") -> None:
        """
        Send an immediate alert

        Routes alert to configured notification channels with severity-based formatting.

        Args:
            title: Alert title/header text
            message: Detailed alert message
            severity: Alert severity ('critical', 'high', 'medium', 'low', 'info')
        """
        if self.config.slack_enabled and self.config.slack_webhook:
            self._send_slack_alert(title, message, severity)

        if self.config.email_enabled:
            self._send_email_alert(title, message, severity)

    def _send_slack_summary(self, domain: str, summary: Dict) -> None:
        """Send summary to Slack"""
        color = "#36a64f"  # green
        if summary.get("findings_critical", 0) > 0:
            color = "#dc3545"  # red
        elif summary.get("findings_high", 0) > 0:
            color = "#fd7e14"  # orange

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 ASM Scan Complete: {domain}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Subdomains:*\n{summary.get('subdomains_total', 0)}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Findings:*\n"
                        f"{summary.get('findings_total', 0)}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical:*\n{summary.get('findings_critical', 0)}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*High:*\n{summary.get('findings_high', 0)}",
                    },
                ],
            },
        ]

        if summary.get("certs_expiring", 0) > 0:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"⚠️ *{summary['certs_expiring']} "
                            "certificates expiring within 30 days*"
                        ),
                    },
                }
            )

        payload = {"attachments": [{"color": color, "blocks": blocks}]}

        try:
            response = requests.post(
                self.config.slack_webhook, json=payload, timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send Slack notification: {e}")

    def _send_slack_alert(self, title: str, message: str, severity: str) -> None:
        """Send immediate alert to Slack"""
        color_map = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }

        emoji_map = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "📢",
            "low": "ℹ️",
            "info": "📝",
        }

        payload = {
            "attachments": [
                {
                    "color": color_map.get(severity, "#6c757d"),
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji_map.get(severity, '')} {title}",
                            },
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": message},
                        },
                    ],
                }
            ]
        }

        try:
            response = requests.post(
                self.config.slack_webhook, json=payload, timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")

    def _send_email_summary(self, domain: str, summary: Dict) -> None:
        """Send summary via email"""
        subject = f"ASM Scan Summary: {domain}"

        body = f"""
Attack Surface Management - Scan Summary
=========================================

Domain: {domain}

Results:
- Subdomains discovered: {summary.get("subdomains_total", 0)}
- Total findings: {summary.get("findings_total", 0)}
- Critical findings: {summary.get("findings_critical", 0)}
- High findings: {summary.get("findings_high", 0)}
- Certificates expiring (30 days): {summary.get("certs_expiring", 0)}

---
This is an automated message from ASM Tool.
"""

        self._send_email(subject, body)

    def _send_email_alert(self, title: str, message: str, severity: str) -> None:
        """Send alert via email"""
        subject = f"[{severity.upper()}] ASM Alert: {title}"
        self._send_email(subject, message)

    def _send_email(self, subject: str, body: str) -> None:
        """Send an email"""
        if not all(
            [self.config.email_smtp_host, self.config.email_from, self.config.email_to]
        ):
            print("Email not configured properly")
            return

        msg = MIMEMultipart()
        msg["From"] = self.config.email_from
        msg["To"] = self.config.email_to
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(
                self.config.email_smtp_host, self.config.email_smtp_port
            ) as server:
                server.starttls()
                # Note: In production, you'd want to add authentication
                server.send_message(msg)
        except Exception as e:
            print(f"Failed to send email: {e}")


class WebhookNotifier:
    """
    Generic webhook notifier for custom integrations

    Supports sending structured data to any HTTP webhook endpoint.
    Useful for integrating with custom monitoring systems, SIEMs, or alerting platforms.
    """

    def __init__(self, webhook_url: str, headers: Optional[Dict] = None):
        """
        Initialize webhook notifier

        Args:
            webhook_url: Target webhook URL for HTTP POST requests
            headers: Optional custom headers for requests
                (defaults to JSON content-type)
        """
        self.webhook_url = webhook_url
        self.headers = headers or {"Content-Type": "application/json"}

    def send(self, data: Dict) -> bool:
        """
        Send data to webhook

        Args:
            data: Dictionary payload to send as JSON

        Returns:
            bool: True if request succeeded, False on failure
        """
        try:
            response = requests.post(
                self.webhook_url, json=data, headers=self.headers, timeout=10
            )
            return response.ok
        except Exception as e:
            print(f"Webhook failed: {e}")
            return False
