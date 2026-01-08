"""
Report generation for ASM Tool
"""

from typing import Dict
from datetime import datetime, timezone
from jinja2 import Template
import json


class Reporter:
    """
    Generate reports in various formats

    Supports:
    - ASCII tables with Rich formatting for terminal output
    - JSON for programmatic consumption
    - Markdown for documentation and git integration
    - HTML for sharing and presentation

    Uses Jinja2 templates for consistent formatting across formats.
    """

    def __init__(self, db):
        """
        Initialize reporter with database instance

        Args:
            db: Database instance for accessing scan data
        """
        self.db = db

    def generate(self, data: Dict, format: str = "table") -> str:
        """
        Generate report in specified format

        Args:
            data: Dictionary containing scan results and statistics
            format: Output format ('table', 'json', 'markdown', 'html')

        Returns:
            str: Formatted report content

        Expected data structure:
            {
                'statistics': {...},
                'domains': [
                    {
                        'domain': str,
                        'subdomains': List[str],
                        'subdomain_count': int,
                        'findings': List[Dict],
                        'certificates': List[Dict],
                        ...
                    }
                ]
            }
        """
        if format == "json":
            return self._generate_json(data)
        elif format == "markdown":
            return self._generate_markdown(data)
        elif format == "html":
            return self._generate_html(data)
        else:
            return self._generate_table(data)

    def _generate_json(self, data: Dict) -> str:
        """Generate JSON report"""
        return json.dumps(data, indent=2, default=str)

    def _generate_table(self, data: Dict) -> str:
        """Generate ASCII table report"""
        from rich.console import Console
        from rich.table import Table
        from io import StringIO

        output = StringIO()
        console = Console(file=output, force_terminal=True)

        stats = data.get("statistics", {})

        # Summary table
        summary = Table(title="Attack Surface Summary")
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="green")

        summary.add_row("Domains Tracked", str(stats.get("domains", 0)))
        summary.add_row("Subdomains Discovered", str(stats.get("subdomains", 0)))
        summary.add_row("Open Ports", str(stats.get("ports", 0)))
        summary.add_row("Active Certificates", str(stats.get("certificates", 0)))
        summary.add_row("Open Findings", str(stats.get("findings", 0)))

        console.print(summary)
        console.print()

        # Findings by severity if present
        for domain_data in data.get("domains", [data]):
            if "findings" in domain_data and domain_data["findings"]:
                findings_table = Table(
                    title=f"Findings for {domain_data.get('domain', 'Unknown')}"
                )
                findings_table.add_column("Severity", style="red")
                findings_table.add_column("Name")
                findings_table.add_column("Host")
                findings_table.add_column("Template")

                for finding in sorted(
                    domain_data["findings"],
                    key=lambda x: ["critical", "high", "medium", "low", "info"].index(
                        x.get("severity", "info")
                    ),
                ):
                    sev = finding.get("severity", "unknown").upper()
                    findings_table.add_row(
                        sev,
                        finding.get("name", "")[:40],
                        finding.get("host", ""),
                        finding.get("template_id", ""),
                    )

                console.print(findings_table)

            if "takeovers" in domain_data and domain_data["takeovers"]:
                to_table = Table(title=f"Subdomain Takeovers for {domain_data.get('domain', 'Unknown')}", style="red")
                to_table.add_column("Subdomain", style="bold red")
                to_table.add_column("Service")
                to_table.add_column("Status")
                for t in domain_data["takeovers"]:
                    to_table.add_row(t.get("subdomain"), t.get("service"), t.get("status"))
                console.print(to_table)

            if "certificates" in domain_data and domain_data["certificates"]:
                cert_table = Table(title=f"Certificates for {domain_data.get('domain', 'Unknown')}")
                cert_table.add_column("Host")
                cert_table.add_column("Issuer")
                cert_table.add_column("Expires", style="cyan")
                for c in domain_data["certificates"]:
                    cert_table.add_row(c.get("host"), c.get("issuer"), str(c.get("days_until_expiry")) + " days")
                console.print(cert_table)

            if "technologies" in domain_data and domain_data["technologies"]:
                tech_table = Table(title=f"Technologies for {domain_data.get('domain', 'Unknown')}")
                tech_table.add_column("Host")
                tech_table.add_column("Technologies", style="magenta")
                for t in domain_data["technologies"]:
                    tech_table.add_row(t.get("host"), ", ".join(t.get("technologies", [])))
                console.print(tech_table)

            if "apis" in domain_data and domain_data["apis"]:
                api_table = Table(title=f"APIs for {domain_data.get('domain', 'Unknown')}")
                api_table.add_column("URL")
                api_table.add_column("Type", style="blue")
                for a in domain_data["apis"]:
                    api_table.add_row(a.get("url"), a.get("type"))
                console.print(api_table)

            if "emails" in domain_data and domain_data["emails"]:
                email_table = Table(title=f"Emails for {domain_data.get('domain', 'Unknown')}")
                email_table.add_column("Email", style="green")
                email_table.add_column("Source")
                for e in domain_data["emails"]:
                    email_table.add_row(e.get("email"), e.get("source"))
                console.print(email_table)

        return output.getvalue()

    def _generate_markdown(self, data: Dict) -> str:
        """Generate Markdown report"""
        template = Template("""# Attack Surface Management Report

**Generated:** {{ timestamp }}

## Summary

| Metric | Value |
|--------|-------|
| Domains Tracked | {{ stats.domains }} |
| Subdomains Discovered | {{ stats.subdomains }} |
| Open Ports | {{ stats.ports }} |
| Active Certificates | {{ stats.certificates }} |
| Open Findings | {{ stats.findings }} |

{% for domain_data in domains %}
## Domain: {{ domain_data.domain }}

### Subdomains ({{ domain_data.subdomain_count }})

{% for sub in domain_data.subdomains[:20] %}
- {{ sub }}
{% endfor %}
{% if domain_data.subdomain_count > 20 %}
- ... and {{ domain_data.subdomain_count - 20 }} more
{% endif %}

{% if domain_data.technologies %}
### Technologies

| Host | Technologies |
|------|--------------|
{% for tech in domain_data.technologies %}
| {{ tech.host }} | {{ tech.technologies | join(', ') }} |
{% endfor %}
{% endif %}

{% if domain_data.takeovers %}
### Subdomain Takeovers

> [!CAUTION]
> Potential Subdomain Takeovers Detected!

| Subdomain | Service | Status |
|-----------|---------|--------|
{% for takeover in domain_data.takeovers %}
| {{ takeover.subdomain }} | {{ takeover.service }} | {{ takeover.status }} |
{% endfor %}
{% endif %}

{% if domain_data.findings %}
### Findings

| Severity | Name | Host |
|----------|------|------|
{% for finding in domain_data.findings %}
| {{ finding.severity | upper }} | {{ finding.name }} | {{ finding.host }} |
{% endfor %}
{% endif %}

{% if domain_data.certificates %}
### Certificates

| Host | Issuer | Expires | Days Left |
|------|--------|---------|-----------|
{% for cert in domain_data.certificates %}
| {{ cert.host }} | {{ cert.issuer }} | {{ cert.not_after }} | \
{{ cert.days_until_expiry }} |
{% endfor %}
{% endif %}

{% if domain_data.apis %}
### APIs

| URL | Type | Endpoints |
|-----|------|-----------|
{% for api in domain_data.apis %}
| {{ api.url }} | {{ api.type }} | {{ api.endpoints_count }} |
{% endfor %}
{% endif %}

{% if domain_data.emails %}
### Emails

| Email | Source |
|-------|--------|
{% for email in domain_data.emails %}
| {{ email.email }} | {{ email.source }} |
{% endfor %}
{% endif %}

{% if domain_data.urls %}
### Discovered URLs

**Total:** {{ domain_data.urls | length }}

{% if domain_data.urls | length > 0 %}
<details>
<summary>View URLs</summary>

{% for url in domain_data.urls[:50] %}
- {{ url }}
{% endfor %}
{% if domain_data.urls | length > 50 %}
... and {{ domain_data.urls | length - 50 }} more
{% endif %}
</details>
{% endif %}
{% endif %}

{% endfor %}
""")

        return template.render(
            timestamp=datetime.now(timezone.utc).isoformat(),
            stats=data.get(
                "statistics",
                {
                    "domains": 0,
                    "subdomains": 0,
                    "ports": 0,
                    "certificates": 0,
                    "findings": 0,
                },
            ),
            domains=data.get("domains", [data]),
        )

    def _generate_html(self, data: Dict) -> str:
        """Generate HTML report"""
        template = Template("""<!DOCTYPE html>
<html>
<head>
    <title>Attack Surface Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
               Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white;
                     padding: 30px; border-radius: 8px;
                     box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .stat-card { display: inline-block; padding: 20px; margin: 10px;
                     background: #f8f9fa; border-radius: 8px; min-width: 150px;
                     text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #007bff; }
        .stat-label { color: #666; }
        .timestamp { color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Attack Surface Management Report</h1>
        <p class="timestamp">Generated: {{ timestamp }}</p>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{ stats.domains }}</div>
                <div class="stat-label">Domains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.subdomains }}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.ports }}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.findings }}</div>
                <div class="stat-label">Findings</div>
            </div>
        </div>

        {% for domain_data in domains %}
        <h2>{{ domain_data.domain }}</h2>

        <h3>Subdomains ({{ domain_data.subdomain_count }})</h3>
        <table>
            <tr><th>Subdomain</th></tr>
            {% for sub in domain_data.subdomains[:30] %}
            <tr><td>{{ sub }}</td></tr>
            {% endfor %}
        </table>

        {% if domain_data.technologies %}
        <h3>Technologies</h3>
        <table>
            <tr><th>Host</th><th>Stack</th></tr>
            {% for tech in domain_data.technologies %}
            <tr>
                <td>{{ tech.host }}</td>
                <td>{{ tech.technologies | join(', ') }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if domain_data.takeovers %}
        <h3 style="color: #dc3545;">⚠ Subdomain Takeovers</h3>
        <div style="background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
            <strong>Warning:</strong> Potential takeover vulnerabilities detected!
        </div>
        <table>
            <tr><th>Subdomain</th><th>Service</th><th>Evidence</th></tr>
            {% for t in domain_data.takeovers %}
            <tr>
                <td class="severity-critical">{{ t.subdomain }}</td>
                <td>{{ t.service }}</td>
                <td>{{ t.evidence }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if domain_data.findings %}
        <h3>Vulnerability Findings</h3>
        <table>
            <tr><th>Severity</th><th>Name</th><th>Host</th><th>Template</th></tr>
            {% for finding in domain_data.findings %}
            <tr>
                <td class="severity-{{ finding.severity }}">
                    {{ finding.severity | upper }}
                </td>
                <td>{{ finding.name | e }}</td>
                <td>{{ finding.host }}</td>
                <td>{{ finding.template_id }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if domain_data.certificates %}
        <h3>Certificates</h3>
        <table>
            <tr><th>Host</th><th>Issuer</th><th>Expires</th><th>Days Left</th></tr>
            {% for cert in domain_data.certificates %}
            <tr>
                <td>{{ cert.host }}</td>
                <td>{{ cert.issuer }}</td>
                <td>{{ cert.not_after }}</td>
                <td>
                    {% if cert.days_until_expiry < 0 %}
                    <span style="color: red; font-weight: bold">{{ cert.days_until_expiry }} (Expired)</span>
                    {% elif cert.days_until_expiry < 30 %}
                    <span style="color: orange; font-weight: bold">{{ cert.days_until_expiry }}</span>
                    {% else %}
                    <span style="color: green">{{ cert.days_until_expiry }}</span>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if domain_data.apis %}
        <h3>API Endpoints</h3>
        <table>
            <tr><th>URL</th><th>Type</th><th>Endpoints Discovered</th></tr>
            {% for api in domain_data.apis %}
            <tr>
                <td><a href="{{ api.url }}">{{ api.url }}</a></td>
                <td>{{ api.type }}</td>
                <td>{{ api.endpoints_count }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if domain_data.emails %}
        <h3>Emails</h3>
        <ul>
            {% for email in domain_data.emails %}
            <li><a href="mailto:{{ email.email }}">{{ email.email }}</a> <span style="color: #777; font-size: 0.9em">({{ email.source }})</span></li>
            {% endfor %}
        </ul>
        {% endif %}

        {% if domain_data.urls %}
        <h3>Discovered URLs (Top 50)</h3>
        <div style="max-height: 300px; overflow-y: auto; background: #f8f9fa; padding: 10px; border: 1px solid #ddd;">
            <ul style="list-style-type: none; padding-left: 0;">
                {% for url in domain_data.urls[:50] %}
                <li><a href="{{ url }}" target="_blank" style="text-decoration: none; color: #007bff;">{{ url }}</a></li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        {% endfor %}
    </div>
</body>
</html>""")

        return template.render(
            timestamp=datetime.now(timezone.utc).isoformat(),
            stats=data.get(
                "statistics",
                {
                    "domains": 0,
                    "subdomains": 0,
                    "ports": 0,
                    "certificates": 0,
                    "findings": 0,
                },
            ),
            domains=data.get("domains", [data]),
        )
