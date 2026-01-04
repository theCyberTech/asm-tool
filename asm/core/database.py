"""
Database module for ASM Tool - handles all persistence using TinyDB
"""

from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import re
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
import json


class Database:
    """Handles all data persistence for the ASM tool"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db = TinyDB(db_path, storage=CachingMiddleware(JSONStorage))

        # Initialize tables
        self.subdomains = self.db.table("subdomains")
        self.ports = self.db.table("ports")
        self.certificates = self.db.table("certificates")
        self.technologies = self.db.table("technologies")
        self.dns_records = self.db.table("dns_records")
        self.findings = self.db.table("findings")
        self.scan_history = self.db.table("scan_history")
        self.domains = self.db.table("domains")
        self.urls = self.db.table("urls")
        self.takeovers = self.db.table("takeovers")
        self.apis = self.db.table("apis")
        self.emails = self.db.table("emails")

    def _now(self) -> str:
        """Return current timestamp as ISO string"""
        return datetime.now(timezone.utc).isoformat()

    # === Domain Management ===

    def add_domain(self, domain: str) -> bool:
        """Add a root domain to track"""
        q = Query()
        if not self.domains.search(q.domain == domain):
            self.domains.insert(
                {"domain": domain, "added_at": self._now(), "last_scanned": None}
            )
            return True
        return False

    def get_domains(self) -> List[str]:
        """Get all tracked root domains"""
        return [d["domain"] for d in self.domains.all()]

    # === Subdomain Management ===

    def add_subdomain(self, root_domain: str, subdomain: str) -> bool:
        """Add a discovered subdomain. Returns True if new."""
        q = Query()
        existing = self.subdomains.search(
            (q.root_domain == root_domain) & (q.subdomain == subdomain)
        )

        if not existing:
            self.subdomains.insert(
                {
                    "root_domain": root_domain,
                    "subdomain": subdomain,
                    "discovered_at": self._now(),
                    "last_seen": self._now(),
                    "active": True,
                }
            )
            self.add_domain(root_domain)
            return True
        else:
            # Update last_seen
            self.subdomains.update(
                {"last_seen": self._now()},
                (q.root_domain == root_domain) & (q.subdomain == subdomain),
            )
            return False

    def get_subdomains(self, root_domain: str) -> List[str]:
        """Get all subdomains for a root domain"""
        q = Query()
        results = self.subdomains.search(q.root_domain == root_domain)
        return [r["subdomain"] for r in results]

    def get_all_subdomains(self) -> List[str]:
        """Get all known subdomains across all domains"""
        return [r["subdomain"] for r in self.subdomains.all()]

    # === Port Management ===

    def add_port(
        self, host: str, port: int, service: str = "", version: str = ""
    ) -> bool:
        """Add an open port finding. Returns True if new."""
        q = Query()
        existing = self.ports.search((q.host == host) & (q.port == port))

        now = self._now()

        if not existing:
            self.ports.insert(
                {
                    "host": host,
                    "port": port,
                    "service": service,
                    "version": version,
                    "discovered_at": now,
                    "last_seen": now,
                    "state": "open",
                }
            )
            return True
        else:
            # Update last_seen and potentially service info
            self.ports.update(
                {
                    "last_seen": now,
                    "service": service or existing[0].get("service", ""),
                    "version": version or existing[0].get("version", ""),
                    "state": "open",
                },
                (q.host == host) & (q.port == port),
            )
            return False

    def get_port(self, host: str, port: int) -> Optional[Dict]:
        """Get info about a specific port"""
        q = Query()
        results = self.ports.search((q.host == host) & (q.port == port))
        return results[0] if results else None

    def get_ports(self, host: str) -> List[Dict]:
        """Get all open ports for a host"""
        q = Query()
        return self.ports.search(q.host == host)

    def get_all_open_ports(self) -> List[Dict]:
        """Get all open ports across all hosts"""
        q = Query()
        return self.ports.search(q.state == "open")

    # === Certificate Management ===

    def add_certificate(self, host: str, cert_info: Dict) -> bool:
        """Add or update certificate info"""
        q = Query()
        existing = self.certificates.search(q.host == host)

        record = {
            "host": host,
            "issuer": cert_info.get("issuer", ""),
            "subject": cert_info.get("subject", ""),
            "not_before": cert_info.get("not_before", ""),
            "not_after": cert_info.get("not_after", ""),
            "days_until_expiry": cert_info.get("days_until_expiry", 0),
            "serial_number": cert_info.get("serial_number", ""),
            "fingerprint": cert_info.get("fingerprint", ""),
            "san": cert_info.get("san", []),
            "checked_at": self._now(),
        }

        if not existing:
            self.certificates.insert(record)
            return True
        else:
            # Check if cert changed (different fingerprint)
            changed = existing[0].get("fingerprint") != cert_info.get("fingerprint")
            self.certificates.update(record, q.host == host)
            return changed

    def get_certificate(self, host: str) -> Optional[Dict]:
        """Get certificate info for a host"""
        q = Query()
        results = self.certificates.search(q.host == host)
        return results[0] if results else None

    def get_expiring_certificates(self, days: int = 30) -> List[Dict]:
        """Get certificates expiring within N days"""
        q = Query()
        return self.certificates.search(
            (q.days_until_expiry <= days) & (q.days_until_expiry >= 0)
        )

    # === Technology Fingerprinting ===

    def add_technologies(self, host: str, tech_info: Dict) -> None:
        """Add or update technology fingerprint"""
        q = Query()

        record = {
            "host": host,
            "status_code": tech_info.get("status_code"),
            "title": tech_info.get("title", ""),
            "technologies": tech_info.get("technologies", []),
            "server": tech_info.get("server", ""),
            "headers": tech_info.get("headers", {}),
            "content_length": tech_info.get("content_length", 0),
            "redirect_url": tech_info.get("redirect_url", ""),
            "checked_at": self._now(),
        }

        existing = self.technologies.search(q.host == host)
        if existing:
            self.technologies.update(record, q.host == host)
        else:
            self.technologies.insert(record)

    def get_technologies(self, host: str) -> Optional[Dict]:
        """Get technology info for a host"""
        q = Query()
        results = self.technologies.search(q.host == host)
        return results[0] if results else None

    # === DNS Records ===

    def save_dns_records(self, domain: str, records: Dict[str, List]) -> None:
        """Save DNS records for a domain"""
        q = Query()

        record = {"domain": domain, "records": records, "checked_at": self._now()}

        existing = self.dns_records.search(q.domain == domain)
        if existing:
            self.dns_records.update(record, q.domain == domain)
        else:
            self.dns_records.insert(record)

    def check_dns_changes(self, domain: str, new_records: Dict[str, List]) -> Dict:
        """Compare new DNS records with stored ones, return changes"""
        q = Query()
        existing = self.dns_records.search(q.domain == domain)

        if not existing:
            return {"new": new_records, "removed": {}}

        old_records = existing[0].get("records", {})

        changes = {"new": {}, "removed": {}}

        # Find new records
        for rtype, values in new_records.items():
            old_values = set(str(v) for v in old_records.get(rtype, []))
            new_values = set(str(v) for v in values)

            added = new_values - old_values
            if added:
                changes["new"][rtype] = list(added)

        # Find removed records
        for rtype, values in old_records.items():
            old_values = set(str(v) for v in values)
            new_values = set(str(v) for v in new_records.get(rtype, []))

            removed = old_values - new_values
            if removed:
                changes["removed"][rtype] = list(removed)

        return changes

    # === URL Management ===

    def add_url(self, domain: str, url: str, interesting: bool = False) -> bool:
        """Add a discovered URL. Returns True if new."""
        q = Query()
        existing = self.urls.search((q.domain == domain) & (q.url == url))

        if not existing:
            self.urls.insert(
                {
                    "domain": domain,
                    "url": url,
                    "interesting": interesting,
                    "discovered_at": self._now(),
                    "last_seen": self._now(),
                }
            )
            return True
        else:
            # Update last_seen
            self.urls.update(
                {"last_seen": self._now()}, (q.domain == domain) & (q.url == url)
            )
            return False

    def add_urls_bulk(self, domain: str, url_data: Dict) -> Dict[str, int]:
        """Add multiple URLs from URL enumeration results. Returns counts."""
        counts = {"new": 0, "existing": 0, "interesting_new": 0}

        # Add all URLs
        for url in url_data.get("urls", []):
            is_interesting = url in url_data.get("interesting", [])
            if self.add_url(domain, url, interesting=is_interesting):
                counts["new"] += 1
                if is_interesting:
                    counts["interesting_new"] += 1
            else:
                counts["existing"] += 1

        # Store summary data
        self._save_url_summary(domain, url_data)

        return counts

    def _save_url_summary(self, domain: str, url_data: Dict) -> None:
        """Save URL enumeration summary for a domain"""
        q = Query()

        summary = {
            "domain": domain,
            "total_urls": url_data.get("total", 0),
            "interesting_count": len(url_data.get("interesting", [])),
            "unique_paths_count": len(url_data.get("unique_paths", [])),
            "endpoints_count": len(url_data.get("endpoints", [])),
            "parameters": list(url_data.get("parameters", {}).keys()),
            "extensions": {
                k: len(v) for k, v in url_data.get("by_extension", {}).items()
            },
            "checked_at": self._now(),
        }

        # Use upsert pattern
        existing = self.db.table("url_summaries").search(q.domain == domain)
        if existing:
            self.db.table("url_summaries").update(summary, q.domain == domain)
        else:
            self.db.table("url_summaries").insert(summary)

    def get_urls(self, domain: str, interesting_only: bool = False) -> List[str]:
        """Get discovered URLs for a domain"""
        q = Query()
        if interesting_only:
            results = self.urls.search((q.domain == domain) & (q.interesting == True))
        else:
            results = self.urls.search(q.domain == domain)
        return [r["url"] for r in results]

    def get_url_summary(self, domain: str) -> Optional[Dict]:
        """Get URL enumeration summary for a domain"""
        q = Query()
        results = self.db.table("url_summaries").search(q.domain == domain)
        return results[0] if results else None

    def get_all_urls(self, interesting_only: bool = False) -> List[Dict]:
        """Get all discovered URLs across all domains"""
        if interesting_only:
            q = Query()
            return self.urls.search(q.interesting == True)
        return self.urls.all()

    # === Subdomain Takeover ===

    def add_takeover(self, takeover: Dict) -> bool:
        """Add a subdomain takeover finding. Returns True if new."""
        q = Query()
        subdomain = takeover["subdomain"]

        existing = self.takeovers.search(q.subdomain == subdomain)

        record = {
            "subdomain": subdomain,
            "cname": takeover.get("cname", ""),
            "service": takeover.get("service", ""),
            "type": takeover.get("type", ""),
            "confidence": takeover.get("confidence", "MEDIUM"),
            "evidence": takeover.get("evidence", ""),
            "documentation": takeover.get("documentation", ""),
            "discovered_at": self._now(),
            "status": "open",
        }

        if not existing:
            self.takeovers.insert(record)
            return True
        else:
            # Update if already exists
            self.takeovers.update(
                {"last_seen": self._now(), "status": "open"}, q.subdomain == subdomain
            )
            return False

    def get_takeovers(self, status: str = None) -> List[Dict]:
        """Get takeover findings, optionally filtered by status"""
        if status:
            q = Query()
            return self.takeovers.search(q.status == status)
        return self.takeovers.all()

    def resolve_takeover(self, subdomain: str) -> None:
        """Mark a takeover as resolved"""
        q = Query()
        self.takeovers.update(
            {"status": "resolved", "resolved_at": self._now()}, q.subdomain == subdomain
        )

    # === API Discovery ===

    def add_api(self, api: Dict) -> bool:
        """Add a discovered API endpoint. Returns True if new."""
        q = Query()
        url = api["url"]

        existing = self.apis.search(q.url == url)

        record = {
            "url": url,
            "type": api.get(
                "type", ""
            ),  # swagger, openapi, graphql, documentation, api_endpoint
            "host": urlparse(url).netloc,
            "version": api.get("version", ""),
            "title": api.get("title", ""),
            "endpoints_count": api.get("endpoints_count", 0),
            "endpoints": api.get("endpoints", []),
            "introspection_enabled": api.get("introspection_enabled", False),
            "types_count": api.get("types_count", 0),
            "queries": api.get("queries", []),
            "mutations": api.get("mutations", []),
            "discovered_at": self._now(),
        }

        if not existing:
            self.apis.insert(record)
            return True
        else:
            self.apis.update(record, q.url == url)
            return False

    def get_apis(self, api_type: str = None) -> List[Dict]:
        """Get discovered APIs, optionally filtered by type"""
        if api_type:
            q = Query()
            return self.apis.search(q.type == api_type)
        return self.apis.all()

    def get_apis_for_host(self, host: str) -> List[Dict]:
        """Get all APIs for a specific host"""
        q = Query()
        return self.apis.search(q.host.matches(f".*{re.escape(host)}.*"))

    # === Email Enumeration ===

    def add_email(self, domain: str, email: str, source: str = "") -> bool:
        """Add a discovered email. Returns True if new."""
        q = Query()
        existing = self.emails.search(q.email == email.lower())

        if not existing:
            self.emails.insert(
                {
                    "domain": domain,
                    "email": email.lower(),
                    "source": source,
                    "discovered_at": self._now(),
                }
            )
            return True
        return False

    def add_emails_bulk(self, domain: str, email_data: Dict) -> Dict[str, int]:
        """Add multiple emails from enumeration results. Returns counts."""
        counts = {"new": 0, "existing": 0}

        for source, emails in email_data.get("by_source", {}).items():
            for email in emails:
                if self.add_email(domain, email, source):
                    counts["new"] += 1
                else:
                    counts["existing"] += 1

        return counts

    def get_emails(self, domain: str = None) -> List[Dict]:
        """Get discovered emails, optionally filtered by domain"""
        if domain:
            q = Query()
            return self.emails.search(q.domain == domain)
        return self.emails.all()

    def get_email_count(self, domain: str = None) -> int:
        """Get count of discovered emails"""
        return len(self.get_emails(domain))

    # === Vulnerability Findings ===

    def add_finding(self, finding: Dict) -> bool:
        """Add a vulnerability finding"""
        q = Query()

        # Create a unique key for the finding
        finding_key = f"{finding['host']}:{finding['template_id']}:{finding.get('matched_at', '')}"

        existing = self.findings.search(q.finding_key == finding_key)

        record = {
            "finding_key": finding_key,
            "host": finding["host"],
            "template_id": finding["template_id"],
            "name": finding["name"],
            "severity": finding["severity"],
            "matched_at": finding.get("matched_at", ""),
            "extracted_results": finding.get("extracted_results", []),
            "description": finding.get("description", ""),
            "reference": finding.get("reference", []),
            "discovered_at": self._now(),
            "status": "open",
        }

        if not existing:
            self.findings.insert(record)
            return True
        else:
            # Update last seen
            self.findings.update(
                {"last_seen": self._now()}, q.finding_key == finding_key
            )
            return False

    def get_findings(self, host: str = None, severity: str = None) -> List[Dict]:
        """Get vulnerability findings, optionally filtered"""
        q = Query()

        if host and severity:
            return self.findings.search((q.host == host) & (q.severity == severity))
        elif host:
            return self.findings.search(q.host == host)
        elif severity:
            return self.findings.search(q.severity == severity)
        else:
            return self.findings.all()

    def get_open_findings(self) -> List[Dict]:
        """Get all open (unresolved) findings"""
        q = Query()
        return self.findings.search(q.status == "open")

    # === Statistics and Summaries ===

    def get_statistics(self) -> Dict:
        """Get overall database statistics"""
        return {
            "domains": len(self.domains.all()),
            "subdomains": len(self.subdomains.all()),
            "ports": len(self.ports.search(Query().state == "open")),
            "certificates": len(self.certificates.all()),
            "urls": len(self.urls.all()),
            "interesting_urls": len(self.urls.search(Query().interesting == True)),
            "apis": len(self.apis.all()),
            "emails": len(self.emails.all()),
            "takeovers": len(self.takeovers.search(Query().status == "open")),
            "findings": len(self.findings.search(Query().status == "open")),
            "last_scan": self._get_last_scan_time(),
        }

    def _get_last_scan_time(self) -> str:
        """Get the most recent scan timestamp"""
        history = self.scan_history.all()
        if history:
            return max(h["timestamp"] for h in history)
        return "Never"

    def get_domain_summary(self, domain: str) -> Dict:
        """Get summary of all data for a domain"""
        q = Query()

        subdomains = self.get_subdomains(domain)

        return {
            "domain": domain,
            "subdomain_count": len(subdomains),
            "subdomains": subdomains,
            "ports": [self.get_ports(s) for s in subdomains],
            "certificates": [
                self.get_certificate(s) for s in subdomains if self.get_certificate(s)
            ],
            "technologies": [
                self.get_technologies(s) for s in subdomains if self.get_technologies(s)
            ],
            "findings": self.findings.search(
                q.host.test(lambda h: any(s in h for s in subdomains))
            ),
        }

    def get_full_summary(self) -> Dict:
        """Get summary of all tracked domains"""
        domains = self.get_domains()
        return {
            "domains": [self.get_domain_summary(d) for d in domains],
            "statistics": self.get_statistics(),
        }

    def get_scan_summary(self, domain: str) -> Dict:
        """Get a summary suitable for notifications"""
        q = Query()
        subdomains = self.get_subdomains(domain)

        # Get recent findings (last 24 hours would need timestamp comparison)
        findings = self.findings.search(
            q.host.test(lambda h: any(s in h for s in subdomains))
        )

        critical = len([f for f in findings if f["severity"] == "critical"])
        high = len([f for f in findings if f["severity"] == "high"])

        expiring = self.get_expiring_certificates(30)

        return {
            "domain": domain,
            "subdomains_total": len(subdomains),
            "findings_critical": critical,
            "findings_high": high,
            "findings_total": len(findings),
            "certs_expiring": len(expiring),
        }

    def record_scan(self, domain: str, scan_type: str) -> None:
        """Record that a scan was performed"""
        self.scan_history.insert(
            {"domain": domain, "scan_type": scan_type, "timestamp": self._now()}
        )

    def close(self):
        """Close the database connection"""
        self.db.close()
