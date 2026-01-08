"""
Database module for ASM Tool - handles all persistence using TinyDB
"""

from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import time
import uuid

from tinydb import TinyDB
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

from ..repositories.domain import DomainRepository
from ..repositories.asset import (
    PortRepository,
    CertificateRepository,
    TechnologyRepository,
    DNSRepository,
)
from ..repositories.finding import FindingRepository, TakeoverRepository
from ..repositories.discovery import URLRepository, APIRepository, EmailRepository
from ..repositories.analytics import AnalyticsRepository


class Database:
    """Handles all data persistence for the ASM tool (Facade for repositories)"""

    # Statistics cache TTL in seconds (default: 30 seconds)
    STATS_CACHE_TTL = 30

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db = TinyDB(db_path, storage=CachingMiddleware(JSONStorage))

        # Initialize Repositories
        self.domain_repo = DomainRepository(self.db)
        self.port_repo = PortRepository(self.db)
        self.cert_repo = CertificateRepository(self.db)
        self.tech_repo = TechnologyRepository(self.db)
        self.dns_repo = DNSRepository(self.db)
        self.finding_repo = FindingRepository(self.db)
        self.takeover_repo = TakeoverRepository(self.db)
        self.url_repo = URLRepository(self.db)
        self.api_repo = APIRepository(self.db)
        self.email_repo = EmailRepository(self.db)
        self.analytics_repo = AnalyticsRepository(self.db)

        # Statistics cache: (timestamp, cached_stats)
        self._stats_cache: Tuple[float, Optional[Dict]] = (0.0, None)

    def close(self):
        """Close the database connection"""
        self.db.close()

    def _now(self) -> str:
        """Return current timestamp as ISO string"""
        return datetime.now(timezone.utc).isoformat()

    # === Properties for Backward Compatibility ===
    # Expose TinyDB tables directly as previous implementation did
    
    @property
    def domains(self): return self.domain_repo.table
    
    @property
    def subdomains(self): return self.domain_repo.subdomains

    @property
    def ports(self): return self.port_repo.table

    @property
    def certificates(self): return self.cert_repo.table

    @property
    def technologies(self): return self.tech_repo.table

    @property
    def dns_records(self): return self.dns_repo.table

    @property
    def findings(self): return self.finding_repo.table

    @property
    def takeovers(self): return self.takeover_repo.table

    @property
    def urls(self): return self.url_repo.table

    @property
    def apis(self): return self.api_repo.table

    @property
    def emails(self): return self.email_repo.table

    @property
    def scan_history(self): return self.analytics_repo.table

    @property
    def scan_snapshots(self): return self.analytics_repo.scan_snapshots

    @property
    def change_events(self): return self.analytics_repo.change_events
    
    @property
    def trend_history(self): return self.analytics_repo.trend_history


    # === Domain Management ===

    def add_domain(self, domain: str) -> bool:
        """Add a root domain to track"""
        return self.domain_repo.add_domain(domain)

    def get_domains(self) -> List[str]:
        """Get all tracked root domains"""
        return self.domain_repo.get_domains()

    # === Subdomain Management ===

    def add_subdomain(self, root_domain: str, subdomain: str) -> bool:
        """Add a discovered subdomain. Returns True if new."""
        return self.domain_repo.add_subdomain(root_domain, subdomain)

    def get_subdomains(self, root_domain: str) -> List[str]:
        """Get all subdomains for a root domain"""
        return self.domain_repo.get_subdomains(root_domain)

    def get_all_subdomains(self) -> List[str]:
        """Get all known subdomains across all domains"""
        return self.domain_repo.get_all_subdomains()

    # === Port Management ===

    def add_port(
        self, host: str, port: int, service: str = "", version: str = ""
    ) -> bool:
        """Add an open port finding. Returns True if new."""
        return self.port_repo.add_port(host, port, service, version)

    def get_port(self, host: str, port: int) -> Optional[Dict]:
        """Get info about a specific port"""
        return self.port_repo.get_port(host, port)

    def get_ports(self, host: str) -> List[Dict]:
        """Get all open ports for a host"""
        return self.port_repo.get_ports(host)

    def get_all_open_ports(self) -> List[Dict]:
        """Get all open ports across all hosts"""
        return self.port_repo.get_all_open_ports()

    # === Certificate Management ===

    def add_certificate(self, host: str, cert_info: Dict) -> bool:
        """Add or update certificate info"""
        return self.cert_repo.add_certificate(host, cert_info)

    def get_certificate(self, host: str) -> Optional[Dict]:
        """Get certificate info for a host"""
        return self.cert_repo.get_certificate(host)

    def get_expiring_certificates(self, days: int = 30) -> List[Dict]:
        """Get certificates expiring within N days"""
        return self.cert_repo.get_expiring_certificates(days)

    # === Technology Fingerprinting ===

    def add_technologies(self, host: str, tech_info: Dict) -> None:
        """Add or update technology fingerprint"""
        self.tech_repo.add_technologies(host, tech_info)

    def get_technologies(self, host: str) -> Optional[Dict]:
        """Get technology info for a host"""
        return self.tech_repo.get_technologies(host)

    # === DNS Records ===

    def save_dns_records(self, domain: str, records: Dict[str, List]) -> None:
        """Save DNS records for a domain"""
        self.dns_repo.save_dns_records(domain, records)

    def check_dns_changes(self, domain: str, new_records: Dict[str, List]) -> Dict:
        """Compare new DNS records with stored ones, return changes"""
        return self.dns_repo.check_dns_changes(domain, new_records)

    # === URL Management ===

    def add_url(self, domain: str, url: str, interesting: bool = False) -> bool:
        """Add a discovered URL. Returns True if new."""
        return self.url_repo.add_url(domain, url, interesting)

    def add_urls_bulk(self, domain: str, url_data: Dict) -> Dict[str, int]:
        """Add multiple URLs from URL enumeration results. Returns counts."""
        return self.url_repo.add_urls_bulk(domain, url_data)

    def get_urls(self, domain: str, interesting_only: bool = False) -> List[str]:
        """Get discovered URLs for a domain"""
        return self.url_repo.get_urls(domain, interesting_only)

    def get_url_summary(self, domain: str) -> Optional[Dict]:
        """Get URL enumeration summary for a domain"""
        return self.url_repo.get_url_summary(domain)

    def get_all_urls(self, interesting_only: bool = False) -> List[Dict]:
        """Get all discovered URLs across all domains"""
        return self.url_repo.get_all_urls(interesting_only)

    # === Subdomain Takeover ===

    def add_takeover(self, takeover: Dict) -> bool:
        """Add a subdomain takeover finding. Returns True if new."""
        return self.takeover_repo.add_takeover(takeover)

    def get_takeovers(self, status: str = None) -> List[Dict]:
        """Get takeover findings, optionally filtered by status"""
        return self.takeover_repo.get_takeovers(status)

    def resolve_takeover(self, subdomain: str) -> None:
        """Mark a takeover as resolved"""
        self.takeover_repo.resolve_takeover(subdomain)

    # === API Discovery ===

    def add_api(self, api: Dict) -> bool:
        """Add a discovered API endpoint. Returns True if new."""
        return self.api_repo.add_api(api)

    def get_apis(self, api_type: str = None) -> List[Dict]:
        """Get discovered APIs, optionally filtered by type"""
        return self.api_repo.get_apis(api_type)

    def get_apis_for_host(self, host: str) -> List[Dict]:
        """Get all APIs for a specific host"""
        return self.api_repo.get_apis_for_host(host)

    # === Email Enumeration ===

    def add_email(self, domain: str, email: str, source: str = "") -> bool:
        """Add a discovered email. Returns True if new."""
        return self.email_repo.add_email(domain, email, source)

    def add_emails_bulk(self, domain: str, email_data: Dict) -> Dict[str, int]:
        """Add multiple emails from enumeration results. Returns counts."""
        return self.email_repo.add_emails_bulk(domain, email_data)

    def get_emails(self, domain: str = None) -> List[Dict]:
        """Get discovered emails, optionally filtered by domain"""
        return self.email_repo.get_emails(domain)

    def get_email_count(self, domain: str = None) -> int:
        """Get count of discovered emails"""
        return self.email_repo.get_email_count(domain)

    # === Vulnerability Findings ===

    def add_finding(self, finding: Dict) -> bool:
        """Add a vulnerability finding"""
        return self.finding_repo.add_finding(finding)

    def get_findings(self, host: str = None, severity: str = None) -> List[Dict]:
        """Get vulnerability findings, optionally filtered"""
        return self.finding_repo.get_findings(host, severity)

    def get_open_findings(self) -> List[Dict]:
        """Get all open (unresolved) findings"""
        return self.finding_repo.get_open_findings()

    # === Statistics and Summaries ===

    def get_statistics(self, use_cache: bool = True) -> Dict:
        """Get overall database statistics.

        Args:
            use_cache: If True, return cached stats if available and fresh.
                       Set to False to force a fresh calculation.

        Returns:
            Dict with counts for domains, subdomains, ports, etc.
        """
        # Check cache validity
        cache_time, cached_stats = self._stats_cache
        if use_cache and cached_stats is not None:
            if time.time() - cache_time < self.STATS_CACHE_TTL:
                return cached_stats

        # Calculate fresh statistics
        stats = {
            "domains": len(self.domains.all()),
            "subdomains": len(self.subdomains.all()),
            "ports": len(self.port_repo.get_all_open_ports()),
            "certificates": len(self.certificates.all()),
            "urls": len(self.urls.all()),
            "interesting_urls": len(self.url_repo.get_all_urls(interesting_only=True)),
            "apis": len(self.apis.all()),
            "emails": len(self.emails.all()),
            "takeovers": len(self.takeover_repo.get_takeovers(status="open")),
            "findings": len(self.finding_repo.get_open_findings()),
            "last_scan": self.analytics_repo.get_last_scan_time(),
        }

        # Update cache
        self._stats_cache = (time.time(), stats)
        return stats

    def invalidate_statistics_cache(self) -> None:
        """Invalidate the statistics cache, forcing fresh calculation on next call."""
        self._stats_cache = (0.0, None)

    def _get_last_scan_time(self) -> str:
        """Get the most recent scan timestamp (internal helper kept if needed, but analytics_repo has it)"""
        return self.analytics_repo.get_last_scan_time()

    def get_domain_summary(self, domain: str) -> Dict:
        """Get summary of all data for a domain"""
        subdomains = self.get_subdomains(domain)
        # We need `Query` for complex filtering in `findings` part
        # "findings": self.findings.search(q.host.test(lambda h: any(s in h for s in subdomains)))
        # We can implement this filter here using the finding repository's table directly, or add a method to repo.
        # Adding method to repo is cleaner, but for now direct access via self.findings (property) works.
        
        from tinydb import Query
        q = Query()
        
        findings = self.findings.search(
            q.host.test(lambda h: any(s in h for s in subdomains))
        )

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
            "findings": findings,
            "takeovers": [
                t for t in self.get_takeovers() 
                if t.get("subdomain") in subdomains or t.get("domain") == domain
            ],
            "urls": self.get_urls(domain),
            "apis": self.api_repo.get_apis_for_host(domain),
            "emails": self.get_emails(domain),
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
        subdomains = self.get_subdomains(domain)
        
        from tinydb import Query
        q = Query()
        
        # Get recent findings
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
        self.analytics_repo.record_scan(domain, scan_type)

    def save_snapshot(self, domain: str, scan_type: str = "full") -> str:
        """Save a complete snapshot of domain state for trend analysis."""

        subdomains = self.get_subdomains(domain)

        # Batch query for ports - O(1) instead of O(n) per subdomain
        all_ports = self.port_repo.get_ports_for_hosts(subdomains)

        findings = self.get_findings()
        # Use set for O(1) lookups instead of O(n) per finding
        subdomains_set = set(subdomains)
        findings_for_domain = [
            f for f in findings if any(sub in f["host"] for sub in subdomains_set)
        ]

        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for f in findings_for_domain:
            sev = f.get("severity", "low").lower()
            if sev in vuln_counts:
                vuln_counts[sev] += 1
            vuln_counts["total"] += 1

        risk_score = (
            vuln_counts["critical"] * 10
            + vuln_counts["high"] * 5
            + vuln_counts["medium"] * 2
            + vuln_counts["low"] * 1
        )

        # Batch query for certificates - O(1) instead of O(n) per subdomain
        certs_map = self.cert_repo.get_certificates_for_hosts(subdomains)
        certs_for_domain = [
            {"host": sub, "fingerprint": cert.get("fingerprint", "")}
            for sub, cert in certs_map.items()
        ]

        snapshot = {
            "snapshot_id": str(uuid.uuid4()),
            "domain": domain,
            "timestamp": self._now(),
            "scan_type": scan_type,
            "subdomain_count": len(subdomains),
            "subdomains": subdomains,
            "port_count": len(all_ports),
            "ports": [f"{p['host']}:{p['port']}" for p in all_ports],
            "certificate_count": len(certs_for_domain),
            "certificates": certs_for_domain,
            "vulnerabilities": vuln_counts,
            "risk_score": risk_score,
        }

        return self.analytics_repo.add_snapshot(snapshot)

    def get_snapshot(self, snapshot_id: str) -> Optional[Dict]:
        """Get a specific snapshot by ID"""
        return self.analytics_repo.get_snapshot(snapshot_id)

    def get_latest_snapshot(self, domain: str) -> Optional[Dict]:
        """Get the most recent snapshot for a domain"""
        return self.analytics_repo.get_latest_snapshot(domain)

    def get_snapshots_in_range(self, domain: str, days: int = 30) -> List[Dict]:
        """Get all snapshots for a domain within N days"""
        return self.analytics_repo.get_snapshots_in_range(domain, days)

    def save_change_event(self, event: Dict) -> str:
        """Save a change event for tracking."""
        return self.analytics_repo.save_change_event(event)

    def get_change_events(
        self, domain: str, days: int = 30, change_type: str = None
    ) -> List[Dict]:
        """Get change events for a domain within N days."""
        return self.analytics_repo.get_change_events(domain, days, change_type)

    def calculate_risk_delta(self, domain: str, days: int = 30) -> Dict:
        """Calculate risk score changes over time period."""
        return self.analytics_repo.calculate_risk_delta(domain, days)

    def get_trend_summary(self, domain: str, days: int = 30) -> Dict:
        """Get detailed trend summary."""
        return self.analytics_repo.get_trend_summary(domain, days)
