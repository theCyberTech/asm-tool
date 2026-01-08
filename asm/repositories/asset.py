from typing import List, Dict, Optional
from tinydb import Query
from .base import BaseRepository

class PortRepository(BaseRepository):
    """Repository for port scan results"""

    def __init__(self, db):
        super().__init__(db, "ports")

    def add_port(
        self, host: str, port: int, service: str = "", version: str = ""
    ) -> bool:
        """Add an open port finding. Returns True if new."""
        q = self.query
        existing = self.table.search((q.host == host) & (q.port == port))

        now = self._now()

        if not existing:
            self.table.insert(
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
            self.table.update(
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
        q = self.query
        results = self.table.search((q.host == host) & (q.port == port))
        return results[0] if results else None

    def get_ports(self, host: str) -> List[Dict]:
        """Get all open ports for a host"""
        q = self.query
        return self.table.search(q.host == host)

    def get_all_open_ports(self) -> List[Dict]:
        """Get all open ports across all hosts"""
        q = self.query
        return self.table.search(q.state == "open")

    def get_ports_for_hosts(self, hosts: List[str]) -> List[Dict]:
        """Get all ports for multiple hosts in a single query.

        5-10x faster than calling get_ports() per host.
        """
        if not hosts:
            return []

        # Single query: fetch all ports, then filter in Python
        # TinyDB doesn't support IN queries, so we fetch all and filter
        all_ports = self.table.all()
        hosts_set = set(hosts)
        return [p for p in all_ports if p.get("host") in hosts_set]


class CertificateRepository(BaseRepository):
    """Repository for SSL/TLS certificates"""

    def __init__(self, db):
        super().__init__(db, "certificates")

    def add_certificate(self, host: str, cert_info: Dict) -> bool:
        """Add or update certificate info"""
        q = self.query
        existing = self.table.search(q.host == host)

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
            self.table.insert(record)
            return True
        else:
            # Check if cert changed (different fingerprint)
            changed = existing[0].get("fingerprint") != cert_info.get("fingerprint")
            self.table.update(record, q.host == host)
            return changed

    def get_certificate(self, host: str) -> Optional[Dict]:
        """Get certificate info for a host"""
        q = self.query
        results = self.table.search(q.host == host)
        return results[0] if results else None

    def get_expiring_certificates(self, days: int = 30) -> List[Dict]:
        """Get certificates expiring within N days"""
        q = self.query
        return self.table.search(
            (q.days_until_expiry <= days) & (q.days_until_expiry >= 0)
        )

    def get_certificates_for_hosts(self, hosts: List[str]) -> Dict[str, Dict]:
        """Get certificates for multiple hosts in a single query.

        Returns dict mapping host -> certificate info.
        5-10x faster than calling get_certificate() per host.
        """
        if not hosts:
            return {}

        # Single query: fetch all certs, then filter in Python
        all_certs = self.table.all()
        hosts_set = set(hosts)
        return {
            c["host"]: c for c in all_certs if c.get("host") in hosts_set
        }


class TechnologyRepository(BaseRepository):
    """Repository for technology fingerprints"""

    def __init__(self, db):
        super().__init__(db, "technologies")

    def add_technologies(self, host: str, tech_info: Dict) -> None:
        """Add or update technology fingerprint"""
        q = self.query

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

        existing = self.table.search(q.host == host)
        if existing:
            self.table.update(record, q.host == host)
        else:
            self.table.insert(record)

    def get_technologies(self, host: str) -> Optional[Dict]:
        """Get technology info for a host"""
        q = self.query
        results = self.table.search(q.host == host)
        return results[0] if results else None


class DNSRepository(BaseRepository):
    """Repository for DNS records"""

    def __init__(self, db):
        super().__init__(db, "dns_records")

    def save_dns_records(self, domain: str, records: Dict[str, List]) -> None:
        """Save DNS records for a domain"""
        q = self.query

        record = {"domain": domain, "records": records, "checked_at": self._now()}

        existing = self.table.search(q.domain == domain)
        if existing:
            self.table.update(record, q.domain == domain)
        else:
            self.table.insert(record)

    def check_dns_changes(self, domain: str, new_records: Dict[str, List]) -> Dict:
        """Compare new DNS records with stored ones, return changes"""
        q = self.query
        existing = self.table.search(q.domain == domain)

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
