from typing import List, Dict, Optional
from tinydb import Query
from .base import BaseRepository

class FindingRepository(BaseRepository):
    """Repository for vulnerability findings"""

    def __init__(self, db):
        super().__init__(db, "findings")

    def add_finding(self, finding: Dict) -> bool:
        """Add a vulnerability finding"""
        q = self.query

        # Create a unique key for the finding
        finding_key = (
            f"{finding['host']}:{finding['template_id']}:"
            f"{finding.get('matched_at', '')}"
        )

        existing = self.table.search(q.finding_key == finding_key)

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
            self.table.insert(record)
            return True
        else:
            # Update last seen
            self.table.update(
                {"last_seen": self._now()}, q.finding_key == finding_key
            )
            return False

    def get_findings(self, host: str = None, severity: str = None) -> List[Dict]:
        """Get vulnerability findings, optionally filtered"""
        q = self.query

        if host and severity:
            return self.table.search((q.host == host) & (q.severity == severity))
        elif host:
            return self.table.search(q.host == host)
        elif severity:
            return self.table.search(q.severity == severity)
        else:
            return self.table.all()

    def get_open_findings(self) -> List[Dict]:
        """Get all open (unresolved) findings"""
        q = self.query
        return self.table.search(q.status == "open")


class TakeoverRepository(BaseRepository):
    """Repository for subdomain takeovers"""

    def __init__(self, db):
        super().__init__(db, "takeovers")

    def add_takeover(self, takeover: Dict) -> bool:
        """Add a subdomain takeover finding. Returns True if new."""
        q = self.query
        subdomain = takeover["subdomain"]

        existing = self.table.search(q.subdomain == subdomain)

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
            self.table.insert(record)
            return True
        else:
            # Update if already exists
            self.table.update(
                {"last_seen": self._now(), "status": "open"}, q.subdomain == subdomain
            )
            return False

    def get_takeovers(self, status: str = None) -> List[Dict]:
        """Get takeover findings, optionally filtered by status"""
        if status:
            q = self.query
            return self.table.search(q.status == status)
        return self.table.all()

    def resolve_takeover(self, subdomain: str) -> None:
        """Mark a takeover as resolved"""
        q = self.query
        self.table.update(
            {"status": "resolved", "resolved_at": self._now()}, q.subdomain == subdomain
        )
