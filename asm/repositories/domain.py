from typing import List
from tinydb import Query
from .base import BaseRepository

class DomainRepository(BaseRepository):
    """Repository for domains and subdomains"""

    def __init__(self, db):
        super().__init__(db, "domains")
        self.subdomains = db.table("subdomains")

    # === Domain Management ===

    def add_domain(self, domain: str) -> bool:
        """Add a root domain to track"""
        q = self.query
        if not self.table.search(q.domain == domain):
            self.table.insert(
                {"domain": domain, "added_at": self._now(), "last_scanned": None}
            )
            return True
        return False

    def get_domains(self) -> List[str]:
        """Get all tracked root domains"""
        return [d["domain"] for d in self.table.all()]

    # === Subdomain Management ===

    def add_subdomain(self, root_domain: str, subdomain: str) -> bool:
        """Add a discovered subdomain. Returns True if new."""
        q = self.query
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
        q = self.query
        results = self.subdomains.search(q.root_domain == root_domain)
        return [r["subdomain"] for r in results]

    def get_all_subdomains(self) -> List[str]:
        """Get all known subdomains across all domains"""
        return [r["subdomain"] for r in self.subdomains.all()]
