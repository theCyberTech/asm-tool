from typing import List, Dict, Optional
from tinydb import Query
from .base import BaseRepository


class CloudStorageRepository(BaseRepository):
    """Repository for cloud storage bucket findings"""

    def __init__(self, db):
        super().__init__(db, "cloud_storage")

    def add_bucket(self, bucket: Dict) -> bool:
        """
        Add a cloud storage bucket finding.
        Returns True if new, False if duplicate.
        Deduplication is by bucket URL.
        """
        q = self.query
        url = bucket["url"]

        existing = self.table.search(q.url == url)

        record = {
            "url": url,
            "provider": bucket.get("provider", ""),
            "bucket_name": bucket.get("bucket_name", ""),
            "source": bucket.get("source", ""),
            "access_level": bucket.get("access_level", "unknown"),
            "severity": bucket.get("severity", "low"),
            "evidence": bucket.get("evidence", ""),
            "discovered_at": self._now(),
            "status": bucket.get("status", "open"),
            "domain": bucket.get("domain", ""),
        }

        if not existing:
            self.table.insert(record)
            return True
        else:
            # Update last seen timestamp
            self.table.update({"last_seen": self._now()}, q.url == url)
            return False

    def get_buckets(
        self, domain: str = None, severity: str = None
    ) -> List[Dict]:
        """
        Get cloud storage bucket findings, optionally filtered by domain and/or severity.
        """
        q = self.query

        if domain and severity:
            return self.table.search((q.domain == domain) & (q.severity == severity))
        elif domain:
            return self.table.search(q.domain == domain)
        elif severity:
            return self.table.search(q.severity == severity)
        else:
            return self.table.all()

    def get_open_buckets(self) -> List[Dict]:
        """Get all buckets with status='open'"""
        q = self.query
        return self.table.search(q.status == "open")
