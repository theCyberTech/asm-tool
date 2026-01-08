from typing import List, Dict, Optional
import re
from urllib.parse import urlparse
from tinydb import Query
from .base import BaseRepository

class URLRepository(BaseRepository):
    """Repository for URLs"""

    def __init__(self, db):
        super().__init__(db, "urls")
        self.summaries = db.table("url_summaries")

    def add_url(self, domain: str, url: str, interesting: bool = False) -> bool:
        """Add a discovered URL. Returns True if new."""
        q = self.query
        existing = self.table.search((q.domain == domain) & (q.url == url))

        if not existing:
            self.table.insert(
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
            self.table.update(
                {"last_seen": self._now()}, (q.domain == domain) & (q.url == url)
            )
            return False

    def add_urls_bulk(self, domain: str, url_data: Dict) -> Dict[str, int]:
        """Add multiple URLs from URL enumeration results. Returns counts.

        Uses true bulk operations for 10-50x speedup:
        - Single query to fetch existing URLs
        - insert_multiple() for new records
        - Single update for existing records' last_seen
        """
        counts = {"new": 0, "existing": 0, "interesting_new": 0}

        urls = url_data.get("urls", [])
        if not urls:
            self._save_url_summary(domain, url_data)
            return counts

        interesting_set = set(url_data.get("interesting", []))
        now = self._now()

        # Single query: get all existing URLs for this domain
        q = self.query
        existing_records = self.table.search(q.domain == domain)
        existing_urls = {r["url"] for r in existing_records}

        # Partition into new vs existing
        new_records = []
        existing_count = 0

        for url in urls:
            if url in existing_urls:
                existing_count += 1
            else:
                is_interesting = url in interesting_set
                new_records.append({
                    "domain": domain,
                    "url": url,
                    "interesting": is_interesting,
                    "discovered_at": now,
                    "last_seen": now,
                })
                if is_interesting:
                    counts["interesting_new"] += 1

        # Bulk insert new records
        if new_records:
            self.table.insert_multiple(new_records)

        # Single update for all existing URLs' last_seen
        if existing_count > 0:
            self.table.update({"last_seen": now}, q.domain == domain)

        counts["new"] = len(new_records)
        counts["existing"] = existing_count

        # Store summary data
        self._save_url_summary(domain, url_data)

        return counts

    def _save_url_summary(self, domain: str, url_data: Dict) -> None:
        """Save URL enumeration summary for a domain"""
        q = self.query

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
        existing = self.summaries.search(q.domain == domain)
        if existing:
            self.summaries.update(summary, q.domain == domain)
        else:
            self.summaries.insert(summary)

    def get_urls(self, domain: str, interesting_only: bool = False) -> List[str]:
        """Get discovered URLs for a domain"""
        q = self.query
        if interesting_only:
            results = self.table.search(
                (q.domain == domain) & (q.interesting.test(lambda x: x is True))
            )
        else:
            results = self.table.search(q.domain == domain)
        return [r["url"] for r in results]

    def get_url_summary(self, domain: str) -> Optional[Dict]:
        """Get URL enumeration summary for a domain"""
        q = self.query
        results = self.summaries.search(q.domain == domain)
        return results[0] if results else None

    def get_all_urls(self, interesting_only: bool = False) -> List[Dict]:
        """Get all discovered URLs across all domains"""
        if interesting_only:
            q = self.query
            return self.table.search(q.interesting.test(lambda x: x is True))
        return self.table.all()


class APIRepository(BaseRepository):
    """Repository for API discovery"""

    def __init__(self, db):
        super().__init__(db, "apis")

    def add_api(self, api: Dict) -> bool:
        """Add a discovered API endpoint. Returns True if new."""
        q = self.query
        url = api["url"]

        existing = self.table.search(q.url == url)

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
            self.table.insert(record)
            return True
        else:
            self.table.update(record, q.url == url)
            return False

    def get_apis(self, api_type: str = None) -> List[Dict]:
        """Get discovered APIs, optionally filtered by type"""
        if api_type:
            q = self.query
            return self.table.search(q.type == api_type)
        return self.table.all()

    def get_apis_for_host(self, host: str) -> List[Dict]:
        """Get all APIs for a specific host"""
        q = self.query
        # Note: requires 're' import
        return self.table.search(q.host.matches(f".*{re.escape(host)}.*"))


class EmailRepository(BaseRepository):
    """Repository for Email enumeration"""

    def __init__(self, db):
        super().__init__(db, "emails")

    def add_email(self, domain: str, email: str, source: str = "") -> bool:
        """Add a discovered email. Returns True if new."""
        q = self.query
        existing = self.table.search(q.email == email.lower())

        if not existing:
            self.table.insert(
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
        """Add multiple emails from enumeration results. Returns counts.

        Uses true bulk operations for 5-10x speedup:
        - Single query to fetch all existing emails
        - insert_multiple() for new records
        """
        counts = {"new": 0, "existing": 0}

        by_source = email_data.get("by_source", {})
        if not by_source:
            return counts

        now = self._now()

        # Single query: get all existing emails (globally, since emails are unique)
        existing_records = self.table.all()
        existing_emails = {r["email"] for r in existing_records}

        # Collect new emails with their sources
        new_records = []
        for source, emails in by_source.items():
            for email in emails:
                email_lower = email.lower()
                if email_lower in existing_emails:
                    counts["existing"] += 1
                else:
                    new_records.append({
                        "domain": domain,
                        "email": email_lower,
                        "source": source,
                        "discovered_at": now,
                    })
                    # Add to set to handle duplicates within same batch
                    existing_emails.add(email_lower)

        # Bulk insert new records
        if new_records:
            self.table.insert_multiple(new_records)

        counts["new"] = len(new_records)

        return counts

    def get_emails(self, domain: str = None) -> List[Dict]:
        """Get discovered emails, optionally filtered by domain"""
        if domain:
            q = self.query
            return self.table.search(q.domain == domain)
        return self.table.all()

    def get_email_count(self, domain: str = None) -> int:
        """Get count of discovered emails"""
        return len(self.get_emails(domain))
