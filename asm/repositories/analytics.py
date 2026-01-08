from typing import List, Dict, Optional
import uuid
from datetime import datetime, timezone, timedelta
from tinydb import Query
from .base import BaseRepository

class AnalyticsRepository(BaseRepository):
    """Repository for analytics, history, and trends"""

    def __init__(self, db):
        # We handle multiple tables, so BaseRepository init is just for one primary (scan_history)
        super().__init__(db, "scan_history")
        self.scan_snapshots = db.table("scan_snapshots")
        self.change_events = db.table("change_events")
        self.trend_history = db.table("trend_history") # Not used in original code explicitly?

    def record_scan(self, domain: str, scan_type: str) -> None:
        """Record that a scan was performed"""
        self.table.insert(
            {"domain": domain, "scan_type": scan_type, "timestamp": self._now()}
        )

    def get_last_scan_time(self) -> str:
        """Get the most recent scan timestamp"""
        history = self.table.all()
        if history:
            return max(h["timestamp"] for h in history)
        return "Never"

    # === Snapshots ===

    def add_snapshot(self, snapshot: Dict) -> str:
        """Save a snapshot. Returns snapshot ID."""
        if "snapshot_id" not in snapshot:
            snapshot["snapshot_id"] = str(uuid.uuid4())
        if "timestamp" not in snapshot:
            snapshot["timestamp"] = self._now()
        
        self.scan_snapshots.insert(snapshot)
        return snapshot["snapshot_id"]

    def get_snapshot(self, snapshot_id: str) -> Optional[Dict]:
        """Get a specific snapshot by ID"""
        q = self.query
        results = self.scan_snapshots.search(q.snapshot_id == snapshot_id)
        return results[0] if results else None

    def get_latest_snapshot(self, domain: str) -> Optional[Dict]:
        """Get the most recent snapshot for a domain"""
        q = self.query
        domain_snapshots = self.scan_snapshots.search(q.domain == domain)
        if domain_snapshots:
            return max(domain_snapshots, key=lambda s: s.get("timestamp", ""))
        return None

    def get_snapshots_in_range(self, domain: str, days: int = 30) -> List[Dict]:
        """Get all snapshots for a domain within N days"""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        q = self.query

        snapshots = self.scan_snapshots.search(
            (q.domain == domain) & (q.timestamp >= cutoff)
        )

        return sorted(snapshots, key=lambda s: s.get("timestamp", ""))

    # === Change Events ===

    def save_change_event(self, event: Dict) -> str:
        """Save a change event for tracking"""
        event["event_id"] = str(uuid.uuid4())
        event["timestamp"] = self._now()

        self.change_events.insert(event)
        return event["event_id"]

    def get_change_events(
        self, domain: str, days: int = 30, change_type: str = None
    ) -> List[Dict]:
        """Get change events for a domain within N days"""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        q = self.query

        query = (q.domain == domain) & (q.timestamp >= cutoff)
        if change_type:
            query = query & (q.change_type == change_type)

        events = self.change_events.search(query)
        return sorted(events, key=lambda e: e.get("timestamp", ""), reverse=True)

    # === Risk Analysis ===

    def calculate_risk_delta(self, domain: str, days: int = 30) -> Dict:
        """Calculate risk score changes over time period"""
        snapshots = self.get_snapshots_in_range(domain, days)

        if len(snapshots) < 2:
            return {"current": 0, "previous": 0, "delta": 0, "trend": "stable"}

        latest = snapshots[-1]
        previous = snapshots[0]

        current_score = latest.get("risk_score", 0)
        previous_score = previous.get("risk_score", 0)
        delta = current_score - previous_score

        trend = "stable"
        if delta > 0:
            trend = "increasing"
        elif delta < 0:
            trend = "decreasing"

        return {
            "current": current_score,
            "previous": previous_score,
            "delta": delta,
            "trend": trend,
        }

    def get_trend_summary(self, domain: str, days: int = 30) -> Dict:
        """Get detailed trend summary by comparing oldest and newest snapshot in range"""
        snapshots = self.get_snapshots_in_range(domain, days)
        
        summary = {
            "domain": domain,
            "days": days,
            "has_history": False,
            "snapshots_count": len(snapshots),
            "subdomains": {"current": 0, "previous": 0, "delta": 0, "new": [], "removed": []},
            "ports": {"current": 0, "previous": 0, "delta": 0, "new": [], "removed": []},
            "certificates": {"current": 0, "previous": 0, "delta": 0},
            "vulnerabilities": {
                "current": {"total": 0}, 
                "previous": {"total": 0}, 
                "delta": {"total": 0}
            },
            "risk_score": {"current": 0, "previous": 0, "delta": 0, "trend": "stable"}
        }

        if len(snapshots) < 2:
            # If we have 1 snapshot, fill current values at least?
            if len(snapshots) == 1:
                latest = snapshots[0]
                summary["subdomains"]["current"] = latest.get("subdomain_count", 0)
                summary["ports"]["current"] = latest.get("port_count", 0)
                summary["certificates"]["current"] = latest.get("certificate_count", 0)
                summary["vulnerabilities"]["current"]["total"] = latest.get("vulnerabilities", {}).get("total", 0)
                summary["risk_score"]["current"] = latest.get("risk_score", 0)
            return summary

        summary["has_history"] = True
        latest = snapshots[-1]
        previous = snapshots[0]

        # Calculate Diffs
        # Subdomains
        curr_subs = set(latest.get("subdomains", []))
        prev_subs = set(previous.get("subdomains", []))
        summary["subdomains"]["current"] = len(curr_subs)
        summary["subdomains"]["previous"] = len(prev_subs)
        summary["subdomains"]["delta"] = len(curr_subs) - len(prev_subs)
        summary["subdomains"]["new"] = sorted(list(curr_subs - prev_subs))
        summary["subdomains"]["removed"] = sorted(list(prev_subs - curr_subs))

        # Ports
        curr_ports = set(latest.get("ports", []))
        prev_ports = set(previous.get("ports", []))
        summary["ports"]["current"] = len(curr_ports)
        summary["ports"]["previous"] = len(prev_ports)
        summary["ports"]["delta"] = len(curr_ports) - len(prev_ports)
        summary["ports"]["new"] = sorted(list(curr_ports - prev_ports))
        summary["ports"]["removed"] = sorted(list(prev_ports - curr_ports))

        # Certificates
        curr_certs = latest.get("certificate_count", 0)
        prev_certs = previous.get("certificate_count", 0)
        summary["certificates"]["current"] = curr_certs
        summary["certificates"]["previous"] = prev_certs
        summary["certificates"]["delta"] = curr_certs - prev_certs

        # Vulnerabilities
        curr_vulns = latest.get("vulnerabilities", {}).get("total", 0)
        prev_vulns = previous.get("vulnerabilities", {}).get("total", 0)
        summary["vulnerabilities"]["current"]["total"] = curr_vulns
        summary["vulnerabilities"]["previous"]["total"] = prev_vulns
        summary["vulnerabilities"]["delta"]["total"] = curr_vulns - prev_vulns

        # Risk Score
        summary["risk_score"] = self.calculate_risk_delta(domain, days)

        return summary
