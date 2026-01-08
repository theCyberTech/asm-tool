"""
Change Detection and Tracking Module for ASM Tool

This module provides change detection capabilities for tracking asset evolution
over time, including subdomain additions/removals, port changes,
certificate changes, and vulnerability tracking.
"""

from typing import Dict, List


class ChangeDetector:
    """Detects and analyzes changes in domain assets over time.

    Compares historical snapshots to identify new/removed assets,
    calculate risk deltas, and generate change events for tracking.
    """

    def __init__(self, db):
        """Initialize change detector with database instance.

        Args:
            db: Database instance for accessing snapshots and change events
        """
        self.db = db

    def detect_changes(self, domain: str, current_state: Dict) -> Dict:
        """Detect changes between current state and previous snapshot.

        Args:
            domain: Root domain to analyze
            current_state: Current scan state with subdomains, ports, etc.

        Returns:
            Dict containing:
                - new_subdomains: List of newly discovered subdomains
                - removed_subdomains: List of subdomains no longer present
                - new_ports: List of newly opened ports
                - closed_ports: List of previously open, now closed ports
                - new_vulnerabilities: List of new vulnerabilities
                - certificate_changes: Certificate fingerprint changes
                - risk_delta: Change in risk score
                - significant_changes: Changes exceeding thresholds
        """
        previous_snapshot = self.db.get_latest_snapshot(domain)

        if not previous_snapshot:
            return self._first_scan_response(current_state)

        changes = {
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_ports": [],
            "closed_ports": [],
            "new_vulnerabilities": [],
            "certificate_changes": [],
            "risk_delta": 0,
            "significant_changes": [],
        }

        previous_subdomains = set(previous_snapshot.get("subdomains", []))
        current_subdomains = set(current_state.get("subdomains", []))

        changes["new_subdomains"] = list(current_subdomains - previous_subdomains)
        changes["removed_subdomains"] = list(previous_subdomains - current_subdomains)

        previous_ports = set(previous_snapshot.get("ports", []))
        current_ports = set(current_state.get("ports", []))

        changes["new_ports"] = list(current_ports - previous_ports)
        changes["closed_ports"] = list(previous_ports - current_ports)

        changes["certificate_changes"] = self._detect_certificate_changes(
            previous_snapshot, current_state
        )

        changes["new_vulnerabilities"] = self._detect_new_vulnerabilities(
            previous_snapshot, current_state
        )

        previous_risk = previous_snapshot.get("risk_score", 0)
        current_risk = current_state.get("risk_score", 0)
        changes["risk_delta"] = current_risk - previous_risk

        changes["significant_changes"] = self._identify_significant_changes(
            changes, previous_risk, current_risk
        )

        return changes

    def calculate_risk(self, vulnerabilities: Dict, asset_count: int) -> float:
        """Calculate risk score based on vulnerabilities and asset count.

        Risk formula: critical * 10 + high * 5 + medium * 2 + low * 1
        Additional factors: asset density, new assets, etc.

        Args:
            vulnerabilities: Dict with critical/high/medium/low counts
            asset_count: Total number of assets (subdomains, ports)

        Returns:
            Calculated risk score
        """
        base_risk = (
            vulnerabilities.get("critical", 0) * 10
            + vulnerabilities.get("high", 0) * 5
            + vulnerabilities.get("medium", 0) * 2
            + vulnerabilities.get("low", 0) * 1
        )

        if asset_count > 0:
            density_factor = min(asset_count / 50.0, 2.0)
        else:
            density_factor = 0

        return base_risk * (1 + density_factor * 0.1)

    def generate_change_events(self, domain: str, changes: Dict) -> List[Dict]:
        """Generate change events from detected changes.

        Creates individual event records for each significant change
        for tracking and alerting purposes.

        Args:
            domain: Root domain
            changes: Dict of detected changes from detect_changes()

        Returns:
            List of change event dicts
        """
        events = []

        for subdomain in changes.get("new_subdomains", []):
            events.append(
                {
                    "domain": domain,
                    "change_type": "subdomain_added",
                    "description": f"New subdomain discovered: {subdomain}",
                    "severity": "info",
                    "details": {"host": subdomain, "action": "added"},
                }
            )

        for subdomain in changes.get("removed_subdomains", []):
            events.append(
                {
                    "domain": domain,
                    "change_type": "subdomain_removed",
                    "description": f"Subdomain no longer present: {subdomain}",
                    "severity": "info",
                    "details": {"host": subdomain, "action": "removed"},
                }
            )

        for port in changes.get("new_ports", []):
            events.append(
                {
                    "domain": domain,
                    "change_type": "port_opened",
                    "description": f"New port opened: {port}",
                    "severity": "medium",
                    "details": {"port": port, "action": "opened"},
                }
            )

        for port in changes.get("closed_ports", []):
            events.append(
                {
                    "domain": domain,
                    "change_type": "port_closed",
                    "description": f"Port closed: {port}",
                    "severity": "low",
                    "details": {"port": port, "action": "closed"},
                }
            )

        for vuln in changes.get("new_vulnerabilities", []):
            severity = vuln.get("severity", "medium").lower()
            sev_weight = {"critical": "critical", "high": "high"}.get(
                severity, "medium"
            )
            events.append(
                {
                    "domain": domain,
                    "change_type": "vulnerability_added",
                    "description": (
                        f"New vulnerability: {vuln.get('name', 'Unknown')} "
                        f"({severity})"
                    ),
                    "severity": sev_weight,
                    "details": vuln,
                }
            )

        for cert_change in changes.get("certificate_changes", []):
            events.append(
                {
                    "domain": domain,
                    "change_type": "certificate_changed",
                    "description": (
                        "Certificate changed for "
                        f"{cert_change.get('host', 'unknown')}"
                    ),
                    "severity": "medium",
                    "details": cert_change,
                }
            )

        if changes.get("risk_delta", 0) != 0:
            delta = changes["risk_delta"]
            if delta > 0:
                events.append(
                    {
                        "domain": domain,
                        "change_type": "risk_increased",
                        "description": f"Risk score increased by {delta:.1f}",
                        "severity": "high" if delta > 10 else "medium",
                        "details": {"delta": delta, "direction": "increase"},
                    }
                )
            else:
                events.append(
                    {
                        "domain": domain,
                        "change_type": "risk_decreased",
                        "description": f"Risk score decreased by {abs(delta):.1f}",
                        "severity": "info",
                        "details": {"delta": delta, "direction": "decrease"},
                    }
                )

        return events

    def _first_scan_response(self, current_state: Dict) -> Dict:
        """Generate response for first scan (no previous data)."""
        return {
            "new_subdomains": current_state.get("subdomains", []),
            "removed_subdomains": [],
            "new_ports": current_state.get("ports", []),
            "closed_ports": [],
            "new_vulnerabilities": [],
            "certificate_changes": [],
            "risk_delta": 0,
            "significant_changes": [],
            "is_first_scan": True,
        }

    def _detect_certificate_changes(self, previous: Dict, current: Dict) -> List[Dict]:
        """Detect certificate fingerprint changes."""
        previous_certs = {
            c["host"]: c.get("fingerprint", "")
            for c in previous.get("certificates", [])
        }

        current_certs = {
            c["host"]: c.get("fingerprint", "") for c in current.get("certificates", [])
        }

        changes = []

        for host, current_fp in current_certs.items():
            previous_fp = previous_certs.get(host)
            if not previous_fp:
                changes.append({"host": host, "type": "new", "fingerprint": current_fp})
            elif previous_fp != current_fp:
                changes.append(
                    {
                        "host": host,
                        "type": "changed",
                        "previous_fingerprint": previous_fp,
                        "new_fingerprint": current_fp,
                    }
                )

        return changes

    def _detect_new_vulnerabilities(self, previous: Dict, current: Dict) -> List[Dict]:
        """Detect vulnerabilities that are new in current scan."""
        previous_vulns = previous.get("vulnerabilities", {})

        current_vulns = current.get("vulnerabilities", {})

        new_vulns = []

        for severity in ["critical", "high", "medium", "low"]:
            delta = current_vulns.get(severity, 0) - previous_vulns.get(severity, 0)
            if delta > 0:
                new_vulns.append(
                    {"severity": severity, "count": delta, "type": "count_increase"}
                )

        return new_vulns

    def _identify_significant_changes(
        self, changes: Dict, previous_risk: float, current_risk: float
    ) -> List[Dict]:
        """Identify changes that exceed alerting thresholds."""
        significant = []

        if len(changes.get("new_subdomains", [])) >= 5:
            significant.append(
                {
                    "type": "subdomain_surge",
                    "description": (
                        f"{len(changes['new_subdomains'])} new subdomains discovered"
                    ),
                    "severity": "medium",
                }
            )

        if len(changes.get("new_ports", [])) >= 3:
            significant.append(
                {
                    "type": "port_surge",
                    "description": f"{len(changes['new_ports'])} new ports opened",
                    "severity": "high",
                }
            )

        risk_change = abs(current_risk - previous_risk)
        if risk_change >= 10:
            significance = "critical" if risk_change >= 20 else "high"
            direction = "increased" if current_risk > previous_risk else "decreased"
            significant.append(
                {
                    "type": "risk_spike",
                    "description": f"Risk score {direction} by {risk_change:.1f}",
                    "severity": significance,
                }
            )

        new_crit_vulns = sum(
            1
            for v in changes.get("new_vulnerabilities", [])
            if v.get("severity") == "critical"
        )
        if new_crit_vulns > 0:
            significant.append(
                {
                    "type": "critical_vulnerabilities",
                    "description": f"{new_crit_vulns} new critical vulnerabilities",
                    "severity": "critical",
                }
            )

        return significant
