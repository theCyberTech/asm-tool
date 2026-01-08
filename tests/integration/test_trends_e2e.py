"""
Integration test for trends feature end-to-end verification

This test verifies that the complete historical trend analysis feature
works by simulating scan history for a domain and running trends command.
"""

import os
import tempfile
import shutil

from asm.core.database import Database


def test_end_to_end_trends_feature():
    """Complete end-to-end test of trends feature"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_asm.db")

        db = Database(db_path)

        domain = "example.com"

        db.add_domain(domain)

        db.add_subdomain(domain, "sub1.example.com")
        db.add_subdomain(domain, "sub2.example.com")

        db.add_port("sub1.example.com", 80, "http", "nginx/1.18")

        cert_info = {
            "issuer": "Test CA",
            "subject": "sub1.example.com",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2026-01-01T00:00:00Z",
            "days_until_expiry": 365,
            "fingerprint": "cert_fp_1",
        }
        db.add_certificate("sub1.example.com", cert_info)

        snapshot_id_1 = db.save_snapshot(domain, "full")

        db.add_subdomain(domain, "sub3.example.com")

        db.add_port("sub2.example.com", 443, "https", "nginx/1.19.1")

        cert_info_2 = {
            "issuer": "Test CA",
            "subject": "sub2.example.com",
            "not_before": "2025-02-01T00:00:00Z",
            "not_after": "2026-02-01T00:00:00Z",
            "days_until_expiry": 180,
            "fingerprint": "cert_fp_2",
        }
        db.add_certificate("sub2.example.com", cert_info_2)

        snapshot_id_2 = db.save_snapshot(domain, "full")

        summary = db.get_trend_summary(domain, days=30)

        assert summary["has_history"] == True
        assert summary["domain"] == domain
        assert summary["days"] == 30
        assert summary["snapshots_count"] == 2

        assert summary["subdomains"]["current"] == 3
        assert summary["subdomains"]["previous"] == 2
        assert summary["subdomains"]["delta"] == 1
        assert "sub3.example.com" in summary["subdomains"]["new"]
        assert len(summary["subdomains"]["removed"]) == 0

        assert summary["ports"]["current"] == 2
        assert summary["ports"]["previous"] == 1
        assert summary["ports"]["delta"] == 1
        assert "sub2.example.com:443" in summary["ports"]["new"]
        assert len(summary["ports"]["removed"]) == 0

        assert summary["certificates"]["current"] == 2
        assert summary["certificates"]["previous"] == 1
        assert summary["certificates"]["delta"] == 1

        assert summary["vulnerabilities"]["current"]["total"] == 0
        assert summary["vulnerabilities"]["previous"]["total"] == 0

        assert summary["vulnerabilities"]["delta"]["total"] == 0

        assert summary["risk_score"]["current"] >= 0
        assert summary["risk_score"]["previous"] >= 0
        assert summary["risk_score"]["trend"] in ["stable", "increasing", "decreasing"]

        assert summary["snapshots_count"] == len(
            db.get_snapshots_in_range(domain, days=30)
        )

        db.close()

        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    test_end_to_end_trends_feature()
