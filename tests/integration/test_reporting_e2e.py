
import pytest
from pathlib import Path
from asm.core.database import Database
from asm.core.reporter import Reporter

@pytest.fixture
def populated_db(tmp_path):
    db_path = tmp_path / "asm.db"
    db = Database(db_path)

    domain = "example.com"
    sub = "api.example.com"

    db.add_domain(domain)
    db.add_subdomain(domain, sub)
    
    # Add comprehensive data
    db.add_port(sub, 443, "https", "nginx/1.18")
    
    db.add_certificate(sub, {
        "issuer": "Let's Encrypt",
        "not_after": "2025-01-01",
        "days_until_expiry": 30,
        "fingerprint": "abc12345",
        "host": sub
    })
    
    db.add_technologies(sub, {
        "technologies": ["React", "AWS"],
        "status_code": 200,
        "title": "API Home"
    })
    
    db.add_finding({
        "name": "XSS Vulnerability",
        "severity": "high",
        "host": sub,
        "template_id": "xss-ref"
    })
    
    db.add_takeover({
        "subdomain": sub,
        "service": "S3 Bucket",
        "status": "open",
        "confidence": "high",
        "evidence": "NoSuchBucket",
        "type": "CNAME",
        "domain": domain
    })
    
    db.add_url(domain, f"https://{sub}/v1/users", interesting=True)
    
    db.add_api({
        "url": f"https://{sub}/swagger.json",
        "title": "User API",
        "type": "swagger",
        "endpoints_count": 10
    })
    
    db.add_email(domain, "admin@example.com", "hunter.io")
    
    yield db
    db.close()

def test_domain_summary_completeness(populated_db):
    """Test that get_domain_summary returns ALL data types"""
    summary = populated_db.get_domain_summary("example.com")
    
    keys = summary.keys()
    required_keys = [
        "domain", "subdomains", "ports", "certificates", 
        "technologies", "findings", "takeovers", 
        "urls", "apis", "emails"
    ]
    
    for key in required_keys:
        assert key in keys, f"Missing {key} in domain summary"
        
    assert len(summary["takeovers"]) == 1
    assert len(summary["apis"]) == 1
    assert len(summary["emails"]) == 1

def test_report_generation_markdown(populated_db):
    """Test Markdown report contains all sections"""
    summary = populated_db.get_domain_summary("example.com")
    reporter = Reporter(populated_db)
    
    report = reporter.generate(summary, format="markdown")
    
    assert "### Technologies" in report
    assert "React" in report
    
    assert "### Subdomain Takeovers" in report
    assert "S3 Bucket" in report
    
    assert "### APIs" in report
    assert "swagger" in report
    
    assert "### Emails" in report
    assert "admin@example.com" in report

def test_report_generation_html(populated_db):
    """Test HTML report contains all sections"""
    summary = populated_db.get_domain_summary("example.com")
    reporter = Reporter(populated_db)
    
    report = reporter.generate(summary, format="html")
    
    assert "Technologies" in report
    assert "React" in report
    
    assert "Subdomain Takeovers" in report
    assert "S3 Bucket" in report
    
    # HTML tables check
    assert "<th>Stack</th>" in report
    assert "<th>Service</th>" in report

def test_report_generation_table(populated_db):
    """Test Rich Table report contains all sections"""
    summary = populated_db.get_domain_summary("example.com")
    reporter = Reporter(populated_db)
    
    report = reporter.generate(summary, format="table")
    
    # Rich table output contains titles
    assert "Technologies for example.com" in report
    assert "Subdomain Takeovers for example.com" in report
    assert "APIs for example.com" in report
    assert "Emails for example.com" in report
    assert "Certificates for example.com" in report
