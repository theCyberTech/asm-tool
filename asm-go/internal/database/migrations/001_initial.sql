-- ASM Tool Database Schema
-- Migration 001: Initial schema

-- Core domain tracking
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scanned DATETIME,
    active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    active INTEGER DEFAULT 1,
    UNIQUE(domain_id, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain_id);

-- Port scan results
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    version TEXT,
    product TEXT,
    state TEXT DEFAULT 'open',
    banner TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host);
CREATE INDEX IF NOT EXISTS idx_ports_state ON ports(state);

-- SSL/TLS certificates
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER DEFAULT 443,
    subject TEXT,
    issuer TEXT,
    serial_number TEXT,
    not_before DATETIME,
    not_after DATETIME,
    days_until_expiry INTEGER,
    fingerprint TEXT,
    san TEXT,
    signature_algorithm TEXT,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, port)
);

-- Technology fingerprints
CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL UNIQUE,
    status_code INTEGER,
    title TEXT,
    server TEXT,
    technologies TEXT,
    headers TEXT,
    content_length INTEGER,
    redirect_url TEXT,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- DNS records
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    records TEXT NOT NULL,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability findings
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description TEXT,
    host TEXT NOT NULL,
    matched_at TEXT,
    matcher_name TEXT,
    evidence TEXT,
    refs TEXT,
    tags TEXT,
    type TEXT,
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'resolved', 'false_positive')),
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Subdomain takeovers
CREATE TABLE IF NOT EXISTS takeovers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain TEXT NOT NULL,
    cname TEXT,
    service TEXT NOT NULL,
    takeover_type TEXT,
    confidence TEXT CHECK(confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    evidence TEXT,
    documentation TEXT,
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'resolved', 'false_positive')),
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    UNIQUE(subdomain, service)
);
CREATE INDEX IF NOT EXISTS idx_takeovers_status ON takeovers(status);

-- Discovered URLs
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    interesting INTEGER DEFAULT 0,
    category TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(domain);
CREATE INDEX IF NOT EXISTS idx_urls_interesting ON urls(interesting);

-- API endpoints
CREATE TABLE IF NOT EXISTS apis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    api_type TEXT,
    version TEXT,
    title TEXT,
    endpoints_count INTEGER DEFAULT 0,
    endpoints TEXT,
    introspection_enabled INTEGER,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Screenshots
CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL UNIQUE,
    file_path TEXT NOT NULL,
    image_hash TEXT,
    file_size INTEGER,
    width INTEGER,
    height INTEGER,
    captured_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- WHOIS records
CREATE TABLE IF NOT EXISTS whois_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    registrar TEXT,
    registrar_url TEXT,
    creation_date DATETIME,
    updated_date DATETIME,
    expiration_date DATETIME,
    days_until_expiry INTEGER,
    registrant_org TEXT,
    registrant_country TEXT,
    name_servers TEXT,
    status TEXT,
    dnssec TEXT,
    raw_data TEXT,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Cloud storage buckets
CREATE TABLE IF NOT EXISTS cloud_storage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL CHECK(provider IN ('s3', 'azure', 'gcs')),
    bucket_name TEXT NOT NULL,
    domain TEXT,
    source TEXT,
    access_level TEXT CHECK(access_level IN ('listing_enabled', 'public_read', 'authenticated_only', 'not_found')),
    severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    evidence TEXT,
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'resolved')),
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Scan history
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    status TEXT DEFAULT 'running' CHECK(status IN ('running', 'completed', 'failed')),
    summary TEXT
);

-- Snapshots for trend analysis
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    scan_type TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    subdomain_count INTEGER DEFAULT 0,
    port_count INTEGER DEFAULT 0,
    certificate_count INTEGER DEFAULT 0,
    finding_counts TEXT,
    risk_score INTEGER DEFAULT 0,
    subdomains TEXT,
    ports TEXT,
    certificates TEXT
);
CREATE INDEX IF NOT EXISTS idx_snapshots_domain ON scan_snapshots(domain);
CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON scan_snapshots(timestamp);

-- Change events
CREATE TABLE IF NOT EXISTS change_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    change_type TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description TEXT,
    old_value TEXT,
    new_value TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_changes_domain ON change_events(domain);
CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON change_events(timestamp);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (1);
