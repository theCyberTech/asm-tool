export const SCHEMA = `
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    added_at TEXT NOT NULL,
    last_scanned TEXT,
    active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    active INTEGER DEFAULT 1,
    UNIQUE(domain_id, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain_id);

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
    discovered_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(host, port, protocol)
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER DEFAULT 443,
    subject TEXT,
    issuer TEXT,
    serial_number TEXT,
    not_before TEXT,
    not_after TEXT,
    days_until_expiry INTEGER,
    fingerprint TEXT,
    san TEXT,
    signature_algorithm TEXT,
    checked_at TEXT NOT NULL,
    UNIQUE(host, port)
);

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
    checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    records TEXT NOT NULL,
    checked_at TEXT NOT NULL
);

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
    discovered_at TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE(template_id, host)
);

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
    discovered_at TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE(subdomain, service)
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    interesting INTEGER DEFAULT 0,
    category TEXT,
    source TEXT,
    discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS apis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    api_type TEXT,
    version TEXT,
    title TEXT,
    endpoints_count INTEGER DEFAULT 0,
    endpoints TEXT,
    introspection_enabled INTEGER,
    discovered_at TEXT NOT NULL
);

-- Unused leftover table: kept so existing asm.db files still open.
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    source TEXT,
    discovered_at TEXT NOT NULL
);

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
    discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS change_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    change_type TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description TEXT,
    old_value TEXT,
    new_value TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    label TEXT NOT NULL,
    command TEXT NOT NULL,
    target TEXT,
    status TEXT NOT NULL,
    exit_code INTEGER DEFAULT 0,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    stdout TEXT DEFAULT '',
    stderr TEXT DEFAULT '',
    error TEXT,
    truncated INTEGER DEFAULT 0
);
`;
