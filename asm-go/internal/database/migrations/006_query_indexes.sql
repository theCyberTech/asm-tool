-- Migration 006: Indexes for frequently queried columns used by the dashboard
-- and domain-detail pages.

CREATE INDEX IF NOT EXISTS idx_certificates_host ON certificates(host);
CREATE INDEX IF NOT EXISTS idx_certificates_expiry ON certificates(days_until_expiry);
CREATE INDEX IF NOT EXISTS idx_ports_host_state ON ports(host, state);
CREATE INDEX IF NOT EXISTS idx_findings_host_status ON findings(host, status);
CREATE INDEX IF NOT EXISTS idx_cloud_storage_domain ON cloud_storage(domain);
CREATE INDEX IF NOT EXISTS idx_cloud_storage_status ON cloud_storage(status);
CREATE INDEX IF NOT EXISTS idx_takeovers_subdomain ON takeovers(subdomain);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (6);
