-- Migration 004: Add vulnerabilities column to scan_snapshots
ALTER TABLE scan_snapshots ADD COLUMN vulnerabilities TEXT;
INSERT OR IGNORE INTO schema_migrations (version) VALUES (4);
