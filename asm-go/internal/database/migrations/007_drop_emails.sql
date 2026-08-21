-- Migration 007: Remove leftover email enumeration storage.

DROP TABLE IF EXISTS emails;

INSERT OR IGNORE INTO schema_migrations (version) VALUES (7);
