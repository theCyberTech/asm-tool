-- Migration 003: Add unique constraint on findings to prevent duplicates.
-- First remove any existing duplicates, keeping the earliest record.
DELETE FROM findings WHERE id NOT IN (
    SELECT MIN(id) FROM findings GROUP BY template_id, host
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup ON findings(template_id, host);
INSERT INTO schema_migrations (version) VALUES (3);
