-- Add source column to urls table
ALTER TABLE urls ADD COLUMN source TEXT;

INSERT INTO schema_migrations (version) VALUES (2);
