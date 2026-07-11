-- Migration 005: Scheduled runs tracking
CREATE TABLE IF NOT EXISTS scheduled_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type TEXT NOT NULL,
    domain TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at DATETIME,
    duration_ms INTEGER DEFAULT 0,
    error TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scheduled_runs_job_type ON scheduled_runs(job_type);
CREATE INDEX IF NOT EXISTS idx_scheduled_runs_domain ON scheduled_runs(domain);
CREATE INDEX IF NOT EXISTS idx_scheduled_runs_started_at ON scheduled_runs(started_at);
