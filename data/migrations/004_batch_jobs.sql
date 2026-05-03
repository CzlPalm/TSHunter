-- Phase B1: batch analysis job tracking
CREATE TABLE IF NOT EXISTS batch_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','downloading','analyzing','ingesting','done','failed','skipped')),
    started_at TEXT,
    finished_at TEXT,
    error_msg TEXT,
    binary_sha256 TEXT,
    analyzer_runs_id INTEGER,
    method TEXT,
    method_duration_sec REAL,
    relocate_max_outlier_delta INTEGER,
    FOREIGN KEY (analyzer_runs_id) REFERENCES analyzer_runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_batch_run ON batch_jobs(run_id, status);
CREATE INDEX IF NOT EXISTS idx_batch_version ON batch_jobs(browser, version, platform, arch);
