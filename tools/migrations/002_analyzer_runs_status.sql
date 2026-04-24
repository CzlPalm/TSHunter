-- F2: record analyzer run outcome so silent-failure cases surface in audit

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES ('002_analyzer_runs_status', datetime('now'));

ALTER TABLE analyzer_runs ADD COLUMN status TEXT
    DEFAULT 'SUCCESS'
    CHECK(status IN ('SUCCESS','FAILED_EMPTY','FAILED_GHIDRA'));

CREATE INDEX IF NOT EXISTS idx_analyzer_runs_status ON analyzer_runs(status);
