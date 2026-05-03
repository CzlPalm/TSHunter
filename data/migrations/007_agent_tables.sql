-- Phase A1: Agent automation tables
-- source_artifacts: records downloaded packages, real binary paths, and sha256
CREATE TABLE IF NOT EXISTS source_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    channel TEXT,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,

    source TEXT NOT NULL,
    package_url TEXT,
    package_path TEXT,
    binary_path TEXT,
    binary_sha256 TEXT NOT NULL,
    version_output TEXT,

    source_metadata_json TEXT,
    downloaded_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT,

    UNIQUE(browser, version, channel, platform, arch, binary_sha256)
);

CREATE INDEX IF NOT EXISTS idx_source_artifacts_lookup
ON source_artifacts(browser, version, platform, arch);

CREATE INDEX IF NOT EXISTS idx_source_artifacts_sha256
ON source_artifacts(binary_sha256);

-- agent_tasks: task orchestration, state recovery, and error tracking
CREATE TABLE IF NOT EXISTS agent_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT UNIQUE NOT NULL,

    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    channel TEXT,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,

    source TEXT,
    source_artifact_id INTEGER,
    binary_path TEXT,
    binary_sha256 TEXT,

    task_type TEXT NOT NULL DEFAULT 'analyze_candidate',
    status TEXT NOT NULL,
    priority INTEGER DEFAULT 100,

    created_at TEXT NOT NULL,
    started_at TEXT,
    updated_at TEXT,
    finished_at TEXT,

    error_stage TEXT,
    error_msg TEXT,
    retry_count INTEGER DEFAULT 0,

    FOREIGN KEY(source_artifact_id) REFERENCES source_artifacts(id)
);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_status
ON agent_tasks(status, priority, created_at);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_target
ON agent_tasks(browser, version, platform, arch);

-- hook_candidates: unverified hook candidate results (staging area)
CREATE TABLE IF NOT EXISTS hook_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    task_id TEXT NOT NULL,
    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,

    kind TEXT NOT NULL,
    rva TEXT,
    fingerprint TEXT,
    fingerprint_len INTEGER,

    source_method TEXT NOT NULL,
    confidence REAL DEFAULT 0,
    status TEXT NOT NULL,

    created_at TEXT NOT NULL,
    updated_at TEXT,
    error_msg TEXT
);

CREATE INDEX IF NOT EXISTS idx_hook_candidates_target
ON hook_candidates(browser, version, platform, arch);

CREATE INDEX IF NOT EXISTS idx_hook_candidates_task
ON hook_candidates(task_id);

-- verification_runs: runtime verification results
CREATE TABLE IF NOT EXISTS verification_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    version_id INTEGER,
    task_id TEXT,

    browser TEXT,
    version TEXT,
    platform TEXT,
    arch TEXT,

    started_at TEXT,
    finished_at TEXT,
    status TEXT,

    keylog_capture_rate REAL,
    client_random_match_rate REAL,
    five_tuple_hit_rate REAL,
    wireshark_decrypt_rate REAL,

    total_baseline_lines INTEGER,
    total_captured_lines INTEGER,

    error_msg TEXT,
    report_path TEXT,
    created_at TEXT NOT NULL
);
