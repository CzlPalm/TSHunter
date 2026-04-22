PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS tls_stacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS browsers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    vendor TEXT,
    default_tls_stack_id INTEGER,
    FOREIGN KEY (default_tls_stack_id) REFERENCES tls_stacks(id)
);

CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    browser_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    tls_stack_id INTEGER,
    tls_lib_commit TEXT,
    image_base TEXT,
    binary_sha256 TEXT,
    binary_size INTEGER,
    analysis_date TEXT,
    analyzer_version TEXT,
    verified INTEGER DEFAULT 0,
    note TEXT,
    UNIQUE(browser_id, version, platform, arch),
    FOREIGN KEY (browser_id) REFERENCES browsers(id) ON DELETE CASCADE,
    FOREIGN KEY (tls_stack_id) REFERENCES tls_stacks(id)
);

CREATE TABLE IF NOT EXISTS hook_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('prf','key_expansion','hkdf','ssl_log_secret')),
    function_name TEXT,
    rva TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    fingerprint_len INTEGER NOT NULL,
    fingerprint_prefix20 TEXT NOT NULL,
    role TEXT,
    params_json TEXT,
    source TEXT,
    verified INTEGER DEFAULT 0,
    UNIQUE(version_id, kind),
    FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hook_fp_prefix ON hook_points(fingerprint_prefix20);
CREATE INDEX IF NOT EXISTS idx_hook_kind ON hook_points(kind);
CREATE INDEX IF NOT EXISTS idx_versions_browser ON versions(browser_id, version);

CREATE TABLE IF NOT EXISTS analyzer_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds INTEGER,
    analyzer_version TEXT,
    exit_code INTEGER,
    log_path TEXT,
    json_path TEXT,
    FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS capture_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER,
    captured_at TEXT NOT NULL,
    pid INTEGER,
    tid INTEGER,
    five_tuple TEXT,
    key_type TEXT,
    client_random TEXT,
    secret TEXT,
    FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE SET NULL
);

INSERT OR IGNORE INTO tls_stacks(name, description) VALUES
    ('boringssl', 'Google BoringSSL (Chrome, Edge, Electron)'),
    ('openssl',   'OpenSSL 1.1.x / 3.x'),
    ('nss',       'Mozilla NSS (Firefox, Thunderbird)'),
    ('rustls',    'Rust TLS implementation');

INSERT OR IGNORE INTO browsers(name, vendor, default_tls_stack_id) VALUES
    ('chrome',   'Google',    (SELECT id FROM tls_stacks WHERE name='boringssl')),
    ('edge',     'Microsoft', (SELECT id FROM tls_stacks WHERE name='boringssl')),
    ('firefox',  'Mozilla',   (SELECT id FROM tls_stacks WHERE name='nss')),
    ('electron', 'Various',   (SELECT id FROM tls_stacks WHERE name='boringssl'));


