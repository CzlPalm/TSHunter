-- Phase 4A: add relocation lineage fields to hook_points

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES ('001_relocate_fields', datetime('now'));

ALTER TABLE hook_points ADD COLUMN derived_from_version_id INTEGER REFERENCES versions(id);
ALTER TABLE hook_points ADD COLUMN rva_delta INTEGER DEFAULT NULL;
ALTER TABLE hook_points ADD COLUMN relocation_method TEXT DEFAULT 'ghidra_full'
    CHECK(relocation_method IN ('ghidra_full','exact_scan','manual','imported'));
ALTER TABLE hook_points ADD COLUMN relocation_confidence REAL DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_hook_derived_from ON hook_points(derived_from_version_id);

