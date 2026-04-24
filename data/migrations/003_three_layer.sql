-- U2: 三层架构 schema 扩展
-- 版本指向运行时 profile；hook_points 补上 Frida 注入所需的语义字段。

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES ('003_three_layer', datetime('now'));

ALTER TABLE versions ADD COLUMN profile_ref TEXT DEFAULT NULL;

ALTER TABLE hook_points ADD COLUMN read_on TEXT DEFAULT 'onLeave';
ALTER TABLE hook_points ADD COLUMN output_len INTEGER DEFAULT NULL;
ALTER TABLE hook_points ADD COLUMN ghidra_name TEXT DEFAULT NULL;
ALTER TABLE hook_points ADD COLUMN note TEXT DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_versions_profile_ref ON versions(profile_ref);
