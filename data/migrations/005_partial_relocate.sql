-- H2: allow PARTIAL relocate rows to be stored separately from strict OK relocates.
-- SQLite cannot alter CHECK constraints in-place. New databases get the widened
-- constraint from data/schema.sql; existing DBs are marked migrated here and are
-- expected to have been created by the current schema or rebuilt before B1.

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES ('005_partial_relocate', datetime('now'));
