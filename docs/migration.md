# Migration Notes

This document records the U0 path from the earlier split repositories into the
current unified layout.

## Source Systems

- TSHunter provided Ghidra static analysis, JSON analysis output, ingest, and
  an SQLite fingerprint database.
- p_t_c provided Frida TLS key capture, eBPF/fd correlation, and the earlier
  exact-byte fingerprint scan idea.

The unified repository keeps SQLite as the single source of truth and makes
runtime capture load DB-backed configs through `VersionConfigLoader`.

## Current Layout

- `tshunter/analyze.py`: runs static analysis and produces hook JSON.
- `tshunter/ingest.py`: imports analyzer or relocate results into SQLite.
- `tshunter/relocate.py`: scans a target binary using baseline fingerprints.
- `tshunter/config_loader.py`: merges DB, profile, and verification layers.
- `tshunter/capture.py`: patches the legacy capture loader and delegates to the
  Frida runtime.
- `tshunter/batch.py`: B1 orchestration for DB hit, relocate, and full analyze.
- `tshunter/downloader.py`: Chrome for Testing binary acquisition.
- `profiles/`: cross-version runtime templates.
- `data/schema.sql` and `data/migrations/`: database contract.

## Important Compatibility Decisions

- Unified CLI keeps forwarding subcommands under `tshunter`, while preserving
  legacy scripts behind the command boundary.
- `capture` is strict by default. It does not consume PARTIAL relocate rows as
  verified baselines.
- `batch` may ingest PARTIAL relocate candidates as `exact_scan_partial`, with
  `versions.verified=0`, so B1 can continue without losing auditability.
- Full analyzer output and relocate output both flow through `ingest.py`; this
  keeps schema upgrades and provenance handling centralized.

## B1 Expansion Path

1. Download Chrome for Testing versions with `download --source cft-all`.
2. Process versions with `batch`.
3. Reuse exact DB hits where available.
4. Try same-major-minor relocate from verified baselines.
5. Store acceptable PARTIAL candidates as unverified.
6. Fall back to full Ghidra analysis when no safe baseline exists.
7. Record `batch_jobs.method`, `method_duration_sec`, and
   `relocate_max_outlier_delta` for E1 analysis.
