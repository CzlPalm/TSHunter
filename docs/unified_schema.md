# Unified Schema

This is the S2 schema contract for the unified TLSHunter database and runtime
profile model.

## Layer Model

TLSHunter uses three layers:

| Layer | Storage | Purpose |
|---|---|---|
| DB version layer | `versions`, `hook_points` | Version-specific RVA, fingerprint, binary identity, relocate lineage. |
| Runtime profile layer | `profiles/*.json` | Cross-version BoringSSL/NSS/OpenSSL/Rustls runtime templates. |
| Verification layer | `versions.verified`, `versions.note` | Human or regression verification status and metrics. |

`VersionConfigLoader` is the only merge point. Runtime capture should consume
the merged config, not raw JSON files, unless `TSHUNTER_ALLOW_JSON_FALLBACK=1`
is explicitly set.

## Core Tables

### `tls_stacks`

Defines TLS implementations. Seed values are `boringssl`, `openssl`, `nss`,
and `rustls`.

### `browsers`

Defines browser families and their default TLS stack. `(name)` is unique.

### `versions`

One browser build on one platform/arch.

Required identity fields:

- `browser_id`
- `version`
- `platform`
- `arch`

Important metadata:

- `tls_stack_id`: normalized TLS stack.
- `tls_lib_commit`: optional upstream commit, for example BoringSSL commit.
- `image_base`: Ghidra image base used when producing RVAs.
- `binary_sha256`, `binary_size`: exact binary identity.
- `verified`: `1` only after ground-truth or regression verification.
- `note`: free-form text or JSON. PARTIAL relocate stores
  `{"partial_relocate": true, "median_delta": "...", "max_outlier_delta": N}`.
- `profile_ref`: runtime profile id without `.json`, for example
  `boringssl_chrome`.

### `hook_points`

One hook kind per version. `kind` is one of `prf`, `key_expansion`, `hkdf`,
or `ssl_log_secret`.

Required runtime fields:

- `rva`
- `fingerprint`
- `fingerprint_len`
- `fingerprint_prefix20`

Relocate lineage:

- `derived_from_version_id`
- `rva_delta`
- `relocation_method`: `ghidra_full`, `exact_scan`,
  `exact_scan_partial`, `manual`, or `imported`.
- `relocation_confidence`

Runtime/template fields:

- `read_on`
- `output_len`
- `role`
- `params_json`
- `ghidra_name`
- `note`

### `analyzer_runs`

Records static-analysis attempts. `status` is `SUCCESS`, `FAILED_EMPTY`, or
`FAILED_GHIDRA`.

### `capture_sessions`

Stores captured key material with `pid`, `tid`, `five_tuple`, `key_type`,
`client_random`, and `secret`. This is the forensic join point between a DB
version row and observed network traffic.

### `batch_jobs`

Tracks B1 batch expansion. `method` is expected to be one of `db_hit`,
`relocate`, `relocate_partial`, `analyze`, or `dry_run`.

H6 metrics:

- `method_duration_sec`: wall-clock time spent resolving one version.
- `relocate_max_outlier_delta`: copied from PARTIAL relocate note when method
  is `relocate_partial`.

These columns support E1 plots for relocate success rate and time saved.

## Runtime Profiles

`profiles/boringssl_chrome.json` currently provides the Chrome-family
BoringSSL template:

- `client_random`
- `tls13_key_len_offsets`
- `tls13_label_map`
- `struct_offsets`
- `five_tuple_strategy`
- `hook_templates`

Profile values are stable defaults. Version-specific RVA and fingerprint values
must come from DB `hook_points`.

## Migration Summary

- `001_relocate_fields`: adds relocate lineage to `hook_points`.
- `002_analyzer_runs_status`: tracks empty/failed analyzer outputs.
- `003_three_layer`: adds `versions.profile_ref` and hook template fields.
- `004_batch_jobs`: adds B1 batch state tracking.
- `005_partial_relocate`: formalizes `exact_scan_partial`.
- `006_batch_metrics`: adds B1/E1 per-version metrics.
