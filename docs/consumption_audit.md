# Runtime Consumption Audit

This document fixes the S1 contract between the fingerprint database, runtime
profiles, and Frida/eBPF capture path. It is intentionally limited to fields
that are consumed by current code.

## Runtime Entry Points

- `tshunter/capture.py` patches legacy `lib.version_detect.load_config()` so
  runtime config is loaded by `VersionConfigLoader`.
- `tshunter/config_loader.py` merges three layers:
  DB `versions` + `hook_points`, JSON profile under `profiles/`, and verified
  metadata stored in `versions.note`.
- `frida_scripts/chrome_hooks.js` consumes the merged config as `CFG`.
- `tshunter/correlator.py` consumes eBPF connect events and correlates emitted
  keylog lines with destination IP/port.

## MUST Fields

These fields are required for Chrome/BoringSSL capture to work.

| Field | Consumer | Reason |
|---|---|---|
| `meta.version` | `chrome_hooks.js` debug output | Identifies loaded version in runtime logs. |
| `hook_points.prf.rva` | `chrome_hooks.js` | Installs TLS 1.2 PRF hook. |
| `hook_points.key_expansion.rva` | `chrome_hooks.js` | Installs TLS 1.2 supplemental master-secret hook. |
| `hook_points.hkdf.rva` | `chrome_hooks.js` | Installs TLS 1.3 derive-secret hook. |
| `hook_points.ssl_log_secret.rva` | `chrome_hooks.js` | Installs BoringSSL keylog hook for PSK/session-ticket coverage. |
| `tls13_label_map` | `chrome_hooks.js` | Maps BoringSSL internal labels to NSS keylog labels. |
| `tls13_key_len_offsets` | `chrome_hooks.js` | Determines TLS 1.3 secret lengths per label. |
| `struct_offsets.ssl_st_rbio` | `chrome_hooks.js` | Reads `ssl->rbio` for fd correlation when available. |
| `struct_offsets.bio_st_num` | `chrome_hooks.js` | Reads BIO fd value. |

## SHOULD Fields

These fields are not always required to install hooks, but they preserve
traceability and reduce runtime ambiguity.

| Field | Consumer | Reason |
|---|---|---|
| `meta.browser`, `meta.platform`, `meta.arch` | loader/query/debug | Disambiguates DB rows and capture target. |
| `meta.tls_lib`, `meta.profile_ref` | `VersionConfigLoader` | Selects stable runtime profile. |
| `meta.verified`, `meta.verified_method`, `meta.verified_metrics` | operator/review | Separates verified baselines from relocated candidates. |
| `hook_points.*.fingerprint` | relocate/forensics | Enables exact-byte relocate and later audit. |
| `hook_points.*.fingerprint_len` | relocate/forensics | Preserves scan window semantics. |
| `hook_points.*.relocation_method` | batch/capture policy | Distinguishes `ghidra_full`, `exact_scan`, and `exact_scan_partial`. |
| `hook_points.*.relocation_confidence` | batch review | Supports PARTIAL candidate triage. |
| `hook_points.*.derived_from_version_id` | batch review | Links relocated hooks to the verified baseline. |
| `hook_points.*.rva_delta` | B1/E1 metrics | Measures small-version drift. |
| `five_tuple_strategy` | operator/docs | Documents whether fd or time correlation is expected. |

## NICE Fields

These are descriptive or forward-compatible today.

| Field | Consumer | Reason |
|---|---|---|
| `client_random.path`, `client_random.steps` | docs/operator | Runtime currently hardcodes `readCR()`/`readCRSslLog()` paths. |
| `hook_points.*.role` | query/docs | Human-readable semantics. |
| `hook_points.*.params` | query/docs | Documents ABI assumptions used by Frida hooks. |
| `hook_points.*.read_on`, `hook_points.*.output_len` | loader/profile | Preserves hook template semantics for future generators. |
| `versions.binary_sha256`, `versions.binary_size` | forensics/dedup | Links DB rows to exact binaries. |

## UNUSED In Runtime

These fields are stored for provenance or analysis but are not read by the
current Frida script.

- `hook_points.*.function_name`
- `hook_points.*.ghidra_name`
- `hook_points.*.source`
- `versions.tls_lib_commit`
- `versions.image_base`
- `versions.analysis_date`
- `versions.analyzer_version`

They should stay in the schema because analysis, relocate, query output, and
paper metrics rely on them.
