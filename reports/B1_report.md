# TLSHunter B1 Batch Report

Generated: 2026-05-02 12:08:43 UTC

## Summary

| Metric | Value | Threshold | Status |
|---|---|---|---|
| Total versions | 2 | — | — |
| Source artifacts | 2675 | — | — |
| Ingestion success | 0.1% | >= 95% | FAIL |
| 4-hook completeness | 100.0% | >= 95% | PASS |
| Analyze failure rate | 0.0% | <= 5% | PASS |
| **Overall** | | | **FAIL** |

## Hook Coverage

| Browser | Version | Hooks | Kinds |
|---|---|---|---|
| chrome | 143.0.7499.169 | 4 | hkdf,key_expansion,prf,ssl_log_secret |
| chrome | 143.0.7499.4 | 4 | hkdf,key_expansion,prf,ssl_log_secret |

## Failed Versions

No failed tasks.

## Relocate Statistics

| Method | Count | Percentage |
|---|---|---|
| ghidra_full | 4 | 50.0% |
| exact_scan_partial | 4 | 50.0% |

## Analyzer Run Statistics

| Status | Count | Percentage |
|---|---|---|
| SUCCESS | 2 | 100.0% |

## Verification Summary

No verification runs found.

## Needs Manual Review

| Browser | Version | Error Stage | Error |
|---|---|---|---|
| chrome | 113.0.5672.0 | — | — |
