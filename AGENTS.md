<claude-mem-context>
# Memory Context

# [TLSHunter] recent context, 2026-05-02 1:43pm GMT+8

Legend: 🎯session 🔴bugfix 🟣feature 🔄refactor ✅change 🔵discovery ⚖️decision 🚨security_alert 🔐security_note
Format: ID TIME TYPE TITLE
Fetch details: get_observations([IDs]) | Search: mem-search skill

Stats: 28 obs (11,717t read) | 1,691,003t work | 99% savings

### Apr 28, 2026
1 10:51a 🔵 TLSHunter Project README Current State (Pre-Update)
2 10:52a 🔵 TLSHunter Unified CLI Architecture and Forwarding Rule Pattern
3 " 🔵 relocate.py and batch.py Actual CLI Interfaces
4 10:53a 🔵 TLSHunter Test Infrastructure: Relocate Unit Tests and Batch State Machine Tests
5 " 🔵 Exact CLI Signatures for relocate scan/probe and batch Commands
6 10:54a 🔵 verified Flag Can Only Be Set via JSON Metadata or Direct SQL — No CLI Command
7 " ⚖️ Relocate Test Target: Use 143.0.7499.169 as Source to Relocate 143.0.7499.192
8 11:03a 🔵 ingest --from-relocate Flag Enables Direct Ingestion of Relocate JSON Output
9 " 🔵 DB State Confirmed Ready for Relocate Test: 143.0.7499.169 verified=1 with 4 Hook Points
10 11:04a 🔵 ingest_relocate_payload Requires --browser/--version/--platform/--arch CLI Args for Target Version Metadata
11 11:05a 🔵 Relocate Results for 143.0.7499.192 Already Exist in results/ Directory
12 " 🔵 Prior Relocate Run of 143.0.7499.192 Produced PARTIAL Verdict Due to Inconsistent Deltas
13 11:06a 🔵 Batch run_batch Logic: Three-Step Resolution with binaries-dir Structure Requirements
14 11:07a ✅ README.md Rewritten with Accurate CLI Usage, Relocate Test Procedure, and Batch Test Guide
15 11:18a 🔵 tshunter CLI Not Available in System PATH — Requires venv Activation
16 5:07p 🔵 fritap-env Virtual Environment Required for P7 Plan Execution
17 " 🔵 TLSHunter Project Structure and CLI Architecture
18 5:08p 🔵 Plan File Has Typo in Filename: paln-3.md Instead of plan-3.md
19 5:11p 🔵 TLSHunter P7 Plan-3: H1 Downloader Extension is the Current Implementation Target
20 " 🔵 TLSHunter Project Phase Status: F1/F2 Complete, H1/H2 Next
21 " 🔵 downloader.py Current Implementation: Single Source, Per-Milestone Latest Only
22 " 🔵 batch.py Already Has Milestone Range Parsing and _download_milestones Integration
23 5:12p 🟣 H1: downloader.py Extended with cft-all Full Historical Source
24 5:15p 🟣 H1: downloader.py main() Wired for cft-all Branch with _download_record_list
25 5:16p 🟣 H1 Task 1 Complete: downloader.py cft-all Support Fully Implemented
26 5:17p 🟣 H1 Task 2 Complete: batch.py Gains --versions-file Parameter
27 5:18p 🟣 H1 Task 3: chrome_versions.txt Created at Project Root
28 5:19p ✅ H1 Task 4: README.md Updated with Download Subcommand Documentation (Section 8)

Access 1691k tokens of past work via get_observations([IDs]) or mem-search skill.
</claude-mem-context>

## Agent skills

### Issue tracker

GitHub Issues on CzlPalm/TSHunter (uses `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical roles with default label names. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout. See `docs/agents/domain.md`.