# TSHunter Agent Automation Layer

The agent layer provides automated browser version discovery, binary download, task orchestration, and batch analysis reporting. It runs on top of the existing TSHunter fingerprint database.

## Architecture

```
Data Sources          Task Orchestration       Analysis
  ChromeCfT  ─┐        agent_tasks           AnalyzeWorker
  EdgeDeb    ─┼─ poll → source_artifacts      (dry-run / real)
  Firefox    ─┘        state machine          VerifyWorker
                                                   │
                                              B1 Report
```

## Directory Structure

```
tshunter/agent/
  cli.py              # CLI entry point (tshunter agent ...)
  config.py           # YAML config loader (AgentConfig)
  logging.py          # Structured logging + StageTimer

  db/
    __init__.py       # connect() — SQLite connection helper
    task_store.py     # agent_tasks CRUD + state machine
    artifact_store.py # source_artifacts CRUD

  sources/
    base.py           # BrowserSource ABC + BrowserArtifact dataclass
    chrome_cft.py     # Chrome for Testing API poll + download
    edge.py           # Microsoft Edge deb repo scrape + download
    firefox.py        # Firefox product-details API poll + download

  downloader/
    http.py           # download_file() with retry + atomic rename
    checksum.py       # sha256_file()
    unpack.py         # zip/deb extraction + binary path resolution

  workers/
    download.py       # DownloadWorker — claims pending → downloads binary
    analyze.py        # AnalyzeWorker — dry-run skeleton (relocate/Ghidra)
    verify.py         # VerifyWorker — dry-run skeleton (keylog comparison)

  reports/
    b1_report.py      # B1 batch report generator (MD + 4 CSVs)
```

## CLI Commands

All commands use `tshunter agent <group> <command>`.

| Group | Command | Description |
|-------|---------|-------------|
| `db` | `migrate` | Apply agent DB migrations (007_agent_tables.sql) |
| `db` | `status` | Show table row counts and per-status breakdowns |
| `source` | `poll --browser {chrome,edge,firefox,all}` | Discover new versions from data sources |
| `source` | `download --browser <b> --version <v>` | Download a specific browser version |
| `task` | `list [--status <s>] [--browser <b>] [--limit <n>]` | List agent tasks |
| `task` | `show <task_id>` | Show task details |
| `task` | `retry <task_id>` | Reset failed task to pending |
| `task` | `reset <task_id> --status <s>` | Force transition to any status |
| `worker` | `download [--once]` | Run download worker |
| `worker` | `analyze [--dry-run] [--once]` | Run analyze worker |
| `worker` | `verify [--once]` | Run verify worker |
| `report` | `b1 [--db <path>] [--out <path>]` | Generate B1 batch report |

## State Machine

```
pending → downloading → downloaded → queued_analyze → analyzing → ingesting
                │                           │              │
                ↓                           ↓              ↓
             failed                    relocating    queued_verify
                │                                        │
                ↓                                        ↓
             (retry)                                  verifying
                                                          │
                                                          ↓
                                                       verified
```

Terminal states: `verified`, `failed`, `skipped`, `needs_manual_review`

## Configuration

`configs/agent.yaml` — all settings have sensible defaults. Key sections:

- `agent.*` — poll interval, download/binary/metadata dirs, retries, timeout
- `policy.*` — auto_analyze, auto_verify, auto_publish (all default off)
- `platform.*` — os, arch
- `sources.chrome_cft.*` — CfT API URLs, channels, platforms
- `sources.edge.*` — Microsoft deb repo URLs, channels
- `sources.firefox.*` — Mozilla product-details URL (planning_only: true)

## Quick Start

```bash
# Initialize agent tables
tshunter-agent db migrate

# Discover Chrome versions
tshunter-agent source poll --browser chrome

# Download a specific version
tshunter-agent source download --browser chrome --version 143.0.7499.169

# Run download worker (processes pending tasks)
tshunter-agent worker download --once

# Run analyze worker (dry-run)
tshunter-agent worker analyze --once --dry-run

# Generate B1 report
tshunter-agent report b1 --out reports/B1_report.md
```

## B1 Report

`reports/B1_report.md` summarizes batch analysis results with pass/fail thresholds:

| Metric | Threshold |
|--------|-----------|
| Ingestion success | >= 95% |
| 4-hook completeness | >= 95% |
| Analyze failure rate | <= 5% |
| Verification success | >= 95% |

Supporting CSV files: `hook_coverage.csv`, `failed_versions.csv`, `relocate_success.csv`, `verification_summary.csv`
