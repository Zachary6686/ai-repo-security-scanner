# AI Repo Security Scanner

A lightweight **static application security testing (SAST) prototype** for scanning local source-code repositories.

It combines:
- **AST-based detection** (high-signal checks for dangerous Python calls)
- **Regex rules** (secrets/config/crypto patterns across multiple file types)
- **Repository risk scoring** (0–100) and **top risky file ranking**
- **Portfolio-friendly reports**: Markdown, HTML dashboard, JSON, and SARIF

This is intentionally **student-friendly**: small codebase, explainable logic, and easy local execution.

## Quick start

```bash
py scanner.py samples
```

To control output location and formats:

```bash
py scanner.py <target_directory> --output-dir output --format all
```

Generated files:
- `output/security_report.md`
- `output/security_report.html`
- `output/security_report.json`
- `output/security_report.sarif`

## Features

- **AST-based vulnerability checks (Python)**:
  - `eval`, `exec`
  - `os.system`
  - `subprocess.*(..., shell=True)`
  - `pickle.load(s)` (unsafe deserialization)
  - `yaml.load` (unsafe loader)
- **Regex-based detection (multi-language)**:
  - secrets (passwords/tokens/private keys)
  - insecure config (`debug=True`, `verify=False`, legacy TLS)
  - crypto smells (`hashlib.md5`, `hashlib.sha1`, insecure randomness heuristic)
- **Risk scoring**:
  - file-level scoring + repo-level normalization to **0–100**
  - boosts for many HIGH findings and for very risky files
- **Reports**:
  - **Markdown**: readable audit-style report
  - **HTML**: interactive dashboard with search/filter
  - **JSON**: structured export for automation
  - **SARIF 2.1.0**: works well for demos and code-scanning integrations
- **Concurrency**: scans files using a thread pool (`--workers`)

## Architecture (high-level)

The repo is organized like a real lightweight security tool:

- `scanner.py`: CLI entrypoint (kept simple; orchestrates scanning + reporting)
- `core/`:
  - `analyzer.py`: AST + regex scanning, snippet extraction, deduplication, sorting
  - `risk.py`: repository risk score and top risky file ranking
  - `rules_engine.py`: aggregates rules from `rules/` (no plugin framework)
  - `models.py`: small dataclasses (`Finding`, `ScanError`, `RepoScanSummary`)
  - `ai_review.py`: optional AI analysis (safe if key/package missing)
- `rules/`: regex rule definitions grouped by category
- `io_utils/`: repo and file loading utilities
- `reports/`: Markdown/HTML/JSON/SARIF generators
- `samples/`: intentionally vulnerable code for demos
- `tests/`: smoke tests to keep behavior stable

## Example output (what a finding contains)

Findings are dicts for report compatibility, but map cleanly to `core.models.Finding`:
- `rule_id`, `title`, `severity`, `confidence`, `category`
- `file_path`, `line_number`
- `code_snippet` (with context)
- `description`, `recommendation`

## Risk scoring (explainable)

The risk score is designed to be simple and explainable (not “ML magic”):
- Each finding contributes by severity weight × confidence multiplier
- Additional boosts for multiple HIGH findings and for very risky files
- Repository score is capped to **100**

## Limitations (honest)

- This is a prototype: it does not perform data-flow analysis or taint tracking.
- Regex rules can produce false positives/negatives.
- AST checks focus on a small set of high-signal dangerous patterns.
- Results are not a substitute for a full security review.

## Future work (reasonable next steps)

- Add a few more AST rules (e.g., `subprocess` argument validation hints, `yaml.load` loader checks)
- Add rule tests and baseline snapshots
- Add path normalization in SARIF for better integration with CI tools
- Add rule documentation pages and a simple “rule registry” table in README

## Installation

Optional (recommended): create a virtual environment, then:

```bash
pip install -r requirements.txt
```

AI review is optional:
- If `OPENAI_API_KEY` is missing, the scanner does **not** crash.
- If `openai` is not installed, the scanner does **not** crash.


