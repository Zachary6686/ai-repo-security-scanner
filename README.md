# AI Repo Security Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/your-org/ai-repo-security-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/your-org/ai-repo-security-scanner/actions/workflows/tests.yml)

> **Note:** Replace `your-org` and the repo name in the Tests badge URL with your GitHub org/repo to show CI status.

A **static application security testing (SAST)** tool for scanning local source-code repositories. It combines AST-based detection, regex rules, taint analysis, and repository hygiene checks to produce explainable risk scores and professional reports. Designed as a portfolio-grade security scanner with clear documentation and deterministic, auditable results.

---

## Table of Contents

- [Motivation and Goals](#motivation-and-goals)
- [Key Features](#key-features)
- [Detection Capabilities](#detection-capabilities)
- [Risk Scoring System](#risk-scoring-system)
- [Report Formats](#report-formats)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Architecture](#architecture)
- [Benchmark and Test Cases](#benchmark-and-test-cases)
- [Limitations](#limitations)
- [Future Work](#future-work)

---

## Motivation and Goals

- **Explainable security analysis**: No black-box ML; every finding and risk score can be traced to rules and weights.
- **Portfolio and education**: Small, readable codebase suitable for graduation projects and security-tool demos.
- **Multi-method detection**: Combine AST, regex, taint flow, and repository hygiene for broader coverage.
- **Production-friendly outputs**: Markdown, HTML dashboard, JSON, and SARIF for integration with CI and issue trackers.

---

## Key Features

- **AST-based vulnerability checks** for Python (dangerous calls, deserialization, code execution).
- **Regex-based detection** for secrets, weak crypto, and insecure configuration across file types.
- **Intra-procedural taint analysis** (sources → sinks) for command injection, SQL injection, and path traversal.
- **Repository hygiene scanning**: sensitive files, `.gitignore` gaps, and secret exposure in tracked files.
- **Deterministic risk scoring** with severity/confidence weighting, taint bonuses, and critical-category emphasis.
- **Rich reports**: Markdown, HTML dashboard, JSON, and SARIF 2.1.0.
- **Rule metadata system**: CWE/OWASP, remediation, and detection type driven by YAML config.

---

## Detection Capabilities

| Method | Description |
|--------|-------------|
| **AST analysis** | Detects dangerous Python constructs: `eval()`, `exec()`, `os.system()`, `subprocess` with `shell=True`, `pickle.loads()`, unsafe `yaml.load()`. |
| **Regex rules** | Patterns for hardcoded secrets, API keys, weak crypto (MD5/SHA1, insecure random), TLS/SSL misconfig (`verify=False`), debug mode. |
| **Taint analysis** | Tracks user-controlled data (e.g. `input()`, `request.args`) to dangerous sinks (shell execution, SQL execution, file paths). Surfaces command injection, SQL injection, and path traversal. |
| **Repository hygiene** | Scans for tracked sensitive files (`.env`, keys, `.pyc`), missing `.gitignore` patterns, and secret patterns in file content. Remediation explains why `.gitignore` alone does not untrack or remove files already in the index or history. |

---

## Severity Model

The project uses a **single canonical severity model** (see `core/severity.py`): **CRITICAL**, **HIGH**, **MEDIUM**, **LOW**. All detection, risk scoring, and reports use these four levels. Unknown or missing severity values are normalized to LOW. Severity weights used for scoring and sort order are defined in one place for consistency.

## Risk Scoring System

The repository risk score is **deterministic and explainable** (no machine learning):

- **Severity × confidence**: Each finding contributes `severity_weight × confidence_weight` (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1; confidence HIGH=1.0, MEDIUM=0.8, LOW=0.6).
- **Taint-flow bonus**: Extra weight per taint finding.
- **Secret exposure bonus**: Extra weight for findings in Secret Exposure / Secrets / Sensitive Artifacts.
- **Repository hygiene**: Hygiene findings contribute to the score and are reported in the breakdown.
- **File concentration**: Higher when many findings are in few files.
- **Critical categories**: Additional weight for Command Injection, SQL Injection, Secret Exposure, Unsafe Deserialization.

**Risk levels** (by numeric score):

- **0–20** → Low  
- **21–50** → Moderate  
- **51–100** → High  
- **>100** → Critical  

Reports include a **score breakdown** (severity contribution, taint bonus, hygiene, concentration, etc.) and **top risky files** and **top risky rule categories**.

---

## Report Formats

| Format | Description |
|--------|-------------|
| **Markdown** | Human-readable audit report with severity breakdown, top files, risk explanation, and findings. |
| **HTML** | Standalone dashboard: risk summary cards, severity/category distribution, top risky files and categories, risk explanation panel, searchable findings table. |
| **JSON** | Structured export with `scan_summary` (risk score, level, breakdown), `top_risky_files`, `top_risky_categories`, and `findings`. |
| **SARIF 2.1.0** | For CI and code-scanning integrations; includes run-level properties (risk score, risk level, breakdown). |

---

## Installation

**Requirements:** Python 3.8+

1. Clone the repository and enter the project directory:

   ```bash
   git clone https://github.com/your-org/ai-repo-security-scanner.git
   cd ai-repo-security-scanner
   ```

2. (Recommended) Create a virtual environment:

   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

Optional: `openai` is listed for optional AI review; the scanner runs without it and does not require an API key.

---

## Usage

**Basic scan** (target directory, reports to `output/`):

```bash
python scanner.py <target_directory>
```

**Example: scan the included samples and generate all reports:**

```bash
python scanner.py samples
```

**Example: scan the benchmark suite and write to a specific folder:**

```bash
python scanner.py benchmark --output-dir reports --format all
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Path to repository or source folder | (required) |
| `--workers` | Number of concurrent scan workers | 8 |
| `--top-files` | Number of top risky files to include | 5 |
| `--format` | Output format(s): `md`, `html`, `json`, `sarif`, `all` | `all` |
| `--output-dir` | Directory for report files | `output` |

Generated files:

- `output/security_report.md`
- `output/security_report.html`
- `output/security_report.json`
- `output/security_report.sarif`

**Pre-commit secret scanner** (optional): run `python tools/check_secrets.py` from the repo root. Use `--include-test-fixtures` to also scan `tests/`, `benchmark/`, and `samples/`.

---

## Example Output

**Console summary:**

```
Scan Summary
----------------------------
Files scanned: 1
Total findings: 9

Severity counts:
  CRITICAL: 0
  HIGH: 8
  MEDIUM: 1
  LOW: 0

Repository risk score: 91 — Risk level: High

Top risky files:
1. samples\vulnerable_sample.py (score 68, 7 findings)
2. .gitignore (score 6, 1 findings)
...
```

**JSON excerpt (risk and breakdown):**

```json
"scan_summary": {
  "repository_risk_score": 91,
  "risk_level": "High",
  "score_breakdown": {
    "severity_contribution": 48.6,
    "taint_flow_contribution": 10.0,
    "secret_exposure_contribution": 0.0,
    "repository_hygiene_contribution": 9.0,
    "file_concentration_factor": 11.67,
    "unique_files_factor": 3.0,
    "critical_category_contribution": 18.0
  }
}
```

The **HTML dashboard** shows risk summary cards, severity/category distribution, top risky files and categories, a risk score explanation panel, and a searchable findings table.

---

## Architecture

High-level layout:

| Directory | Purpose |
|-----------|---------|
| **`core/`** | Analysis and risk logic: AST + regex + taint in `analyzer.py` and `taint_analysis.py`, repository hygiene in `repo_hygiene.py`, risk scoring and breakdown in `risk.py`, rule metadata loading and enrichment in `rule_registry.py`. |
| **`rules/`** | Regex rule definitions (e.g. secrets, crypto, config) and **`rules/metadata/`** (YAML) for rule metadata (title, severity, category, CWE, OWASP, remediation, detection_type). |
| **`reports/`** | Report generators: Markdown, HTML, JSON, SARIF; consume enriched findings and risk summary. |
| **`io_utils/`** | File and repository utilities: collecting source files, loading content, path handling. |
| **`tools/`** | Standalone utilities; e.g. **`tools/check_secrets.py`** — pre-commit secret scanner (excludes tests/benchmark/samples by default). |

- **`scanner.py`** — CLI entry point: parses args, runs SAST and hygiene, enriches findings, builds risk summary, prints summary, writes reports.

---

## Benchmark and Test Cases

The **`benchmark/`** directory contains small example files to demonstrate scanner behavior:

| Category | Vulnerable example | Safe example |
|----------|---------------------|--------------|
| Command injection | `command_injection_vulnerable.py` | `command_injection_safe.py` |
| SQL injection | `sql_injection_vulnerable.py` | `sql_injection_safe.py` |
| Path traversal | `path_traversal_vulnerable.py` | `path_traversal_safe.py` |
| Unsafe deserialization | `deserialization_vulnerable.py` | `deserialization_safe.py` |
| Weak crypto | `weak_crypto_vulnerable.py` | `weak_crypto_safe.py` |
| Secret exposure | `secret_exposure_vulnerable.py` | `secret_exposure_safe.py` |

**Run the benchmark:**

```bash
python scanner.py benchmark --output-dir output --format all
```

Then open `output/security_report.html` to inspect findings and risk. The **`samples/`** directory also contains a single file with multiple vulnerability types for quick demos.

---

## Limitations

- **Prototype scope**: Taint analysis is intra-procedural; no full inter-procedural or cross-file data flow.
- **Regex and AST**: Rule-based only; false positives and false negatives are possible (e.g. benign string patterns, obfuscated code).
- **Coverage**: AST and taint focus on a defined set of sources/sinks; not a replacement for a full security audit or commercial SAST.
- **Results**: Output is advisory; always validate findings and apply fix decisions in context.

---

## Future Work

- Expand taint sources/sinks and add more AST rules (e.g. subprocess argument validation, YAML loader checks).
- Inter-procedural or cross-file taint for higher accuracy.
- Baseline/snapshot tests and regression tests for rule changes.
- SARIF path normalization and optional GitHub Code Scanning SARIF upload in CI.
- Optional AI-assisted triage or remediation suggestions (already stubbed where applicable).

---

## Running Tests

```bash
pip install pytest   # if not already installed
pytest tests/ -v
```

To run only risk-model tests:

```bash
pytest tests/test_risk.py -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
