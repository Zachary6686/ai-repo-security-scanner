"""
AI Repo Security Scanner — CLI entry point.

Scans a target directory for code vulnerabilities (SAST) and repository
hygiene issues (sensitive artifacts, .gitignore gaps). Produces reports
in Markdown, HTML, JSON, and SARIF.
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.analyzer import analyze_file
from core.repo_hygiene import check_gitignore_hygiene, scan_repository_hygiene
from core.risk import (
    build_risk_summary,
    calculate_repository_risk_score,
    get_risk_level,
    get_top_risky_files,
    summarize_severity_counts,
)
from core.severity import SEVERITY_LEVELS
from core.rule_registry import enrich_findings
from io_utils.repo_loader import get_source_files
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.markdown_report import generate_markdown_report
from reports.sarif_report import generate_sarif_report


# =========================
# CLI
# =========================


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Namespace with target, workers, format, output_dir, and top_files.
    """
    parser = argparse.ArgumentParser(
        description="AI Repo Security Scanner - rule-based repository security scanner"
    )

    parser.add_argument(
        "target",
        help="Path to repository or source folder"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of concurrent scanning workers (default: 8)"
    )

    parser.add_argument(
        "--top-files",
        type=int,
        default=5,
        help="Number of top risky files to show"
    )

    parser.add_argument(
        "--format",
        nargs="+",
        choices=["md", "html", "json", "sarif", "all"],
        default=["all"],
        help="Output report format"
    )

    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory for report output (default: output)"
    )

    return parser.parse_args()


# =========================
# Scan logic
# =========================

def scan_file_safe(file_path: str) -> Dict[str, Any]:
    """
    Run SAST on a single file without raising.

    Returns:
        Dict with keys: 'file' (str), 'findings' (list), 'error' (str or None).
    """
    try:
        findings = analyze_file(file_path)
        return {"file": file_path, "findings": findings, "error": None}
    except Exception as e:
        return {"file": file_path, "findings": [], "error": str(e)}


def scan_repository(
    files: List[str], workers: int = 8
) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    """
    Run SAST on a list of source files in parallel.

    Returns:
        Tuple of (list of finding dicts, list of error dicts with 'file' and 'error').
    """
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_file_safe, f): f for f in files
        }

        for future in as_completed(futures):
            result = future.result()

            if result["error"]:
                errors.append({
                    "file": result["file"],
                    "error": result["error"]
                })

            results.extend(result["findings"])

    return results, errors


def run_hygiene_checks(target_path: str) -> List[Dict[str, Any]]:
    """
    Run repository hygiene and .gitignore checks.

    Scans for sensitive files, secrets in content, and .gitignore gaps.

    Returns:
        List of finding dicts (Repository Hygiene, Sensitive Artifacts, Secret Exposure).
    """
    hygiene_findings: List[Dict[str, Any]] = []
    hygiene_findings.extend(scan_repository_hygiene(target_path))
    hygiene_findings.extend(check_gitignore_hygiene(target_path))
    return hygiene_findings


# =========================
# Terminal output
# =========================


def print_summary(
    files_scanned: int,
    findings: List[Dict[str, Any]],
    top_files_count: int,
) -> None:
    """Print scan summary to stdout: file count, finding count, severity breakdown, risk score, risk level, top risky files."""
    severity_counts = summarize_severity_counts(findings)
    repo_score = calculate_repository_risk_score(findings)
    risk_level = get_risk_level(repo_score)
    top_files = get_top_risky_files(findings, top_files_count)

    print("\nScan Summary")
    print("----------------------------")
    print(f"Files scanned: {files_scanned}")
    print(f"Total findings: {len(findings)}")
    print()

    print("Severity counts:")
    for sev in SEVERITY_LEVELS:
        print(f"  {sev}: {severity_counts.get(sev, 0)}")

    print()
    print(f"Repository risk score: {repo_score} — Risk level: {risk_level}")
    print()

    print("Top risky files:")
    for idx, item in enumerate(top_files, start=1):
        print(
            f"{idx}. {item['file_path']} "
            f"(score {item['risk_score']}, "
            f"{item['findings_count']} findings)"
        )

    print()


# =========================
# Report assembly and output
# =========================


def build_report_data(
    target: Path,
    files: List[str],
    findings: List[Dict[str, Any]],
    errors: List[Dict[str, str]],
    top_files_n: int = 5,
    top_categories_n: int = 10,
) -> Dict[str, Any]:
    """
    Build the report payload from scan results and risk summary.

    Used by main() before passing to report generators.
    """
    risk_summary = build_risk_summary(
        findings,
        top_files_n=top_files_n,
        top_categories_n=top_categories_n,
    )
    return {
        "target": str(target),
        "files_scanned": len(files),
        "total_findings": len(findings),
        "severity_counts": risk_summary["severity_counts"],
        "repository_risk_score": risk_summary["repository_risk_score"],
        "risk_level": risk_summary["risk_level"],
        "risk_level_css_class": risk_summary["risk_level_css_class"],
        "score_breakdown": risk_summary["score_breakdown"],
        "top_risky_files": risk_summary["top_risky_files"],
        "top_risky_categories": risk_summary["top_risky_categories"],
        "findings": findings,
        "scan_errors": errors,
    }


def write_reports(
    report_data: Dict[str, Any],
    output_dir: Path,
    formats: List[str],
) -> None:
    """Write requested report formats to output_dir; print each path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    if "all" in formats:
        formats = ["md", "html", "json", "sarif"]

    if "md" in formats:
        p = output_dir / "security_report.md"
        generate_markdown_report(report_data, p)
        print("Markdown report saved to", p)
    if "html" in formats:
        p = output_dir / "security_report.html"
        generate_html_report(report_data, p)
        print("HTML report saved to", p)
    if "json" in formats:
        p = output_dir / "security_report.json"
        generate_json_report(report_data, p)
        print("JSON report saved to", p)
    if "sarif" in formats:
        p = output_dir / "security_report.sarif"
        generate_sarif_report(report_data, p)
        print("SARIF report saved to", p)


# =========================
# Main
# =========================


def main() -> None:
    """
    Entry point: parse args, scan target, print summary, write reports.

    Exits with 1 if target does not exist or file collection fails; 0 otherwise.
    """
    args = parse_args()
    target = Path(args.target)

    if not target.exists():
        print(f"Target path does not exist: {target}")
        sys.exit(1)

    print("[1/5] Using local directory:", target)
    print("[2/5] Collecting source files")
    try:
        files = get_source_files(str(target))
    except Exception as e:
        print("Failed to collect files:", e)
        sys.exit(1)

    if not files:
        print("No source files found.")
        sys.exit(0)

    print(f"Found {len(files)} files to scan.")
    print("[3/5] Scanning repository (SAST)")
    findings, errors = scan_repository(files, workers=args.workers)
    print("[4/5] Checking repository hygiene")
    findings = findings + run_hygiene_checks(str(target))
    findings = enrich_findings(findings)

    print_summary(len(files), findings, args.top_files)

    print("[5/5] Saving reports")
    report_data = build_report_data(
        target, files, findings, errors,
        top_files_n=args.top_files,
        top_categories_n=10,
    )
    write_reports(report_data, Path(args.output_dir), list(args.format))
    print("\nScan completed.")


if __name__ == "__main__":
    main()