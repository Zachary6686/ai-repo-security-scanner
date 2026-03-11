import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.analyzer import analyze_file
from io_utils.repo_loader import get_source_files
from reports.markdown_report import generate_markdown_report
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.sarif_report import generate_sarif_report

from core.risk import (
    calculate_repository_risk_score,
    get_top_risky_files,
    summarize_severity_counts,
)


# =========================
# CLI
# =========================

def parse_args():
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

def scan_file_safe(file_path):
    try:
        findings = analyze_file(file_path)
        return {
            "file": file_path,
            "findings": findings,
            "error": None
        }
    except Exception as e:
        return {
            "file": file_path,
            "findings": [],
            "error": str(e)
        }


def scan_repository(files, workers=8):
    results = []
    errors = []

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


# =========================
# Terminal output
# =========================

def print_summary(files_scanned, findings, top_files_count):
    severity_counts = summarize_severity_counts(findings)
    repo_score = calculate_repository_risk_score(findings)
    top_files = get_top_risky_files(findings, top_files_count)

    print("\nScan Summary")
    print("----------------------------")
    print(f"Files scanned: {files_scanned}")
    print(f"Total findings: {len(findings)}")
    print()

    print("Severity counts:")
    for sev in ["HIGH", "MEDIUM", "LOW"]:
        print(f"  {sev}: {severity_counts.get(sev,0)}")

    print()
    print(f"Repository risk score: {repo_score}/100")
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
# Main
# =========================

def main():
    args = parse_args()

    target = Path(args.target)

    if not target.exists():
        print(f"Target path does not exist: {target}")
        sys.exit(1)

    print("[1/4] Using local directory:", target)

    # Collect files
    print("[2/4] Collecting source files")
    try:
        files = get_source_files(str(target))
    except Exception as e:
        print("Failed to collect files:", e)
        sys.exit(1)

    if not files:
        print("No source files found.")
        sys.exit(0)

    print(f"Found {len(files)} files to scan.")

    # Scan files
    print("[3/4] Scanning repository")

    findings, errors = scan_repository(
        files,
        workers=args.workers
    )

    # Terminal summary
    print_summary(len(files), findings, args.top_files)

    # Reports
    print("[4/4] Saving reports")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    severity_counts = summarize_severity_counts(findings)
    repo_score = calculate_repository_risk_score(findings)
    top_files = get_top_risky_files(findings, args.top_files)

    report_data = {
        "target": str(target),
        "files_scanned": len(files),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "repository_risk_score": repo_score,
        "top_risky_files": top_files,
        "findings": findings,
        "scan_errors": errors,
    }

    formats = args.format
    if "all" in formats:
        formats = ["md", "html", "json", "sarif"]

    if "md" in formats:
        md_path = output_dir / "security_report.md"
        generate_markdown_report(report_data, md_path)
        print("Markdown report saved to", md_path)

    if "html" in formats:
        html_path = output_dir / "security_report.html"
        generate_html_report(report_data, html_path)
        print("HTML report saved to", html_path)

    if "json" in formats:
        json_path = output_dir / "security_report.json"
        generate_json_report(report_data, json_path)
        print("JSON report saved to", json_path)

    if "sarif" in formats:
        sarif_path = output_dir / "security_report.sarif"
        generate_sarif_report(report_data, sarif_path)
        print("SARIF report saved to", sarif_path)

    print("\nScan completed.")


if __name__ == "__main__":
    main()