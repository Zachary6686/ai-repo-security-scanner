from pathlib import Path
from datetime import datetime


def generate_markdown_report(report_data, output_path):
    """
    Generate a Markdown security report.

    report_data structure:

    {
        "target": "...",
        "files_scanned": 13,
        "total_findings": 4,
        "severity_counts": {...},
        "repository_risk_score": 34,
        "top_risky_files": [...],
        "findings": [...],
        "scan_errors": [...]
    }
    """

    target = report_data.get("target", "Unknown")
    files_scanned = report_data.get("files_scanned", 0)
    total_findings = report_data.get("total_findings", 0)
    severity_counts = report_data.get("severity_counts", {})
    risk_score = report_data.get("repository_risk_score", 0)
    top_risky_files = report_data.get("top_risky_files", [])
    findings = report_data.get("findings", [])
    scan_errors = report_data.get("scan_errors", [])

    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)

    lines = []

    # Header
    lines.append("# AI Repo Security Scanner Report\n")
    lines.append(f"**Scan Target:** `{target}`  ")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Summary
    lines.append("## Scan Summary\n")

    lines.append(f"- Files scanned: **{files_scanned}**")
    lines.append(f"- Total findings: **{total_findings}**")
    lines.append(f"- Repository risk score: **{risk_score}/100**\n")

    lines.append("### Severity Breakdown\n")
    lines.append(f"- HIGH: **{high}**")
    lines.append(f"- MEDIUM: **{medium}**")
    lines.append(f"- LOW: **{low}**\n")

    # Top risky files
    lines.append("## Top Risky Files\n")

    if not top_risky_files:
        lines.append("_No risky files detected._\n")
    else:
        lines.append("| File | Risk Score | Findings |")
        lines.append("|------|-----------|----------|")

        for item in top_risky_files:
            file_path = item.get("file_path", "")
            score = item.get("risk_score", 0)
            count = item.get("findings_count", 0)

            lines.append(f"| `{file_path}` | {score} | {count} |")

        lines.append("")

    # Findings
    lines.append("## Findings\n")

    if not findings:
        lines.append("_No vulnerabilities detected._\n")
    else:
        for finding in findings:
            severity = finding.get("severity", "LOW")
            title = finding.get("title") or finding.get("type") or "Finding"
            file_path = finding.get("file_path") or finding.get("file")
            line = finding.get("line_number") or finding.get("line")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation") or finding.get(
                "suggested_fix", ""
            )
            snippet = finding.get("code_snippet") or finding.get("snippet") or ""

            lines.append(f"### {title}")
            lines.append(f"- **Severity:** {severity}")
            lines.append(f"- **File:** `{file_path}`")
            lines.append(f"- **Line:** {line}")

            if description:
                lines.append(f"- **Description:** {description}")

            if recommendation:
                lines.append(f"- **Recommendation:** {recommendation}")

            if snippet:
                lines.append("\n```")
                lines.append(snippet)
                lines.append("```")

            lines.append("")

    # Scan errors
    lines.append("## Scan Errors\n")

    if not scan_errors:
        lines.append("_No scan errors._")
    else:
        for err in scan_errors:
            file = err.get("file", "")
            msg = err.get("error", "")
            lines.append(f"- `{file}` : {msg}")

    lines.append("")

    output_path = Path(output_path)
    output_path.write_text("\n".join(lines), encoding="utf-8")

