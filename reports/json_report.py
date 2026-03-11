import json
from pathlib import Path
from datetime import datetime


def generate_json_report(report_data, output_path):
    output = {
        "tool": "AI Repo Security Scanner",
        "version": "1.0.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": report_data.get("target"),
        "scan_summary": {
            "files_scanned": report_data.get("files_scanned", 0),
            "total_findings": report_data.get("total_findings", 0),
            "severity_counts": report_data.get("severity_counts", {}),
            "repository_risk_score": report_data.get("repository_risk_score", 0),
        },
        "top_risky_files": report_data.get("top_risky_files", []),
        "findings": report_data.get("findings", []),
        "scan_errors": report_data.get("scan_errors", []),
    }

    output_path = Path(output_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

