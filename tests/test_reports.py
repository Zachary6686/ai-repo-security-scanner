import tempfile
import unittest
from pathlib import Path

from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.markdown_report import generate_markdown_report
from reports.sarif_report import generate_sarif_report


class TestReportsSmoke(unittest.TestCase):
    def test_reports_generate_files(self):
        report_data = {
            "target": "sample",
            "files_scanned": 1,
            "total_findings": 1,
            "severity_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "repository_risk_score": 10,
            "top_risky_files": [
                {
                    "file_path": "sample.py",
                    "risk_score": 10,
                    "findings_count": 1,
                    "severity_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
                }
            ],
            "findings": [
                {
                    "rule_id": "X",
                    "title": "Test Finding",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "category": "Test",
                    "file_path": "sample.py",
                    "line_number": 1,
                    "code_snippet": ">>    1: eval('1')",
                    "description": "desc",
                    "recommendation": "fix",
                }
            ],
            "scan_errors": [],
        }

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            md = tmp_path / "security_report.md"
            html = tmp_path / "security_report.html"
            js = tmp_path / "security_report.json"
            sarif = tmp_path / "security_report.sarif"

            generate_markdown_report(report_data, md)
            generate_html_report(report_data, html)
            generate_json_report(report_data, js)
            generate_sarif_report(report_data, sarif)

            self.assertTrue(md.exists())
            self.assertTrue(html.exists())
            self.assertTrue(js.exists())
            self.assertTrue(sarif.exists())

            self.assertIn("AI Repo Security Scanner Report", md.read_text(encoding="utf-8"))
            self.assertIn("AI Repo Security Scanner", html.read_text(encoding="utf-8"))
            self.assertIn('"tool": "AI Repo Security Scanner"', js.read_text(encoding="utf-8"))
            self.assertIn('"version": "2.1.0"', sarif.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

