import unittest
from pathlib import Path

from core.analyzer import analyze_file


class TestAnalyzerSmoke(unittest.TestCase):
    def test_analyze_sample_vuln_file_finds_issues(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "vulnerable_sample.py"
        findings = analyze_file(str(sample))

        self.assertIsInstance(findings, list)
        self.assertGreaterEqual(len(findings), 1)

        rule_ids = {f.get("rule_id") for f in findings}
        # AST rules should trigger on this sample.
        self.assertTrue({"PY001", "PY003", "PY005", "PY006"}.intersection(rule_ids))


if __name__ == "__main__":
    unittest.main()

