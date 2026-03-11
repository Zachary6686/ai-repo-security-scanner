import unittest

from core.risk import (
    calculate_file_risk_score,
    calculate_repository_risk_score,
    get_top_risky_files,
    summarize_severity_counts,
)


class TestRiskSmoke(unittest.TestCase):
    def test_risk_functions_return_reasonable_values(self):
        findings = [
            {"file_path": "a.py", "severity": "HIGH", "confidence": "HIGH"},
            {"file_path": "a.py", "severity": "MEDIUM", "confidence": "MEDIUM"},
            {"file_path": "b.py", "severity": "LOW", "confidence": "LOW"},
        ]

        counts = summarize_severity_counts(findings)
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["LOW"], 1)

        repo_score = calculate_repository_risk_score(findings)
        self.assertGreaterEqual(repo_score, 0)
        self.assertLessEqual(repo_score, 100)

        top_files = get_top_risky_files(findings, top_n=5)
        self.assertTrue(top_files)
        self.assertIn("file_path", top_files[0])
        self.assertIn("risk_score", top_files[0])

        file_score = calculate_file_risk_score([f for f in findings if f["file_path"] == "a.py"])
        self.assertGreater(file_score, 0)


if __name__ == "__main__":
    unittest.main()

