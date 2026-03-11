import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestCLISmoke(unittest.TestCase):
    def test_cli_generates_all_reports(self):
        repo_root = Path(__file__).resolve().parents[1]
        scanner = repo_root / "scanner.py"
        samples = repo_root / "samples"

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "output"
            out_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                sys.executable,
                str(scanner),
                str(samples),
                "--output-dir",
                str(out_dir),
                "--format",
                "all",
                "--workers",
                "2",
                "--top-files",
                "5",
            ]

            completed = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, msg=completed.stdout + "\n" + completed.stderr)

            self.assertTrue((out_dir / "security_report.md").exists())
            self.assertTrue((out_dir / "security_report.html").exists())
            self.assertTrue((out_dir / "security_report.json").exists())
            self.assertTrue((out_dir / "security_report.sarif").exists())


if __name__ == "__main__":
    unittest.main()

