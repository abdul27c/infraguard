
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from infraguard.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(sys, "argv", ["infraguard", *map(str, args)]):
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    exit_code = main()

        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_json_output_contains_findings_and_summary(self):
        code, stdout, _ = self.run_cli(
            FIXTURES / "insecure-plan.json",
            "--format",
            "json",
        )

        output = json.loads(stdout)
        self.assertEqual(code, 1)
        self.assertEqual(output["summary"]["total"], 3)
        self.assertEqual(output["summary"]["high"], 3)
        self.assertEqual(len(output["findings"]), 3)
        self.assertIn("rule_id", output["findings"][0])
        self.assertIn("remediation", output["findings"][0])

    def test_safe_json_output_returns_zero(self):
        code, stdout, _ = self.run_cli(
            FIXTURES / "safe-plan.json",
            "--format",
            "json",
        )

        output = json.loads(stdout)
        self.assertEqual(code, 0)
        self.assertEqual(output["findings"], [])
        self.assertEqual(output["summary"]["total"], 0)

    def test_missing_file_returns_two(self):
        code, _, stderr = self.run_cli(
            "file-that-does-not-exist.json",
            "--format",
            "json",
        )

        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(stderr))

    def test_invalid_json_file_returns_two(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("{invalid json", encoding="utf-8")

            code, _, stderr = self.run_cli(
                path,
                "--format",
                "json",
            )

        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(stderr))


if __name__ == "__main__":
    unittest.main()
