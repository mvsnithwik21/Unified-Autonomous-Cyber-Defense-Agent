"""End-to-end verification using the checked-in synthetic sample data."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from uacda.core.orchestrator import run_pipeline


class PipelineIntegrationTests(unittest.TestCase):
    def test_sample_data_runs_full_pipeline(self) -> None:
        workspace = Path(__file__).parents[1]
        samples = workspace / "data" / "samples"
        input_paths = [
            samples / "sample_syslog.log",
            samples / "cloud_audit.jsonl",
            samples / "vulnerability_scan.csv",
            samples / "clean.eml",
            samples / "phishing.eml",
            samples / "ambiguous.eml",
        ]

        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit_log.jsonl"
            result = run_pipeline(input_paths, audit_log_path=audit_path)
            audit_records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertGreaterEqual(len(result.incidents), 1)
        self.assertTrue(any(verdict.verdict == "phishing" for verdict in result.phishing_verdicts.values()))
        self.assertIsNotNone(result.compliance_report)
        assert result.compliance_report is not None
        self.assertGreaterEqual(result.compliance_report.failed_count, 1)
        self.assertTrue(result.reports)
        self.assertTrue(all(report.strip() for report in result.reports.values()))
        self.assertTrue(any(record["stage"] == "compliance_audit" for record in audit_records))


if __name__ == "__main__":
    unittest.main()
