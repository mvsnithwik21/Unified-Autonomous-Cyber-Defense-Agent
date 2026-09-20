"""Integration tests for the end-to-end UACDA orchestrator."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from uacda.core.orchestrator import HUMAN_APPROVAL_REQUIRED, run_pipeline


class OrchestratorTests(unittest.TestCase):
    def test_pipeline_wires_stages_and_audits_approval_gates(self) -> None:
        phishing_fixture = Path(__file__).parents[1] / "fixtures" / "phishing" / "obvious_phishing.eml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_path = root / "auth.log"
            log_path.write_text(
                "\n".join(
                    f"Jan 02 03:04:0{index} web01 sshd: Failed login for alice"
                    for index in range(5)
                ),
                encoding="utf-8",
            )
            audit_path = root / "audit_log.jsonl"

            result = run_pipeline([log_path, phishing_fixture], audit_log_path=audit_path)

            records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]

        self.assertTrue(HUMAN_APPROVAL_REQUIRED)
        self.assertEqual(len(result.events), 6)
        self.assertEqual(len(result.incidents), 2)
        self.assertEqual(len(result.risk_scores), 2)
        self.assertEqual(set(result.risk_scores), set(result.reports))
        self.assertTrue(any(alert.detector_name == "phishing_analysis" for alert in result.alerts))
        self.assertTrue(any(record["stage"] == "ingestion" for record in records))
        self.assertTrue(any(record["stage"] == "phishing_analysis" for record in records))
        self.assertTrue(any(record["stage"] == "correlation" for record in records))
        self.assertTrue(any(record["stage"] == "risk_prioritization" for record in records))
        self.assertTrue(any(record["stage"] == "reporting" for record in records))

        pending = [record for record in records if record["decision"] == "pending approval"]
        self.assertTrue(pending)
        self.assertTrue(all(record["details"]["executed"] is False for record in pending))
        self.assertTrue(all(record["evidence_refs"] for record in records))
        self.assertTrue(all("detector_name" in record and "confidence" in record for record in records))
        self.assertFalse(any(record["decision"] == "executed" for record in records))