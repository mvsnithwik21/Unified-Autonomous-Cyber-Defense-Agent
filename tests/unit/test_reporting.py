"""Independent unit-test boundary for reporting."""

from __future__ import annotations

import re
import unittest
from datetime import datetime, timezone

from uacda.compliance_audit.checker import ComplianceGapReport, ControlResult
from uacda.core.schemas import Alert, Incident, NormalizedEvent, RiskScore
from uacda.reporting.report_generator import (
	generate_executive_summary,
	generate_incident_report,
	render_compliance_report,
)
from uacda.response_planner.planner import ResponseAction


class ReportingTests(unittest.TestCase):
	def setUp(self) -> None:
		self.event = NormalizedEvent(
			timestamp=datetime(2026, 1, 1, 12, tzinfo=timezone.utc),
			actor="alice",
			asset_id="prod-db-1",
			action="login_failed",
		)
		self.incident = Incident(
			id="incident-1",
			severity="high",
			status="open",
			affected_assets=["prod-db-1"],
			timeline=[self.event],
			alerts=[
				Alert(
					id="alert-1",
					events=[self.event],
					detector_name="repeated_failed_logins",
					confidence=0.9,
					description="Repeated failed logins detected.",
				)
			],
		)
		self.risk_score = RiskScore(
			cvss_like_score=9.0,
			exploitability=9.0,
			asset_criticality=10.0,
			business_impact=10.0,
			final_score=96.0,
			rationale="Production asset with high-confidence detection.",
		)

	def test_incident_report_contains_requested_sections_and_context(self) -> None:
		plan = [
			ResponseAction(order=1, action="Collect evidence", rationale="Preserve telemetry."),
			ResponseAction(order=2, action="Isolate host", requires_human_approval=True),
		]

		report = generate_incident_report(self.incident, self.risk_score, plan)

		for heading in (
			"## Summary",
			"## Timeline",
			"## Evidence",
			"## Severity & Rationale",
			"## Affected Assets",
			"## Recommended Actions",
			"## Confidence Notes",
		):
			self.assertIn(heading, report)
		self.assertIn("event-0", report)
		self.assertIn("HUMAN APPROVAL REQUIRED", report)
		self.assertIn("Informational / no approval required", report)
		self.assertIn("96.00/100", report)

	def test_executive_summary_has_three_to_five_nontechnical_sentences(self) -> None:
		summary = generate_executive_summary(self.incident, self.risk_score)

		sentence_count = len(re.findall(r"[^.!?]+[.!?](?:\s|$)", summary))
		self.assertGreaterEqual(sentence_count, 3)
		self.assertLessEqual(sentence_count, 5)
		self.assertIn("incident-1", summary)
		self.assertIn("96 out of 100", summary)

	def test_compliance_report_renders_status_evidence_and_remediation(self) -> None:
		report = ComplianceGapReport(
			framework="CIS Controls v8 Subset",
			passed_count=1,
			failed_count=1,
			controls=[
				ControlResult(
					control_id="CIS-1",
					title="MFA",
					status="pass",
					evidence="MFA is enabled.",
					remediation="No remediation required.",
				),
				ControlResult(
					control_id="CIS-2",
					title="Log retention",
					status="fail",
					evidence="Observed 30 days.",
					remediation="Increase retention to 90 days.",
				),
			],
		)

		markdown = render_compliance_report(report)

		self.assertIn("# Compliance Gap Report: CIS Controls v8 Subset", markdown)
		self.assertIn("| Control | Status | Evidence | Remediation |", markdown)
		self.assertIn("**PASS**", markdown)
		self.assertIn("**FAIL**", markdown)
		self.assertIn("Increase retention to 90 days.", markdown)
