"""Independent unit-test boundary for response planning."""

from __future__ import annotations

import unittest

from uacda.core.schemas import Alert, Incident
from uacda.response_planner.planner import infer_incident_type, plan_response


def make_incident(detector_name: str, severity: str) -> Incident:
	return Incident(
		id=f"incident-{detector_name}",
		severity=severity,
		affected_assets=["host-1"],
		alerts=[Alert(detector_name=detector_name, description=detector_name, confidence=0.9)],
	)


class ResponsePlannerTests(unittest.TestCase):
	def test_brute_force_critical_plan_marks_containment_for_approval(self) -> None:
		plan = plan_response(make_incident("repeated_failed_logins", "critical"))

		self.assertGreaterEqual(len(plan), 3)
		self.assertEqual([action.order for action in plan], list(range(1, len(plan) + 1)))
		self.assertFalse(plan[0].requires_human_approval)
		self.assertTrue(any(action.requires_human_approval and "Isolate" in action.action for action in plan))
		self.assertTrue(any(action.requires_human_approval and "Revoke" in action.action for action in plan))

	def test_all_requested_playbook_types_are_selected(self) -> None:
		cases = {
			"phishing_analyzer": "phishing",
			"known_ioc_match": "malware",
			"impossible_travel": "impossible_travel",
			"repeated_failed_logins": "brute_force",
		}
		for detector_name, expected_type in cases.items():
			with self.subTest(detector_name=detector_name):
				incident = make_incident(detector_name, "high")
				self.assertEqual(infer_incident_type(incident), expected_type)
				self.assertTrue(plan_response(incident))

	def test_phishing_plan_marks_quarantine_and_block_for_approval(self) -> None:
		plan = plan_response(make_incident("phishing_analyzer", "high"))

		self.assertTrue(any(action.requires_human_approval and "Quarantine" in action.action for action in plan))
		self.assertTrue(any(action.requires_human_approval and "Block" in action.action for action in plan))

	def test_unknown_type_uses_informational_generic_plan(self) -> None:
		plan = plan_response(make_incident("new_detector", "unknown"))

		self.assertGreaterEqual(len(plan), 1)
		self.assertTrue(all(not action.requires_human_approval for action in plan))
		self.assertIn("Review incident evidence", plan[0].action)
