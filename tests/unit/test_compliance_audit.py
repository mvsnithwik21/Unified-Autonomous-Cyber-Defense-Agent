"""Independent unit-test boundary for compliance auditing."""

from __future__ import annotations

import unittest

from uacda.compliance_audit.checker import check_compliance, check_framework


class ComplianceCheckerTests(unittest.TestCase):
	def test_cis_subset_reports_each_control_and_gaps(self) -> None:
		report = check_compliance()

		self.assertEqual(report.framework, "CIS Controls v8 Subset")
		self.assertEqual(len(report.controls), 10)
		self.assertEqual(report.passed_count, 7)
		self.assertEqual(report.failed_count, 3)
		failed = {control.control_id: control for control in report.controls if control.status == "fail"}
		self.assertIn("CIS-5.4", failed)
		self.assertIn("CIS-8.3", failed)
		self.assertIn("CIS-11.4", failed)
		self.assertIn("retention", failed["CIS-8.3"].remediation.lower())
		self.assertIn("Observed 30", failed["CIS-8.3"].evidence)

	def test_generic_framework_shape_can_be_swapped(self) -> None:
		organization = {"security": {"mfa": True, "owners": ["soc"]}}
		framework = {
			"framework": "NIST Example",
			"controls": [
				{
					"id": "NIST-AC-1",
					"title": "MFA enabled",
					"path": "security.mfa",
					"operator": "equals",
					"expected": True,
					"remediation": "Enable MFA.",
				},
				{
					"id": "NIST-IR-1",
					"title": "SOC owner exists",
					"path": "security.owners",
					"operator": "contains",
					"expected": "soc",
					"remediation": "Assign a SOC owner.",
				},
			],
		}

		report = check_framework(organization, framework)

		self.assertEqual(report.framework, "NIST Example")
		self.assertEqual(report.passed_count, 2)
		self.assertEqual(report.failed_count, 0)
		self.assertTrue(all(control.remediation == "No remediation required." for control in report.controls))

	def test_missing_setting_fails_with_remediation(self) -> None:
		report = check_framework(
			{},
			{
				"framework": "ISO Example",
				"controls": [
					{
						"id": "ISO-A.1",
						"title": "Logging configured",
						"path": "logging.enabled",
						"operator": "equals",
						"expected": True,
						"remediation": "Enable centralized logging.",
					}
				],
			},
		)

		self.assertEqual(report.controls[0].status, "fail")
		self.assertIn("missing", report.controls[0].evidence)
		self.assertEqual(report.controls[0].remediation, "Enable centralized logging.")
