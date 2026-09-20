"""Independent unit-test boundary for phishing analysis."""

from __future__ import annotations

import unittest
from pathlib import Path

from uacda.phishing_analysis.analyzer import analyze_eml


FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "phishing"


class PhishingAnalyzerTests(unittest.TestCase):
	"""Verify verdicts and evidence for representative email messages."""

	def test_clean_authenticated_message(self) -> None:
		verdict = analyze_eml(FIXTURE_DIRECTORY / "clean.eml")

		self.assertEqual(verdict.verdict, "clean")
		self.assertGreaterEqual(verdict.confidence, 0.9)
		self.assertEqual(verdict.evidence, [])

	def test_obvious_phishing_message_reports_specific_evidence(self) -> None:
		verdict = analyze_eml(FIXTURE_DIRECTORY / "obvious_phishing.eml")

		self.assertEqual(verdict.verdict, "phishing")
		self.assertGreaterEqual(verdict.confidence, 0.9)
		evidence = " ".join(verdict.evidence)
		self.assertIn("SPF authentication fail", evidence)
		self.assertIn("DKIM authentication fail", evidence)
		self.assertIn("DMARC authentication fail", evidence)
		self.assertIn("Reply-To domain", evidence)
		self.assertIn("lookalike domain", evidence)
		self.assertIn("security_update.exe", evidence)

	def test_ambiguous_message_is_suspicious(self) -> None:
		verdict = analyze_eml(FIXTURE_DIRECTORY / "ambiguous.eml")

		self.assertEqual(verdict.verdict, "suspicious")
		self.assertIn("Reply-To domain external.example differs from sender domain partner.example.", verdict.evidence)
