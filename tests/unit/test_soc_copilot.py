"""Independent unit-test boundary for the SOC copilot."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from uacda.core.schemas import Alert, Incident, NormalizedEvent
from uacda.soc_copilot.chat import answer_question


class FakeChatProvider:
	def __init__(self, response: dict) -> None:
		self.response = response
		self.prompt = ""

	def complete(self, prompt: str) -> dict:
		self.prompt = prompt
		return self.response


def make_incident() -> tuple[Incident, NormalizedEvent]:
	event = NormalizedEvent(
		timestamp=datetime(2026, 1, 1, 12, tzinfo=timezone.utc),
		actor="alice",
		asset_id="prod-db-1",
		action="login_failed",
		raw_data={"source_ip": "203.0.113.10"},
	)
	alert = Alert(
		id="alert-1",
		events=[event],
		detector_name="repeated_failed_logins",
		confidence=0.9,
		description="Repeated failed logins",
	)
	return (
		Incident(
			id="incident-1",
			severity="high",
			affected_assets=["prod-db-1"],
			alerts=[alert],
			timeline=[event],
		),
		event,
	)


class SocCopilotTests(unittest.TestCase):
	def test_answers_with_citations_from_only_the_incident(self) -> None:
		incident, event = make_incident()
		provider = FakeChatProvider(
			{
				"answer": "The incident was flagged because of repeated failed logins.",
				"citations": ["event-0"],
			}
		)

		answer = answer_question("Why was this flagged?", incident, provider=provider)
		prompt = json.loads(provider.prompt)

		self.assertIn("repeated failed logins", answer)
		self.assertTrue(answer.endswith("Sources: event-0"))
		self.assertEqual(len(prompt["incident_context"]["events"]), 1)
		self.assertEqual(prompt["incident_context"]["events"][0]["event_id"], "event-0")
		self.assertEqual(prompt["incident_context"]["events"][0]["event"]["asset_id"], event.asset_id)
		self.assertIn("ONLY from the incident alerts and events", prompt["system"])
		self.assertIn("insufficient evidence", prompt["system"])

	def test_invalid_citations_cannot_produce_a_trusted_answer(self) -> None:
		incident, _ = make_incident()
		provider = FakeChatProvider(
			{
				"answer": "The attacker used an unverified technique.",
				"citations": ["event-999"],
			}
		)

		answer = answer_question("What happened?", incident, provider=provider)

		self.assertEqual(answer, "insufficient evidence. Sources: none")

	def test_no_provider_returns_explicit_insufficient_evidence(self) -> None:
		incident, _ = make_incident()

		answer = answer_question("Show related events", incident)

		self.assertEqual(answer, "insufficient evidence. Sources: none")
