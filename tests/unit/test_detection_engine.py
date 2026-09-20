"""Independent unit-test boundary for the detection engine."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from uacda.core.schemas import NormalizedEvent
from uacda.detection_engine.llm_reasoner import merge_detections, reason_about_events
from uacda.detection_engine.rules import (
	detect_ioc_matches,
	detect_impossible_travel,
	detect_outside_typical_hours,
	detect_repeated_failed_logins,
)


def event(
	timestamp: datetime,
	action: str,
	*,
	actor: str = "alice",
	asset_id: str = "server-1",
	raw_data: dict | None = None,
	metadata: dict | None = None,
) -> NormalizedEvent:
	return NormalizedEvent(
		timestamp=timestamp,
		action=action,
		actor=actor,
		asset_id=asset_id,
		raw_data=raw_data or {},
		metadata=metadata or {},
	)


class FakeProvider:
	def __init__(self, response: dict) -> None:
		self.response = response
		self.prompt = ""

	def complete(self, prompt: str) -> dict:
		self.prompt = prompt
		return self.response


class DetectionRuleTests(unittest.TestCase):
	def test_repeated_failed_logins(self) -> None:
		start = datetime(2026, 1, 1, 8, tzinfo=timezone.utc)
		events = [event(start + timedelta(minutes=index), "login_failed") for index in range(3)]

		alerts = detect_repeated_failed_logins(events, threshold=3)

		self.assertEqual(len(alerts), 1)
		self.assertEqual(alerts[0].detector_name, "repeated_failed_logins")
		self.assertEqual(alerts[0].events, events)

	def test_impossible_travel(self) -> None:
		first = event(
			datetime(2026, 1, 1, 8, tzinfo=timezone.utc),
			"login_success",
			metadata={"geolocation": {"latitude": 51.5, "longitude": -0.1, "country": "gb"}},
		)
		second = event(
			datetime(2026, 1, 1, 9, tzinfo=timezone.utc),
			"login_success",
			metadata={"geolocation": {"latitude": 35.7, "longitude": 139.7, "country": "jp"}},
		)

		alerts = detect_impossible_travel([first, second])

		self.assertEqual(len(alerts), 1)
		self.assertEqual(alerts[0].events, [first, second])

	def test_outside_typical_hours(self) -> None:
		baseline = [
			event(datetime(2026, 1, 1, 9, tzinfo=timezone.utc), "login_success"),
			event(datetime(2026, 1, 2, 9, tzinfo=timezone.utc), "login_success"),
			event(datetime(2026, 1, 3, 9, tzinfo=timezone.utc), "login_success"),
		]
		unusual = event(datetime(2026, 1, 4, 2, tzinfo=timezone.utc), "login_success")

		alerts = detect_outside_typical_hours(baseline + [unusual])

		self.assertEqual(len(alerts), 1)
		self.assertIs(alerts[0].events[0], unusual)

	def test_local_ioc_match(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "iocs.json"
			path.write_text(json.dumps({"ips": ["203.0.113.10"], "domains": ["evil.example"]}), encoding="utf-8")
			suspicious = event(
				datetime(2026, 1, 1, tzinfo=timezone.utc),
				"dns_lookup",
				raw_data={"destination": "https://evil.example/login", "ip": "203.0.113.10"},
			)

			alerts = detect_ioc_matches([suspicious], path)

		self.assertEqual(len(alerts), 1)
		self.assertIn("known_ioc_match", alerts[0].detector_name)
		self.assertIs(alerts[0].events[0], suspicious)

	def test_llm_alert_requires_valid_source_citation(self) -> None:
		suspicious = event(datetime(2026, 1, 1, tzinfo=timezone.utc), "unusual_api_sequence")
		provider = FakeProvider(
			{
				"suspicious": True,
				"confidence": 0.9,
				"description": "The sequence is suspicious.",
				"supporting_event_ids": ["event-0"],
			}
		)

		alerts = reason_about_events([suspicious], provider)

		self.assertEqual(len(alerts), 1)
		self.assertIs(alerts[0].events[0], suspicious)
		self.assertIn("event-0", provider.prompt)

		provider.response["supporting_event_ids"] = ["event-999"]
		self.assertEqual(reason_about_events([suspicious], provider), [])

	def test_merge_sends_only_unconfident_events_to_llm(self) -> None:
		start = datetime(2026, 1, 1, 8, tzinfo=timezone.utc)
		failures = [event(start + timedelta(minutes=index), "login_failed") for index in range(5)]
		candidate = event(start, "unusual_api_sequence")
		provider = FakeProvider(
			{
				"suspicious": True,
				"confidence": 0.8,
				"description": "Suspicious sequence.",
				"supporting_event_ids": ["event-0"],
			}
		)

		alerts = merge_detections(
			[*failures, candidate],
			provider=provider,
			rule_confidence_threshold=0.7,
		)

		self.assertEqual({alert.detector_name for alert in alerts}, {"repeated_failed_logins", "llm_reasoner"})
		llm_alert = next(alert for alert in alerts if alert.detector_name == "llm_reasoner")
		self.assertIs(llm_alert.events[0], candidate)
