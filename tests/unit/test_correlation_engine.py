"""Independent unit-test boundary for the correlation engine."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from uacda.core.schemas import Alert, NormalizedEvent
from uacda.correlation_engine.correlator import correlate_alerts


def make_event(minutes: int, *, actor: str = "alice", asset_id: str = "host-1") -> NormalizedEvent:
	return NormalizedEvent(
		timestamp=datetime(2026, 1, 1, 8, tzinfo=timezone.utc) + timedelta(minutes=minutes),
		source_type="test",
		actor=actor,
		asset_id=asset_id,
		action="login_success",
	)


def make_alert(event: NormalizedEvent, detector_name: str, confidence: float = 0.8) -> Alert:
	return Alert(events=[event], detector_name=detector_name, confidence=confidence, description=detector_name)


class CorrelatorTests(unittest.TestCase):
	def test_groups_shared_actor_within_default_window(self) -> None:
		first = make_alert(make_event(0, asset_id="host-1"), "detector-a")
		second = make_alert(make_event(20, asset_id="host-2"), "detector-b")

		incidents = correlate_alerts([first, second])

		self.assertEqual(len(incidents), 1)
		self.assertEqual(len(incidents[0].alerts), 2)
		self.assertEqual(incidents[0].affected_assets, ["host-1", "host-2"])

	def test_groups_shared_asset_within_configured_window(self) -> None:
		first = make_alert(make_event(0, actor="alice", asset_id="shared-host"), "detector-a")
		second = make_alert(make_event(10, actor="bob", asset_id="shared-host"), "detector-b")

		incidents = correlate_alerts([first, second], time_window=timedelta(minutes=15))

		self.assertEqual(len(incidents), 1)

	def test_keeps_alerts_outside_time_window_separate(self) -> None:
		first = make_alert(make_event(0), "detector-a")
		second = make_alert(make_event(31), "detector-b")

		incidents = correlate_alerts([first, second])

		self.assertEqual(len(incidents), 2)

	def test_merges_overlapping_detector_alerts_and_deduplicates_events(self) -> None:
		shared_event = make_event(0)
		first = make_alert(shared_event, "rule_detector", confidence=0.8)
		second = make_alert(shared_event.model_copy(), "llm_reasoner", confidence=0.9)

		incidents = correlate_alerts([first, second])

		self.assertEqual(len(incidents), 1)
		incident = incidents[0]
		self.assertEqual(len(incident.alerts), 1)
		self.assertEqual(incident.alerts[0].detector_name, "rule_detector+llm_reasoner")
		self.assertEqual(len(incident.alerts[0].events), 1)
		self.assertEqual(len(incident.timeline), 1)
		self.assertEqual(incident.alerts[0].confidence, 0.9)

	def test_duplicate_alert_id_is_not_counted_twice(self) -> None:
		alert = make_alert(make_event(0), "detector-a")

		incidents = correlate_alerts([alert, alert.model_copy()])

		self.assertEqual(len(incidents), 1)
		self.assertEqual(len(incidents[0].alerts), 1)
