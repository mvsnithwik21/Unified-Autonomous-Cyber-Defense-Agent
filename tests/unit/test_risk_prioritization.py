"""Independent unit-test boundary for risk prioritization."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from uacda.core.schemas import Alert, Incident, NormalizedEvent
from uacda.risk_prioritization.scorer import load_asset_inventory, rank_incidents, score_incident


def make_incident(
	incident_id: str,
	*,
	confidence: float,
	asset_id: str,
	environment: str,
) -> Incident:
	event = NormalizedEvent(
		timestamp=datetime(2026, 1, 1, 12, tzinfo=timezone.utc),
		asset_id=asset_id,
		actor="alice",
		action="suspicious_action",
		metadata={"environment": environment},
	)
	alert = Alert(
		id=f"alert-{incident_id}",
		events=[event],
		detector_name="test-detector",
		confidence=confidence,
	)
	return Incident(id=incident_id, alerts=[alert], affected_assets=[asset_id], timeline=[event])


class RiskScorerTests(unittest.TestCase):
	def test_scores_production_asset_with_inventory_tier(self) -> None:
		incident = make_incident("prod-incident", confidence=0.9, asset_id="prod-db", environment="production")

		score = score_incident(incident, asset_inventory={"prod-db": 5})

		self.assertEqual(score.exploitability, 9.0)
		self.assertEqual(score.asset_criticality, 10.0)
		self.assertEqual(score.business_impact, 10.0)
		self.assertEqual(score.final_score, 96.0)
		self.assertIn("weight 40%", score.rationale)
		self.assertIn("production environment", score.rationale)

	def test_defaults_missing_asset_to_low_criticality_and_dev_impact(self) -> None:
		incident = make_incident("dev-incident", confidence=0.5, asset_id="dev-host", environment="development")

		score = score_incident(incident, asset_inventory={})

		self.assertEqual(score.asset_criticality, 2.0)
		self.assertEqual(score.business_impact, 2.0)
		self.assertEqual(score.final_score, 32.0)
		self.assertIn("conservative default tier 1/5", score.rationale)

	def test_loads_only_valid_inventory_tiers(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "asset_inventory.json"
			path.write_text(
				json.dumps({"prod-db": 5, "dev-host": 1, "bad-tier": 6, "not-number": "high"}),
				encoding="utf-8",
			)

			inventory = load_asset_inventory(path)

		self.assertEqual(inventory, {"prod-db": 5, "dev-host": 1})

	def test_ranks_incidents_by_final_score_descending(self) -> None:
		low = make_incident("low", confidence=0.2, asset_id="dev", environment="dev")
		high = make_incident("high", confidence=1.0, asset_id="prod", environment="production")

		ranked = rank_incidents([low, high], asset_inventory={"dev": 1, "prod": 5})

		self.assertEqual([incident.id for incident, _ in ranked], ["high", "low"])
		self.assertGreaterEqual(ranked[0][1].final_score, ranked[1][1].final_score)

	def test_final_score_is_bounded(self) -> None:
		incident = make_incident("bounded", confidence=1.0, asset_id="critical", environment="production")

		score = score_incident(incident, asset_inventory={"critical": 5})

		self.assertGreaterEqual(score.final_score, 0.0)
		self.assertLessEqual(score.final_score, 100.0)
