"""Explainable risk scoring and ranking for correlated security incidents."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Iterable

from uacda.core.schemas import Incident, RiskScore

LOGGER = logging.getLogger(__name__)
DEFAULT_ASSET_INVENTORY_PATH = Path("config/asset_inventory.json")

EXPLOITABILITY_WEIGHT = 0.40
ASSET_CRITICALITY_WEIGHT = 0.35
BUSINESS_IMPACT_WEIGHT = 0.25


def load_asset_inventory(path: str | Path = DEFAULT_ASSET_INVENTORY_PATH) -> dict[str, int]:
    """Load an asset-to-criticality-tier mapping, ignoring invalid entries."""

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        LOGGER.warning("Unable to load asset inventory %s: %s", path, error)
        return {}

    if isinstance(payload, dict) and isinstance(payload.get("assets"), dict):
        payload = payload["assets"]
    if not isinstance(payload, dict):
        LOGGER.warning("Asset inventory %s must contain an object mapping asset IDs to tiers", path)
        return {}

    inventory: dict[str, int] = {}
    for asset_id, tier in payload.items():
        try:
            numeric_tier = int(tier)
        except (TypeError, ValueError):
            LOGGER.warning("Ignoring non-numeric criticality tier for asset %s", asset_id)
            continue
        if 1 <= numeric_tier <= 5:
            inventory[str(asset_id)] = numeric_tier
        else:
            LOGGER.warning("Ignoring out-of-range criticality tier for asset %s", asset_id)
    return inventory


def _all_event_values(incident: Incident) -> Iterable[Any]:
    def walk(value: Any) -> Iterable[Any]:
        if isinstance(value, dict):
            for key, nested in value.items():
                yield key
                yield from walk(nested)
        elif isinstance(value, (list, tuple, set)):
            for nested in value:
                yield from walk(nested)
        else:
            yield value

    for event in incident.timeline:
        yield from walk(event.metadata)
        yield from walk(event.raw_data)


def _environment(incident: Incident) -> tuple[str, int]:
    """Infer business impact from explicit environment tags in incident evidence."""

    text = " ".join(str(value).lower() for value in _all_event_values(incident))
    if re.search(r"\b(prod|production|live)\b", text):
        return "production", 10
    if re.search(r"\b(staging|stage|qa|uat)\b", text):
        return "staging", 6
    if re.search(r"\b(dev|development|test|testing|sandbox)\b", text):
        return "development", 2
    return "unknown", 5


def _incident_assets(incident: Incident) -> list[str]:
    assets = list(incident.affected_assets)
    for event in incident.timeline:
        if event.asset_id and event.asset_id.lower() != "unknown" and event.asset_id not in assets:
            assets.append(event.asset_id)
    return assets


def score_incident(
    incident: Incident,
    *,
    asset_inventory: dict[str, int] | None = None,
    inventory_path: str | Path = DEFAULT_ASSET_INVENTORY_PATH,
) -> RiskScore:
    """Compute an explainable 0–100 risk score for one incident."""

    inventory = asset_inventory if asset_inventory is not None else load_asset_inventory(inventory_path)
    confidence = max((alert.confidence for alert in incident.alerts), default=0.0)
    exploitability = confidence * 10

    assets = _incident_assets(incident)
    known_tiers = [inventory[asset_id] for asset_id in assets if asset_id in inventory]
    if known_tiers:
        tier = max(known_tiers)
        asset_criticality = tier * 2
        asset_basis = f"highest inventory tier {tier}/5 across {', '.join(assets)}"
    else:
        tier = 1
        asset_criticality = 2
        asset_basis = "no matching inventory entry; conservative default tier 1/5"

    environment, business_impact = _environment(incident)
    final_score = (
        exploitability * EXPLOITABILITY_WEIGHT
        + asset_criticality * ASSET_CRITICALITY_WEIGHT
        + business_impact * BUSINESS_IMPACT_WEIGHT
    ) * 10
    final_score = round(max(0.0, min(100.0, final_score)), 2)
    rationale = (
        f"Exploitability {exploitability:.2f}/10 from maximum detector confidence "
        f"{confidence:.2f} (weight {EXPLOITABILITY_WEIGHT:.0%}); "
        f"asset criticality {asset_criticality:.2f}/10 based on {asset_basis} "
        f"(weight {ASSET_CRITICALITY_WEIGHT:.0%}); "
        f"business impact {business_impact:.2f}/10 from {environment} environment "
        f"(weight {BUSINESS_IMPACT_WEIGHT:.0%})."
    )
    return RiskScore(
        cvss_like_score=round(exploitability, 2),
        asset_criticality=round(asset_criticality, 2),
        exploitability=round(exploitability, 2),
        business_impact=round(business_impact, 2),
        final_score=final_score,
        rationale=rationale,
    )


def rank_incidents(
    incidents: Iterable[Incident],
    *,
    asset_inventory: dict[str, int] | None = None,
    inventory_path: str | Path = DEFAULT_ASSET_INVENTORY_PATH,
) -> list[tuple[Incident, RiskScore]]:
    """Return incidents paired with scores from highest to lowest risk."""

    scored = [
        (
            incident,
            score_incident(
                incident,
                asset_inventory=asset_inventory,
                inventory_path=inventory_path,
            ),
        )
        for incident in incidents
    ]
    return sorted(scored, key=lambda item: item[1].final_score, reverse=True)


__all__ = ["load_asset_inventory", "rank_incidents", "score_incident"]