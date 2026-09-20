"""Translate incident types and severities into ordered response actions."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from uacda.core.schemas import Incident

LOGGER = logging.getLogger(__name__)
DEFAULT_PLAYBOOK_PATH = Path("config/playbooks.yaml")


class ResponseAction(BaseModel):
    """One recommended response step and its execution-approval requirement."""

    model_config = ConfigDict(extra="forbid")

    order: int = Field(ge=1)
    action: str = Field(min_length=1)
    rationale: str = Field(default="")
    requires_human_approval: bool = False


def load_playbooks(path: str | Path = DEFAULT_PLAYBOOK_PATH) -> dict[str, Any]:
    """Load response playbooks from YAML, returning an empty mapping on failure."""

    try:
        with Path(path).open(encoding="utf-8") as handle:
            payload = yaml.safe_load(handle)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        LOGGER.warning("Unable to load response playbooks %s: %s", path, error)
        return {}
    if not isinstance(payload, dict):
        LOGGER.warning("Response playbooks %s must contain a mapping", path)
        return {}
    playbooks = payload.get("playbooks", payload)
    if not isinstance(playbooks, dict):
        LOGGER.warning("Response playbooks %s must contain a playbooks mapping", path)
        return {}
    return playbooks


def infer_incident_type(incident: Incident) -> str:
    """Infer a playbook key from detector names and alert evidence."""

    text = " ".join(
        f"{alert.detector_name} {alert.description}" for alert in incident.alerts
    ).lower()
    if "impossible_travel" in text or "impossible travel" in text:
        return "impossible_travel"
    if "phish" in text or "lookalike domain" in text or "reply-to domain" in text:
        return "phishing"
    if "malware" in text or "known_ioc_match" in text or "malicious indicator" in text:
        return "malware"
    if "brute" in text or "failed_login" in text or "failed login" in text:
        return "brute_force"
    return "generic"


def _severity_actions(playbook: Any, severity: str) -> list[dict[str, Any]]:
    if not isinstance(playbook, dict):
        return []
    severity_map = playbook.get("severity", playbook)
    if not isinstance(severity_map, dict):
        return []
    normalized_severity = severity.lower()
    if isinstance(severity_map.get(normalized_severity), list):
        return severity_map[normalized_severity]
    for fallback in ("high", "medium", "low", "default"):
        if isinstance(severity_map.get(fallback), list):
            return severity_map[fallback]
    return []


def _context(incident: Incident, incident_type: str) -> dict[str, str]:
    assets = ", ".join(incident.affected_assets) or "affected assets"
    return {
        "incident_id": incident.id,
        "incident_type": incident_type,
        "severity": incident.severity,
        "assets": assets,
    }


def plan_response(
    incident: Incident,
    *,
    playbook_path: str | Path = DEFAULT_PLAYBOOK_PATH,
) -> list[ResponseAction]:
    """Return an ordered, approval-aware response plan for an incident."""

    playbooks = load_playbooks(playbook_path)
    incident_type = infer_incident_type(incident)
    playbook = playbooks.get(incident_type) or playbooks.get("generic", {})
    raw_actions = _severity_actions(playbook, incident.severity)
    context = _context(incident, incident_type)
    actions: list[ResponseAction] = []
    for order, raw_action in enumerate(raw_actions, start=1):
        if not isinstance(raw_action, dict):
            LOGGER.warning("Ignoring malformed %s response action", incident_type)
            continue
        try:
            action_text = str(raw_action["action"]).format(**context)
            rationale = str(raw_action.get("rationale", "")).format(**context)
            actions.append(
                ResponseAction(
                    order=order,
                    action=action_text,
                    rationale=rationale,
                    requires_human_approval=bool(raw_action.get("requires_human_approval", False)),
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            LOGGER.warning("Ignoring malformed %s response action: %s", incident_type, error)
    return actions


def create_plan(
    incident: Incident,
    *,
    playbook_path: str | Path = DEFAULT_PLAYBOOK_PATH,
) -> list[ResponseAction]:
    """Compatibility alias for callers that use create-plan terminology."""

    return plan_response(incident, playbook_path=playbook_path)


__all__ = ["ResponseAction", "create_plan", "infer_incident_type", "load_playbooks", "plan_response"]