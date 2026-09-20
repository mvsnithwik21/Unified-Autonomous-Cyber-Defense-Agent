"""Pluggable LLM reasoning that preserves evidence for every generated alert."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from uacda.core.schemas import Alert, NormalizedEvent
from uacda.detection_engine.rules import run_rule_detectors

LOGGER = logging.getLogger(__name__)


class LLMProvider(Protocol):
    """Provider boundary implemented by an OpenAI, local, or test adapter."""

    def complete(self, prompt: str) -> str | Mapping[str, Any]:
        """Return a structured JSON response for the supplied prompt."""


class LLMAnalysis(BaseModel):
    """Validated response shape expected from an LLM provider."""

    model_config = ConfigDict(extra="ignore")

    suspicious: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    description: str = ""
    supporting_event_ids: list[str] = Field(default_factory=list)


def build_reasoning_prompt(events: Sequence[NormalizedEvent]) -> str:
    """Build a structured prompt with stable IDs the model must cite."""

    event_payload = [
        {"event_id": f"event-{index}", "event": event.model_dump(mode="json")}
        for index, event in enumerate(events)
    ]
    request = {
        "task": "Identify suspicious patterns in these security events that deterministic rules did not confidently flag.",
        "requirements": [
            "Return JSON only.",
            "Set suspicious to true only when evidence supports a security concern.",
            "Set confidence to a number from 0 to 1.",
            "Cite every supporting event using its exact event_id.",
            "Do not invent events, indicators, identities, or facts not present in the input.",
        ],
        "output_schema": {
            "suspicious": "boolean",
            "confidence": "number between 0 and 1",
            "description": "string",
            "supporting_event_ids": "array of exact event_id strings",
        },
        "events": event_payload,
    }
    return json.dumps(request, indent=2, default=str)


def _parse_provider_response(response: str | Mapping[str, Any]) -> LLMAnalysis:
    if isinstance(response, Mapping):
        return LLMAnalysis.model_validate(response)
    text = response.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1]).strip()
    return LLMAnalysis.model_validate_json(text)


def reason_about_events(
    events: Sequence[NormalizedEvent],
    provider: LLMProvider,
    *,
    minimum_confidence: float = 0.6,
) -> list[Alert]:
    """Ask an LLM about candidate events and attach only cited source events."""

    if not events:
        return []
    if not 0.0 <= minimum_confidence <= 1.0:
        raise ValueError("minimum_confidence must be between 0 and 1")

    try:
        analysis = _parse_provider_response(provider.complete(build_reasoning_prompt(events)))
    except (ValidationError, TypeError, ValueError, json.JSONDecodeError) as error:
        LOGGER.warning("Discarding malformed LLM detection response: %s", error)
        return []
    except Exception as error:  # Provider failures must not stop ingestion or detection.
        LOGGER.warning("LLM provider failed; continuing without LLM alert: %s", error)
        return []

    event_by_id = {f"event-{index}": event for index, event in enumerate(events)}
    cited_events = [
        event_by_id[event_id]
        for event_id in dict.fromkeys(analysis.supporting_event_ids)
        if event_id in event_by_id
    ]
    if not analysis.suspicious or analysis.confidence < minimum_confidence:
        return []
    if not cited_events:
        LOGGER.warning("Discarding LLM alert without valid supporting source events")
        return []

    return [
        Alert(
            events=cited_events,
            detector_name="llm_reasoner",
            confidence=analysis.confidence,
            description=analysis.description or "LLM identified a suspicious pattern in cited events.",
        )
    ]


def merge_detections(
    events: Sequence[NormalizedEvent],
    *,
    provider: LLMProvider | None = None,
    ioc_path: str | Path | None = None,
    baseline_events: Sequence[NormalizedEvent] | None = None,
    rule_confidence_threshold: float = 0.8,
    llm_confidence_threshold: float = 0.6,
) -> list[Alert]:
    """Merge deterministic alerts with LLM alerts for remaining candidate events."""

    if not 0.0 <= rule_confidence_threshold <= 1.0:
        raise ValueError("rule_confidence_threshold must be between 0 and 1")
    rule_alerts = run_rule_detectors(
        events,
        ioc_path=ioc_path,
        baseline_events=baseline_events,
    )
    if provider is None:
        return rule_alerts

    confidently_flagged = {
        id(event)
        for alert in rule_alerts
        if alert.confidence >= rule_confidence_threshold
        for event in alert.events
    }
    candidates = [event for event in events if id(event) not in confidently_flagged]
    return [
        *rule_alerts,
        *reason_about_events(
            candidates,
            provider,
            minimum_confidence=llm_confidence_threshold,
        ),
    ]


__all__ = [
    "LLMAnalysis",
    "LLMProvider",
    "build_reasoning_prompt",
    "merge_detections",
    "reason_about_events",
]