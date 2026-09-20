"""Evidence-bounded analyst chat for a single security incident."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from uacda.core.schemas import Incident, NormalizedEvent

LOGGER = logging.getLogger(__name__)


class ChatProvider(Protocol):
    """Provider boundary for hosted, local, or test LLM implementations."""

    def complete(self, prompt: str) -> str | Mapping[str, Any]:
        """Return a JSON response for the supplied system and user context."""


class ChatResponse(BaseModel):
    """Structured response required from the language model."""

    model_config = ConfigDict(extra="ignore")

    answer: str = Field(min_length=1)
    citations: list[str] = Field(default_factory=list)


_default_provider: ChatProvider | None = None


def configure_provider(provider: ChatProvider | None) -> None:
    """Configure the process-wide provider used when no provider is passed."""

    global _default_provider
    _default_provider = provider


def _event_fingerprint(event: NormalizedEvent) -> str:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, default=str, separators=(",", ":"))


def _context_window(incident: Incident) -> tuple[dict[str, Any], dict[str, NormalizedEvent]]:
    events_by_fingerprint: dict[str, NormalizedEvent] = {}
    for event in incident.timeline:
        events_by_fingerprint.setdefault(_event_fingerprint(event), event)
    for alert in incident.alerts:
        for event in alert.events:
            events_by_fingerprint.setdefault(_event_fingerprint(event), event)

    event_by_id = {
        f"event-{index}": event
        for index, event in enumerate(events_by_fingerprint.values())
    }
    event_ids_by_fingerprint = {
        _event_fingerprint(event): event_id for event_id, event in event_by_id.items()
    }
    alerts = []
    for alert in incident.alerts:
        alert_event_ids = [
            event_ids_by_fingerprint[_event_fingerprint(event)]
            for event in alert.events
            if _event_fingerprint(event) in event_ids_by_fingerprint
        ]
        alerts.append(
            {
                "alert_id": alert.id,
                "detector_name": alert.detector_name,
                "confidence": alert.confidence,
                "description": alert.description,
                "event_ids": alert_event_ids,
            }
        )
    context = {
        "incident": {
            "id": incident.id,
            "severity": incident.severity,
            "status": incident.status,
            "affected_assets": incident.affected_assets,
            "alerts": alerts,
        },
        "events": [
            {"event_id": event_id, "event": event.model_dump(mode="json")}
            for event_id, event in event_by_id.items()
        ],
    }
    return context, event_by_id


def _build_prompt(question: str, context: dict[str, Any]) -> str:
    system_prompt = (
        "You are a SOC analyst copilot. Answer ONLY from the incident alerts and events "
        "provided in this prompt. Do not use outside knowledge or invent facts. "
        "If the evidence does not support an answer, use the exact phrase 'insufficient evidence'. "
        "Return JSON only with keys: answer (string) and citations (array of event_id strings). "
        "Every factual claim must be supported by one or more exact event IDs from the context."
    )
    return json.dumps(
        {
            "system": system_prompt,
            "question": question,
            "incident_context": context,
        },
        indent=2,
        default=str,
    )


def _parse_response(response: str | Mapping[str, Any]) -> ChatResponse:
    if isinstance(response, Mapping):
        return ChatResponse.model_validate(response)
    text = response.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1]).strip()
    return ChatResponse.model_validate_json(text)


def _insufficient_evidence(citations: list[str] | None = None) -> str:
    source_text = ", ".join(citations) if citations else "none"
    return f"insufficient evidence. Sources: {source_text}"


def answer_question(
    question: str,
    incident: Incident,
    *,
    provider: ChatProvider | None = None,
) -> str:
    """Answer an analyst question using only one incident's evidence."""

    if not question.strip():
        return _insufficient_evidence()
    context, event_by_id = _context_window(incident)
    selected_provider = provider or _default_provider
    if selected_provider is None:
        LOGGER.warning("No SOC copilot provider configured")
        return _insufficient_evidence()

    try:
        response = _parse_response(selected_provider.complete(_build_prompt(question, context)))
    except (ValidationError, TypeError, ValueError, json.JSONDecodeError) as error:
        LOGGER.warning("Discarding malformed SOC copilot response: %s", error)
        return _insufficient_evidence()
    except Exception as error:  # Provider failures must not break the analyst workflow.
        LOGGER.warning("SOC copilot provider failed: %s", error)
        return _insufficient_evidence()

    valid_citations = list(dict.fromkeys(
        event_id for event_id in response.citations if event_id in event_by_id
    ))
    if not valid_citations:
        return _insufficient_evidence()
    answer = response.answer.strip()
    if not answer:
        return _insufficient_evidence(valid_citations)
    return f"{answer}\n\nSources: {', '.join(valid_citations)}"


__all__ = ["ChatProvider", "ChatResponse", "answer_question", "configure_provider"]