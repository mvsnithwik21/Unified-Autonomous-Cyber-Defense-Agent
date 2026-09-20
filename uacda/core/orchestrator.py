"""Wire the UACDA ingestion-to-report pipeline with auditable decisions."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from uacda.core.schemas import Alert, Incident, NormalizedEvent, RiskScore
from uacda.correlation_engine.correlator import correlate_alerts
from uacda.detection_engine.llm_reasoner import LLMProvider, merge_detections
from uacda.log_ingestion.loader import load_events
from uacda.phishing_analysis.analyzer import analyze_eml
from uacda.reporting.report_generator import generate_incident_report
from uacda.response_planner.planner import ResponseAction, plan_response
from uacda.risk_prioritization.scorer import score_incident

LOGGER = logging.getLogger(__name__)
HUMAN_APPROVAL_REQUIRED = True
DEFAULT_AUDIT_LOG_PATH = Path("audit_log.jsonl")


class OrchestrationResult(BaseModel):
    """All artifacts produced by one pipeline run."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    events: list[NormalizedEvent] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)
    risk_scores: dict[str, RiskScore] = Field(default_factory=dict)
    response_plans: dict[str, list[ResponseAction]] = Field(default_factory=dict)
    reports: dict[str, str] = Field(default_factory=dict)


def _event_fingerprint(event: NormalizedEvent) -> str:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, default=str, separators=(",", ":"))


def _event_refs(events: Iterable[NormalizedEvent], refs: Mapping[str, str]) -> list[str]:
    return [refs.get(_event_fingerprint(event), "event-untracked") for event in events]


def _append_audit_record(path: str | Path, record: dict[str, Any]) -> None:
    """Append one JSON object to the explainability audit trail."""

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **record,
    }
    audit_path = Path(path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")
    except OSError as error:
        LOGGER.warning("Unable to write audit record to %s: %s", audit_path, error)


def _phishing_alert(path: Path) -> tuple[NormalizedEvent, Alert | None]:
    verdict = analyze_eml(path)
    event = NormalizedEvent(
        source_type="email",
        actor="unknown",
        asset_id=str(path),
        action=f"phishing_{verdict.verdict}",
        raw_data={"path": str(path), "verdict": verdict.verdict},
        metadata={"evidence": verdict.evidence},
    )
    if verdict.verdict == "clean":
        return event, None
    alert = Alert(
        events=[event],
        detector_name="phishing_analysis",
        confidence=verdict.confidence,
        description=" ".join(verdict.evidence) or f"Email classified as {verdict.verdict}.",
    )
    return event, alert


def run_pipeline(
    input_paths: Iterable[str | Path],
    *,
    llm_provider: LLMProvider | None = None,
    ioc_path: str | Path | None = None,
    asset_inventory_path: str | Path = "config/asset_inventory.json",
    playbook_path: str | Path = "config/playbooks.yaml",
    audit_log_path: str | Path = DEFAULT_AUDIT_LOG_PATH,
) -> OrchestrationResult:
    """Run ingestion, detection, phishing analysis, correlation, and reporting."""

    input_list = [Path(path) for path in input_paths]
    events: list[NormalizedEvent] = []
    phishing_alerts: list[Alert] = []
    for path in input_list:
        if path.suffix.lower() == ".eml":
            try:
                email_event, alert = _phishing_alert(path)
                events.append(email_event)
                _append_audit_record(
                    audit_log_path,
                    {
                        "stage": "phishing_analysis",
                        "decision": alert.detector_name if alert else "clean",
                        "detector_name": "phishing_analysis",
                        "confidence": alert.confidence if alert else 0.98,
                        "evidence_refs": [str(path)],
                        "details": email_event.metadata.get("evidence", []),
                    },
                )
                if alert is not None:
                    phishing_alerts.append(alert)
            except (OSError, ValueError) as error:
                LOGGER.warning("Unable to analyze email %s: %s", path, error)
                _append_audit_record(
                    audit_log_path,
                    {
                        "stage": "phishing_analysis",
                        "decision": "error",
                        "detector_name": "phishing_analysis",
                        "confidence": 0.0,
                        "evidence_refs": [str(path)],
                        "details": str(error),
                    },
                )
            continue

        loaded = load_events(path)
        events.extend(loaded)
        _append_audit_record(
            audit_log_path,
            {
                "stage": "ingestion",
                "decision": "events_loaded",
                "detector_name": "log_ingestion",
                "confidence": 1.0,
                "evidence_refs": [str(path)],
                "details": {"event_count": len(loaded)},
            },
        )

    event_refs = {
        _event_fingerprint(event): f"event-{index}"
        for index, event in enumerate(events)
    }
    detected_alerts = merge_detections(events, provider=llm_provider, ioc_path=ioc_path)
    alerts = [*detected_alerts, *phishing_alerts]
    for alert in alerts:
        _append_audit_record(
            audit_log_path,
            {
                "stage": "detection",
                "decision": "alert_created",
                "detector_name": alert.detector_name,
                "confidence": alert.confidence,
                "evidence_refs": _event_refs(alert.events, event_refs),
                "details": alert.description,
            },
        )

    incidents = correlate_alerts(alerts)
    for incident in incidents:
        _append_audit_record(
            audit_log_path,
            {
                "stage": "correlation",
                "decision": "incident_created",
                "detector_name": "correlation_engine",
                "confidence": max((alert.confidence for alert in incident.alerts), default=0.0),
                "evidence_refs": _event_refs(incident.timeline, event_refs),
                "incident_id": incident.id,
                "details": {"alert_count": len(incident.alerts)},
            },
        )

    risk_scores: dict[str, RiskScore] = {}
    response_plans: dict[str, list[ResponseAction]] = {}
    reports: dict[str, str] = {}
    for incident in incidents:
        risk_score = score_incident(incident, inventory_path=asset_inventory_path)
        risk_scores[incident.id] = risk_score
        _append_audit_record(
            audit_log_path,
            {
                "stage": "risk_prioritization",
                "decision": "risk_scored",
                "detector_name": "risk_prioritization",
                "confidence": risk_score.exploitability / 10,
                "evidence_refs": _event_refs(incident.timeline, event_refs),
                "incident_id": incident.id,
                "details": {"final_score": risk_score.final_score, "rationale": risk_score.rationale},
            },
        )

        plan = plan_response(incident, playbook_path=playbook_path)
        response_plans[incident.id] = plan
        for action in plan:
            pending = HUMAN_APPROVAL_REQUIRED and action.requires_human_approval
            _append_audit_record(
                audit_log_path,
                {
                    "stage": "response_planning",
                    "decision": "pending approval" if pending else "informational",
                    "detector_name": "response_planner",
                    "confidence": risk_score.final_score / 100,
                    "evidence_refs": _event_refs(incident.timeline, event_refs),
                    "incident_id": incident.id,
                    "details": {
                        "order": action.order,
                        "action": action.action,
                        "requires_human_approval": action.requires_human_approval,
                        "executed": False,
                    },
                },
            )

        reports[incident.id] = generate_incident_report(incident, risk_score, plan)
        _append_audit_record(
            audit_log_path,
            {
                "stage": "reporting",
                "decision": "report_generated",
                "detector_name": "reporting",
                "confidence": risk_score.final_score / 100,
                "evidence_refs": _event_refs(incident.timeline, event_refs),
                "incident_id": incident.id,
                "details": {"format": "markdown"},
            },
        )

    return OrchestrationResult(
        events=events,
        alerts=alerts,
        incidents=incidents,
        risk_scores=risk_scores,
        response_plans=response_plans,
        reports=reports,
    )


def orchestrate(*args: Any, **kwargs: Any) -> OrchestrationResult:
    """Compatibility alias for ``run_pipeline``."""

    return run_pipeline(*args, **kwargs)


__all__ = ["HUMAN_APPROVAL_REQUIRED", "OrchestrationResult", "orchestrate", "run_pipeline"]