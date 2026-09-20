"""Markdown renderers for incidents, executive summaries, and compliance reports."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from uacda.compliance_audit.checker import ComplianceGapReport
from uacda.core.schemas import Incident, NormalizedEvent, RiskScore
from uacda.response_planner.planner import ResponseAction


def _event_key(event: NormalizedEvent) -> str:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, default=str, separators=(",", ":"))


def _event_catalog(incident: Incident) -> list[tuple[str, NormalizedEvent]]:
    events: dict[str, NormalizedEvent] = {}
    for event in incident.timeline:
        events.setdefault(_event_key(event), event)
    for alert in incident.alerts:
        for event in alert.events:
            events.setdefault(_event_key(event), event)
    ordered = sorted(events.values(), key=lambda event: event.timestamp)
    return [(f"event-{index}", event) for index, event in enumerate(ordered)]


def _event_ids(incident: Incident) -> dict[str, str]:
    return {_event_key(event): event_id for event_id, event in _event_catalog(incident)}


def _format_timestamp(event: NormalizedEvent) -> str:
    return event.timestamp.isoformat()


def _markdown_text(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def generate_incident_report(
    incident: Incident,
    risk_score: RiskScore,
    response_plan: Sequence[ResponseAction],
) -> str:
    """Generate a complete operational Markdown report for one incident."""

    event_ids = _event_ids(incident)
    alerts = incident.alerts
    detector_names = ", ".join(dict.fromkeys(alert.detector_name for alert in alerts)) or "undetermined"
    assets = incident.affected_assets or [event.asset_id for _, event in _event_catalog(incident)]
    lines = [
        f"# Incident Report: {_markdown_text(incident.id)}",
        "",
        "## Summary",
        f"- **Incident ID:** {_markdown_text(incident.id)}",
        f"- **Detectors:** {_markdown_text(detector_names)}",
        f"- **Status:** {_markdown_text(incident.status)}",
        f"- **Severity:** {_markdown_text(incident.severity)}",
        f"- **Risk score:** {risk_score.final_score:.2f}/100",
        "",
        "## Timeline",
    ]
    timeline = _event_catalog(incident)
    if timeline:
        lines.extend(
            f"- **{event_id}** `{_format_timestamp(event)}`: "
            f"{_markdown_text(event.action)} by `{_markdown_text(event.actor)}` on "
            f"`{_markdown_text(event.asset_id)}`."
            for event_id, event in timeline
        )
    else:
        lines.append("- No underlying events were recorded.")

    lines.extend(["", "## Evidence"])
    if alerts:
        for alert in alerts:
            cited_ids = [
                event_ids[_event_key(event)]
                for event in alert.events
                if _event_key(event) in event_ids
            ]
            citations = ", ".join(cited_ids) or "no event citation"
            description = _markdown_text(alert.description or "No detector description provided.")
            lines.append(
                f"- **{_markdown_text(alert.detector_name)}** "
                f"(confidence {alert.confidence:.2f}; sources: {citations}): {description}"
            )
    else:
        lines.append("- No alerts were recorded.")

    lines.extend(
        [
            "",
            "## Severity & Rationale",
            f"- **CVSS-like score:** {risk_score.cvss_like_score:.2f}/10",
            f"- **Exploitability:** {risk_score.exploitability:.2f}/10",
            f"- **Asset criticality:** {risk_score.asset_criticality:.2f}/10",
            f"- **Business impact:** {risk_score.business_impact:.2f}/10",
            f"- **Rationale:** {_markdown_text(risk_score.rationale)}",
            "",
            "## Affected Assets",
        ]
    )
    if assets:
        lines.extend(f"- `{_markdown_text(asset)}`" for asset in dict.fromkeys(assets))
    else:
        lines.append("- No affected assets were identified.")

    lines.extend(["", "## Recommended Actions"])
    if response_plan:
        for action in sorted(response_plan, key=lambda item: item.order):
            approval = "HUMAN APPROVAL REQUIRED" if action.requires_human_approval else "Informational / no approval required"
            rationale = f" — {_markdown_text(action.rationale)}" if action.rationale else ""
            lines.append(
                f"{action.order}. **{_markdown_text(action.action)}** "
                f"`{approval}`{rationale}"
            )
    else:
        lines.append("- No response actions were recommended.")

    max_confidence = max((alert.confidence for alert in alerts), default=0.0)
    lines.extend(
        [
            "",
            "## Confidence Notes",
            f"- Highest detector confidence: {max_confidence:.2f}.",
            f"- Risk score confidence signal: {risk_score.exploitability / 10:.2f}.",
            "- Conclusions are limited to the alerts and events recorded in this report.",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_executive_summary(incident: Incident, risk_score: RiskScore) -> str:
    """Generate a four-sentence, non-technical summary for leadership."""

    assets = ", ".join(incident.affected_assets) or "the affected environment"
    action = "follow-up actions have been recommended" if incident.alerts else "additional review is recommended"
    return (
        f"Incident {incident.id} is currently rated {incident.severity} and affects {assets}. "
        f"The assessment produced an overall risk score of {risk_score.final_score:.0f} out of 100. "
        f"The available evidence supports the current assessment, while {action}. "
        "Any disruptive response should be approved through the organization’s normal process."
    )


def render_compliance_report(report: ComplianceGapReport) -> str:
    """Render a compliance gap report as a Markdown control table."""

    lines = [
        f"# Compliance Gap Report: {_markdown_text(report.framework)}",
        "",
        f"- **Generated:** {report.generated_at.isoformat()}",
        f"- **Passed:** {report.passed_count}",
        f"- **Failed:** {report.failed_count}",
        "",
        "| Control | Status | Evidence | Remediation |",
        "| --- | --- | --- | --- |",
    ]
    for control in report.controls:
        lines.append(
            f"| {_markdown_text(control.control_id)}: {_markdown_text(control.title)} "
            f"| **{_markdown_text(control.status.upper())}** "
            f"| {_markdown_text(control.evidence)} "
            f"| {_markdown_text(control.remediation)} |"
        )
    return "\n".join(lines) + "\n"


def generate_report(
    incident: Incident,
    risk_score: RiskScore,
    response_plan: Sequence[ResponseAction],
) -> str:
    """Compatibility alias for generating an operational incident report."""

    return generate_incident_report(incident, risk_score, response_plan)


__all__ = [
    "generate_executive_summary",
    "generate_incident_report",
    "generate_report",
    "render_compliance_report",
]