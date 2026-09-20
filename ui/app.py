"""Streamlit presentation layer for the existing UACDA pipeline."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from uacda.core.orchestrator import OrchestrationResult, run_pipeline
from uacda.core.schemas import Incident
from uacda.reporting.report_generator import generate_executive_summary
from uacda.response_planner.planner import ResponseAction
from uacda.soc_copilot.chat import answer_question

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "data" / "samples"
UI_APPROVAL_LOG = Path(__file__).resolve().parent / "approval_log.jsonl"
SAMPLE_INPUTS = [
    SAMPLES / "sample_syslog.log",
    SAMPLES / "cloud_audit.jsonl",
    SAMPLES / "vulnerability_scan.csv",
    SAMPLES / "clean.eml",
    SAMPLES / "phishing.eml",
    SAMPLES / "ambiguous.eml",
]


def run_latest_pipeline() -> OrchestrationResult | None:
    """Run the backend orchestrator as a black box for the sample workspace."""

    try:
        return run_pipeline(SAMPLE_INPUTS)
    except Exception as error:  # UI failures must become visible state, not crashes.
        return None


def dashboard_rows(result: OrchestrationResult) -> list[dict[str, Any]]:
    """Convert backend incidents and risk scores into sortable dashboard rows."""

    rows = []
    for incident in result.incidents:
        risk_score = result.risk_scores.get(incident.id)
        rows.append(
            {
                "id": incident.id,
                "severity": incident.severity,
                "affected_assets": ", ".join(incident.affected_assets) or "None",
                "status": incident.status,
                "risk_score": risk_score.final_score if risk_score else 0.0,
            }
        )
    return sorted(rows, key=lambda row: row["risk_score"], reverse=True)


def pending_actions(result: OrchestrationResult) -> list[tuple[str, ResponseAction]]:
    """Return response actions that require human approval."""

    pending = []
    for incident_id, actions in result.response_plans.items():
        for action in actions:
            if action.requires_human_approval:
                pending.append((incident_id, action))
    return pending


def _safe_call(st: Any, callback: Any, error_message: str) -> Any:
    try:
        return callback()
    except Exception as error:
        st.error(f"{error_message}: {error}")
        return None


def _incident_by_id(result: OrchestrationResult, incident_id: str) -> Incident | None:
    return next((incident for incident in result.incidents if incident.id == incident_id), None)


def render_dashboard(st: Any, result: OrchestrationResult) -> None:
    """Render the incident dashboard from the latest orchestrator result."""

    st.header("Dashboard")
    rows = dashboard_rows(result)
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No incidents were produced by the latest run.")


def render_incident_detail(st: Any, result: OrchestrationResult) -> None:
    """Render alerts, events, risk, and actions for a selected incident."""

    st.header("Incident Detail")
    if not result.incidents:
        st.info("No incidents available.")
        return
    incident_ids = [incident.id for incident in result.incidents]
    selected_id = st.selectbox("Incident", incident_ids)
    incident = _incident_by_id(result, selected_id)
    if incident is None:
        st.error("The selected incident is no longer available.")
        return

    st.subheader(f"{incident.id} · {incident.severity}")
    st.write({"status": incident.status, "affected_assets": incident.affected_assets})
    st.subheader("Alerts")
    for alert in incident.alerts:
        st.write({
            "detector": alert.detector_name,
            "confidence": alert.confidence,
            "description": alert.description,
        })
    st.subheader("Normalized Events")
    st.json([event.model_dump(mode="json") for event in incident.timeline])
    risk_score = result.risk_scores.get(incident.id)
    if risk_score:
        st.subheader("Risk Score")
        st.write(risk_score.model_dump())
        st.caption(risk_score.rationale)
    st.subheader("Response Plan")
    for action in result.response_plans.get(incident.id, []):
        label = "pending approval" if action.requires_human_approval else "informational"
        st.write(f"{action.order}. {action.action} [{label}]")


def _write_approval_decision(incident_id: str, action: ResponseAction, decision: str) -> None:
    """Write only UI approval state; never touch the agent audit log."""

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "action_order": action.order,
        "action": action.action,
        "decision": decision,
        "executed": False,
    }
    UI_APPROVAL_LOG.parent.mkdir(parents=True, exist_ok=True)
    with UI_APPROVAL_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def render_approval_queue(st: Any, result: OrchestrationResult) -> None:
    """Render approval actions with local-only approve/reject state changes."""

    st.header("Approval Queue")
    pending = pending_actions(result)
    if not pending:
        st.info("No actions are awaiting human approval.")
        return
    statuses = st.session_state.setdefault("approval_status", {})
    for index, (incident_id, action) in enumerate(pending):
        key = f"{incident_id}:{action.order}"
        current_status = statuses.get(key, "pending approval")
        st.write(f"**{incident_id}** · {action.action}")
        st.caption(f"Status: {current_status} · No system action is executed by this UI.")
        approve, reject = st.columns(2)
        if approve.button("Approve", key=f"approve-{index}"):
            statuses[key] = "approved locally"
            _safe_call(st, lambda: _write_approval_decision(incident_id, action, "approved locally"), "Could not log approval")
        if reject.button("Reject", key=f"reject-{index}"):
            statuses[key] = "rejected locally"
            _safe_call(st, lambda: _write_approval_decision(incident_id, action, "rejected locally"), "Could not log rejection")


def render_copilot(st: Any, result: OrchestrationResult) -> None:
    """Pass an analyst question directly to the existing SOC Copilot function."""

    st.header("SOC Copilot")
    if not result.incidents:
        st.info("No incident is available for chat.")
        return
    incident_id = st.selectbox("Incident context", [incident.id for incident in result.incidents], key="copilot-incident")
    question = st.text_input("Ask about this incident")
    if question:
        incident = _incident_by_id(result, incident_id)
        if incident is not None:
            response = _safe_call(
                st,
                lambda: answer_question(question, incident),
                "SOC Copilot could not answer",
            )
            if response is not None:
                st.markdown(response)


def render_reports(st: Any, result: OrchestrationResult) -> None:
    """Render backend-generated Markdown reports and executive summaries."""

    st.header("Reports")
    if not result.incidents:
        st.info("No reports are available.")
        return
    incident_id = st.selectbox("Report", [incident.id for incident in result.incidents], key="report-incident")
    incident = _incident_by_id(result, incident_id)
    risk_score = result.risk_scores.get(incident_id)
    if incident is None or risk_score is None:
        st.error("The selected report is unavailable.")
        return
    st.markdown(result.reports.get(incident_id, "No incident report available."))
    st.subheader("Executive Summary")
    summary = _safe_call(
        st,
        lambda: generate_executive_summary(incident, risk_score),
        "Could not generate executive summary",
    )
    if summary is not None:
        st.write(summary)


def render_app(st: Any, result: OrchestrationResult) -> None:
    """Render one selected presentation view using an injected Streamlit-like object."""

    view = st.sidebar.radio(
        "View",
        ["Dashboard", "Incident Detail", "Approval Queue", "SOC Copilot", "Reports"],
    )
    renderers = {
        "Dashboard": render_dashboard,
        "Incident Detail": render_incident_detail,
        "Approval Queue": render_approval_queue,
        "SOC Copilot": render_copilot,
        "Reports": render_reports,
    }
    renderers[view](st, result)


def main() -> None:
    """Start the Streamlit application."""

    import streamlit as st

    st.set_page_config(page_title="UACDA SOC Console", layout="wide")
    st.title("UACDA SOC Console")
    st.caption("Presentation layer only - backend actions are never executed here")
    result = run_latest_pipeline()
    if result is None:
        st.error("The latest UACDA pipeline run failed. Check the backend logs and try again.")
        return
    render_app(st, result)


if __name__ == "__main__":
    main()
