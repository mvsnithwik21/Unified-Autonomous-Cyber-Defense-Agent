# UACDA - Unified Autonomous Cyber Defense Agent

## Project Overview

UACDA is a Python-based cybersecurity analysis pipeline that turns heterogeneous security logs and email messages into explainable alerts, correlated incidents, prioritized risk scores, approval-aware response plans, compliance gap reports, and Markdown incident reports. It addresses the operational problem of fragmented security evidence: analysts need to normalize data from different sources, detect threats consistently, understand why an incident was raised, prioritize the work, and preserve a traceable record without allowing automated containment actions to bypass human review.

## Architecture

The implementation is organized as independently testable Python packages:

1. **`core/`** - Shared contracts and infrastructure used across UACDA modules, including Pydantic schemas, configuration, logging, and orchestration.
2. **`log_ingestion/`** - Ingests security events from logs and normalizes them into UACDA contracts.
3. **`detection_engine/`** - Evaluates normalized events against detection rules and analytic strategies.
4. **`phishing_analysis/`** - Analyzes messages, links, and attachments for phishing indicators.
5. **`correlation_engine/`** - Correlates detections and events into incidents and attack narratives.
6. **`risk_prioritization/`** - Ranks security findings and incidents by risk and business impact.
7. **`response_planner/`** - Plans defensive actions for prioritized incidents and findings.
8. **`soc_copilot/`** - Provides the SOC analyst chat interface and conversational workflows.
9. **`compliance_audit/`** - Evaluates security activity and evidence against compliance requirements.
10. **`reporting/`** - Generates operational, executive, and compliance-facing security reports.
11. **`core/orchestrator.py`** - Wires the ingestion-to-report pipeline with auditable decisions.

## End-to-End Workflow

```text
Ingest -> Detect -> Correlate -> Prioritize -> Respond -> Report
```

- **Ingest:** Read syslog, JSONL cloud audit logs, CSV vulnerability exports, and `.eml` files into normalized events.
- **Detect:** Run deterministic detectors and optionally use a pluggable LLM for lower-confidence events. Analyze `.eml` files for phishing signals.
- **Correlate:** Group related alerts by actor, asset, time window, or overlapping evidence into deduplicated incidents.
- **Prioritize:** Calculate explainable 0-100 risk scores using detection confidence, asset criticality, and business impact.
- **Respond:** Select severity-specific playbook actions and mark disruptive actions for human approval.
- **Report:** Produce Markdown incident reports, executive summaries, compliance reports, and JSONL audit records.

## Setup

UACDA is tested with Python 3.14.7 and requires Python 3.11 or newer.

From the repository root in PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the test suite with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Run the Sample Pipeline

The repository includes synthetic inputs under [`data/samples/`](data/samples/):

- `sample_syslog.log`
- `cloud_audit.jsonl`
- `vulnerability_scan.csv`
- `clean.eml`
- `phishing.eml`
- `ambiguous.eml`

The orchestrator is a Python API. Run it from PowerShell with:

```powershell
@'
from pathlib import Path
from uacda.core.orchestrator import run_pipeline

samples = Path("data/samples")
result = run_pipeline([
    samples / "sample_syslog.log",
    samples / "cloud_audit.jsonl",
    samples / "vulnerability_scan.csv",
    samples / "clean.eml",
    samples / "phishing.eml",
    samples / "ambiguous.eml",
])

print(f"Events: {len(result.events)}")
print(f"Alerts: {len(result.alerts)}")
print(f"Incidents: {len(result.incidents)}")
print(f"Phishing verdicts: {len(result.phishing_verdicts)}")
print(f"Compliance gaps: {result.compliance_report.failed_count if result.compliance_report else 0}")
print(f"Reports: {len(result.reports)}")
'@ | .\.venv\Scripts\python.exe -
```

Expected output includes approximately:

```text
Events: 13
Alerts: 3
Incidents: 3
Phishing verdicts: 3
Compliance gaps: 3
Reports: 3
```

The exact incident identifiers and audit timestamps are generated at runtime. Structured decisions are appended to [`audit_log.jsonl`](audit_log.jsonl), which is intentionally excluded from version control because it is a runtime artifact.

## Configuration

- [`config/organization_config.json`](config/organization_config.json) contains simulated organization settings for compliance checks.
- [`config/frameworks/cis_subset.yaml`](config/frameworks/cis_subset.yaml) contains the example CIS controls. The checker accepts the same generic control shape for NIST, ISO, or another YAML checklist.
- [`config/asset_inventory.json`](config/asset_inventory.json) maps asset IDs to criticality tiers from 1 to 5.
- [`config/playbooks.yaml`](config/playbooks.yaml) maps inferred incident types and severities to ordered response actions.

## Reliability & Guardrails

- **Human approval gate:** `HUMAN_APPROVAL_REQUIRED` is enabled by default. Actions such as isolating a host, revoking credentials, or blocking an indicator are never executed by the orchestrator. They are recorded as `pending approval` with `executed: false`; informational actions are also logged without execution.
- **Evidence-bounded reasoning:** LLM-generated detection alerts and SOC copilot answers must cite source events. Unsupported or uncited LLM output is discarded or reported as `insufficient evidence`.
- **Graceful ingestion:** Malformed log records are logged as warnings and skipped so one bad record does not stop the pipeline.
- **Explainability:** Every major decision records a timestamp, stage, detector name, confidence, evidence references, and decision details in `audit_log.jsonl`.
- **Deterministic reports:** Incident reports include timelines, alert evidence, risk rationale, affected assets, approval status, and confidence notes. Compliance reports list every control with pass/fail status, observed evidence, and remediation text.

## Project Status

The repository is scaffolded for incremental implementation and currently includes working ingestion, detection, phishing analysis, correlation, risk scoring, response planning, SOC chat, compliance auditing, reporting, and orchestration components.
