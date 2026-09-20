# UACDA Architecture

UACDA is organized as independently testable packages around shared Pydantic contracts. Implemented modules transform source files into `NormalizedEvent` objects, produce `Alert` objects, correlate alerts into `Incident` objects, calculate `RiskScore` objects, create approval-aware `ResponseAction` plans, and render reports. The modules in `domain.py`, `application.py`, `ports.py`, and `adapters.py` are currently scaffold boundaries: their module docstrings define responsibility, but they do not yet expose public implementation symbols.

## Shared Contracts

### `uacda.core.schemas`

This is the stable data boundary used throughout the pipeline.

| Symbol | Description | Main inputs and outputs |
| --- | --- | --- |
| `NormalizedEvent` | Canonical security event. | Fields include `timestamp`, `source_type`, `actor`, `asset_id`, `action`, `raw_data`, and `metadata`. Parsers and analyzers create it; detection, correlation, scoring, and reporting consume it. |
| `Alert` | Detection result containing evidence and detector assessment. | Contains an `id`, `events: list[NormalizedEvent]`, `detector_name`, `confidence` from 0 to 1, and `description`. Detectors and phishing analysis produce it; correlation consumes it. |
| `Incident` | Correlated security case assembled from related alerts. | Contains `alerts: list[Alert]`, `severity`, `affected_assets`, `status`, and `timeline: list[NormalizedEvent]`. Correlation produces it; scoring, planning, and reporting consume it. |
| `RiskScore` | Explainable risk assessment. | Contains component scores, `final_score` from 0 to 100, and `rationale`. Risk prioritization produces it; reporting consumes it. |

The models reject unknown fields and validate assignments. Collection fields use isolated defaults so separate events, alerts, and incidents do not share mutable state.

## Core

### `uacda.core.orchestrator`

**Responsibility:** Wire the ingestion-to-report pipeline with auditable decisions.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `HUMAN_APPROVAL_REQUIRED` | Enabled safety flag for response actions. | A boolean consumed by the orchestration approval gate. |
| `OrchestrationResult` | Container for all artifacts from one pipeline run. | Holds normalized events, alerts, incidents, `risk_scores`, response plans, Markdown reports, phishing verdicts, and an optional `ComplianceGapReport`. |
| `run_pipeline(input_paths, ...)` | Runs ingestion, detection, `.eml` analysis, correlation, risk scoring, planning, compliance auditing, and reporting. | Accepts source paths plus optional LLM, IOC, inventory, playbook, framework, organization-config, and audit-log paths. Returns `OrchestrationResult`. |
| `orchestrate(...)` | Compatibility alias for `run_pipeline`. | Same inputs and output as `run_pipeline`. |

The orchestrator appends structured JSON objects to `audit_log.jsonl` for ingestion, detection, correlation, risk, response planning, compliance, phishing analysis, and reporting decisions. It does not execute response actions.

### `uacda.core.config`

**Responsibility:** Application configuration and environment-backed settings for UACDA.

This file currently contains only its responsibility docstring and no public functions or classes.

### `uacda.core.logging`

**Responsibility:** Shared logging configuration and structured logging helpers for UACDA.

This file currently contains only its responsibility docstring and no public functions or classes. The orchestrator currently owns its append-only JSONL audit writer.

## Log Ingestion

### `uacda.log_ingestion.parsers`

**Responsibility:** Convert supported source formats into `NormalizedEvent` objects.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `parse_syslog(path)` | Parse RFC 3164-style syslog text and skip malformed lines with warnings. | Reads a text file and returns `list[NormalizedEvent]`. |
| `parse_jsonl(path)` | Parse newline-delimited JSON cloud audit records and skip malformed lines. | Reads JSON objects line by line and returns `list[NormalizedEvent]`. |
| `parse_windows_event_xml(path)` | Parse Windows Event Log XML exports. | Reads XML and returns `list[NormalizedEvent]`; malformed XML or event records are logged and skipped. |
| `parse_vulnerability_csv(path)` | Parse vulnerability scanner CSV findings. | Reads CSV rows and returns `list[NormalizedEvent]`; rows without an asset or vulnerability identifier are skipped. |

Each parser preserves source content in `raw_data` and format-specific context in `metadata` where applicable.

### `uacda.log_ingestion.loader`

**Responsibility:** Select and invoke a parser using file extension or lightweight content detection.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `PARSER_REGISTRY` | Mapping from extensions such as `.jsonl`, `.csv`, `.xml`, and `.log` to parser callables. | Maps file suffixes to functions returning `list[NormalizedEvent]`. |
| `Parser` | Callable type alias for parser functions. | Accepts `str | Path`; returns `list[NormalizedEvent]`. |
| `register_parser(extension, parser)` | Add or replace an extension parser. | Accepts an extension and a `Parser`; mutates the registry. |
| `detect_parser(path)` | Choose a parser from extension, then content. | Accepts a path; returns a `Parser`. |
| `load_events(path, parser=None)` | Load events with an explicit or detected parser. | Accepts a path and optional parser; returns `list[NormalizedEvent]`. Load failures are logged and return an empty list. |

### `uacda.log_ingestion.domain`

**Responsibility:** Domain concepts and invariants for security log ingestion.

Currently a docstring-only boundary with no public implementation symbols.

### `uacda.log_ingestion.application`

**Responsibility:** Use cases for accepting, parsing, and normalizing security log events.

Currently a docstring-only boundary with no public implementation symbols. The implemented loader and parsers provide the current ingestion behavior.

### `uacda.log_ingestion.ports`

**Responsibility:** Interfaces required by log ingestion use cases and external sources.

Currently a docstring-only boundary with no public implementation symbols.

### `uacda.log_ingestion.adapters`

**Responsibility:** External log readers and format adapters for the ingestion boundary.

Currently a docstring-only boundary with no public implementation symbols.

## Detection Engine

### `uacda.detection_engine.rules`

**Responsibility:** Apply deterministic threat detectors to normalized events.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `detect_repeated_failed_logins(events, threshold=5, window=10 minutes)` | Detect repeated failed logins grouped by actor and asset. | Accepts `Iterable[NormalizedEvent]`; returns brute-force `list[Alert]`. |
| `detect_impossible_travel(events, ...)` | Detect successful logins from new or distant locations at implausible speed. | Accepts `Iterable[NormalizedEvent]`; returns `list[Alert]`. Geolocation is read from event metadata or raw data. |
| `detect_outside_typical_hours(events, baseline_events=None, ...)` | Detect successful logins outside frequently observed per-user hours. | Accepts current and optional baseline `NormalizedEvent` iterables; returns `list[Alert]`. |
| `load_ioc_list(path)` | Load IPs/domains from common JSON IOC list shapes. | Accepts a JSON path; returns `set[str]`. Invalid files produce a warning and an empty set. |
| `detect_ioc_matches(events, ioc_path)` | Match event values against the local IOC list. | Accepts events and an IOC path; returns `list[Alert]` with detector name `known_ioc_match`. |
| `run_rule_detectors(events, ioc_path=None, baseline_events=None)` | Run all deterministic detectors. | Accepts normalized events and optional IOC/baseline inputs; returns `list[Alert]`. |

### `uacda.detection_engine.llm_reasoner`

**Responsibility:** Use a pluggable LLM to reason about events that deterministic rules did not confidently flag while retaining source evidence.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `LLMProvider` | Protocol for an LLM adapter. | `complete(prompt)` accepts a string and returns JSON text or a mapping. |
| `LLMAnalysis` | Validated LLM result. | Contains `suspicious`, bounded `confidence`, `description`, and `supporting_event_ids`. |
| `build_reasoning_prompt(events)` | Build a structured prompt with stable `event-*` IDs. | Accepts `Sequence[NormalizedEvent]`; returns a JSON prompt string. |
| `reason_about_events(events, provider, ...)` | Call the provider and create an alert only when confidence and citations are valid. | Accepts events and an `LLMProvider`; returns `list[Alert]` whose events are the cited source events. |
| `merge_detections(events, provider=None, ioc_path=None, ...)` | Merge rule alerts with LLM alerts for remaining candidates. | Accepts `Sequence[NormalizedEvent]`; returns `list[Alert]`. |

### `uacda.detection_engine.domain`, `application`, `ports`, `adapters`

These modules respectively document threat-detection concepts, detection use cases, external interfaces, and integration adapters. They are currently docstring-only boundaries; the implemented behavior resides in `rules.py` and `llm_reasoner.py`.

## Phishing Analysis

### `uacda.phishing_analysis.analyzer`

**Responsibility:** Analyze raw RFC 5322 email messages for phishing indicators.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `PhishingVerdict` | Pydantic result for an email analysis. | Contains `verdict` (`phishing`, `suspicious`, or `clean`), bounded `confidence`, and evidence strings. |
| `analyze_eml(path, known_brands=...)` | Parse headers, body URLs, authentication results, reply-to domains, and attachments. | Accepts an `.eml` path; returns `PhishingVerdict`. |
| `DEFAULT_KNOWN_BRANDS` | Default brand names used by URL similarity checks. | Tuple of brand strings consumed by `analyze_eml`. |

The analyzer does not emit a `NormalizedEvent` directly. The orchestrator converts non-clean verdicts into an email event and a `phishing_analysis` `Alert`.

### `uacda.phishing_analysis.domain`, `application`, `ports`, `adapters`

These modules document phishing-analysis concepts, use cases, provider interfaces, and external integrations. They are currently docstring-only boundaries; `analyzer.py` contains the implemented path-based analysis.

## Correlation Engine

### `uacda.correlation_engine.correlator`

**Responsibility:** Correlate alerts and deduplicate their underlying evidence into incidents.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `correlate_alerts(alerts, time_window=30 minutes)` | Build transitive alert groups when alerts share actor or asset within the time window, or share an event fingerprint. | Accepts `Iterable[Alert]`; returns `list[Incident]`. Duplicate alert IDs are ignored. |

The resulting `Incident.alerts` merges detector alerts that overlap on underlying events, while `Incident.timeline` contains each normalized event once. Affected assets are derived from the deduplicated timeline.

### `uacda.correlation_engine.domain`, `application`, `ports`, `adapters`

These modules document incident concepts, correlation use cases, storage/stream interfaces, and external adapters. They are currently docstring-only boundaries; `correlator.py` contains the implemented correlation logic.

## Risk Prioritization

### `uacda.risk_prioritization.scorer`

**Responsibility:** Calculate explainable risk scores and rank incidents by business risk.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `load_asset_inventory(path)` | Load an asset-to-criticality-tier mapping and discard invalid tiers. | Accepts JSON path; returns `dict[str, int]` with tiers from 1 to 5. |
| `score_incident(incident, asset_inventory=None, inventory_path=...)` | Calculate an incident `RiskScore`. | Accepts an `Incident` and optional inventory; returns `RiskScore` with component values, a 0-100 final score, and rationale. |
| `rank_incidents(incidents, asset_inventory=None, inventory_path=...)` | Score and sort incidents from highest to lowest final score. | Accepts `Iterable[Incident]`; returns `list[tuple[Incident, RiskScore]]`. |

Scoring maps maximum alert confidence to exploitability and combines exploitability, asset criticality, and business impact with weights of 40%, 35%, and 25% respectively.

### `uacda.risk_prioritization.domain`, `application`, `ports`, `adapters`

These modules document risk concepts, prioritization use cases, scoring interfaces, and external integrations. They are currently docstring-only boundaries; `scorer.py` contains the implemented scoring logic.

## Response Planner

### `uacda.response_planner.planner`

**Responsibility:** Translate incident type and severity into ordered, approval-aware response actions.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `ResponseAction` | Pydantic representation of one recommended step. | Contains `order`, `action`, `rationale`, and `requires_human_approval`. |
| `load_playbooks(path)` | Load the YAML playbook mapping. | Accepts a YAML path; returns a mapping of playbooks. |
| `infer_incident_type(incident)` | Infer a playbook key from alert detector names and descriptions. | Accepts an `Incident`; returns a string such as `brute_force`, `phishing`, `malware`, `impossible_travel`, or `generic`. |
| `plan_response(incident, playbook_path=...)` | Select severity actions and interpolate incident context. | Accepts an `Incident`; returns ordered `list[ResponseAction]`. |
| `create_plan(incident, playbook_path=...)` | Compatibility alias for `plan_response`. | Same input and output as `plan_response`. |

The planner only creates recommendations. The orchestrator records approval-required actions as pending and does not execute them.

### `uacda.response_planner.domain`, `application`, `ports`, `adapters`

These modules document response concepts, planning use cases, action/approval interfaces, and external execution adapters. They are currently docstring-only boundaries; `planner.py` contains the implemented playbook lookup.

## SOC Copilot

### `uacda.soc_copilot.chat`

**Responsibility:** Provide evidence-bounded analyst chat for one incident.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `ChatProvider` | Protocol for hosted, local, or test LLM adapters. | `complete(prompt)` accepts a prompt and returns JSON text or a mapping. |
| `ChatResponse` | Validated answer shape. | Contains an `answer` and event-ID `citations`. |
| `configure_provider(provider)` | Set the process-wide default chat provider. | Accepts a `ChatProvider` or `None`; returns `None`. |
| `answer_question(question, incident, provider=None)` | Ask a natural-language question using only the incident context. | Accepts a question and `Incident`; returns a string with `Sources: event-*` citations or `insufficient evidence`. |

### `uacda.soc_copilot.domain`, `application`, `ports`, `adapters`

These modules document conversation concepts, chat workflows, model/tool interfaces, and transport integrations. They are currently docstring-only boundaries; `chat.py` contains the implemented evidence-bounded behavior.

## Compliance Audit

### `uacda.compliance_audit.checker`

**Responsibility:** Evaluate organization settings against a framework-neutral YAML checklist.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `ComplianceControl` | Generic checklist control definition. | Contains control identity, dotted config `path`, comparison `operator`, `expected` value, evidence text, and remediation text. |
| `ControlResult` | Pass/fail result for one control. | Contains `control_id`, title, `status`, evidence, and remediation. |
| `ComplianceGapReport` | Complete framework evaluation. | Contains framework name, generation time, control results, and passed/failed counts. |
| `check_framework(organization_config, framework)` | Evaluate in-memory mappings. | Accepts organization and checklist mappings; returns `ComplianceGapReport`. |
| `check_compliance(organization_config_path, framework_path)` | Load JSON organization settings and YAML framework files, then evaluate them. | Accepts file paths; returns `ComplianceGapReport`. |

The control format is not CIS-specific. Current comparison operators include `equals`, `not_equals`, `contains`, `exists`, `gt`, `gte`, `lt`, and `lte`, allowing another framework checklist to use the same engine.

### `uacda.compliance_audit.domain`, `application`, `ports`, `adapters`

These modules document compliance concepts, audit use cases, evidence/control interfaces, and external adapters. They are currently docstring-only boundaries; `checker.py` contains the implemented checklist evaluation.

## Reporting

### `uacda.reporting.report_generator`

**Responsibility:** Generate operational, executive, and compliance-facing Markdown reports.

| Public symbol | Description | Inputs and outputs |
| --- | --- | --- |
| `generate_incident_report(incident, risk_score, response_plan)` | Render Summary, Timeline, Evidence, Severity & Rationale, Affected Assets, Recommended Actions, and Confidence Notes. | Accepts `Incident`, `RiskScore`, and `Sequence[ResponseAction]`; returns Markdown `str`. |
| `generate_report(...)` | Compatibility alias for `generate_incident_report`. | Same inputs and Markdown output. |
| `generate_executive_summary(incident, risk_score)` | Render a four-sentence non-technical summary. | Accepts `Incident` and `RiskScore`; returns Markdown/plain text `str`. |
| `render_compliance_report(report)` | Render control status, evidence, remediation, and counts. | Accepts `ComplianceGapReport`; returns Markdown `str`. |

Reports assign stable `event-*` labels to deduplicated incident events and preserve response approval markers in the action section.

### `uacda.reporting.domain`, `application`, `ports`, `adapters`

These modules document report concepts, report assembly use cases, rendering/publication interfaces, and delivery adapters. They are currently docstring-only boundaries; `report_generator.py` contains the implemented renderers.

## Data Flow

```text
source files
    |
    v
load_events() / analyze_eml()
    |
    v
NormalizedEvent + phishing Alert
    |
    v
run_rule_detectors() + optional LLM reasoning
    |
    v
Alert
    |
    v
correlate_alerts()
    |
    v
Incident
    |
    +--> score_incident() ------> RiskScore
    |
    +--> plan_response() -------> ResponseAction list
    |
    +--> generate_incident_report() -> Markdown
    |
    +--> check_compliance() ----> ComplianceGapReport
```

The orchestrator also appends stage decisions and evidence references to `audit_log.jsonl` throughout this flow.
