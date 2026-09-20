"""Generic checklist-based compliance evaluation for organization settings."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml
from pydantic import BaseModel, ConfigDict, Field

LOGGER = logging.getLogger(__name__)
DEFAULT_ORGANIZATION_CONFIG = Path("config/organization_config.json")
DEFAULT_FRAMEWORK_PATH = Path("config/frameworks/cis_subset.yaml")
_MISSING = object()


class ComplianceControl(BaseModel):
    """Framework-neutral definition of one configuration control."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = ""
    path: str = Field(min_length=1)
    operator: str = "equals"
    expected: Any = None
    evidence: str = ""
    remediation: str = ""


class ControlResult(BaseModel):
    """Pass/fail result and supporting text for one control."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    title: str
    status: str = Field(pattern="^(pass|fail)$")
    evidence: str
    remediation: str


class ComplianceGapReport(BaseModel):
    """Complete framework evaluation, including passing controls and gaps."""

    model_config = ConfigDict(extra="forbid")

    framework: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    controls: list[ControlResult] = Field(default_factory=list)
    passed_count: int = 0
    failed_count: int = 0


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        LOGGER.warning("Unable to load organization configuration %s: %s", path, error)
        return {}
    if not isinstance(payload, dict):
        LOGGER.warning("Organization configuration %s must contain an object", path)
        return {}
    return payload


def _load_framework(path: str | Path) -> tuple[str, list[ComplianceControl]]:
    try:
        payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        LOGGER.warning("Unable to load compliance framework %s: %s", path, error)
        return "unknown", []
    if not isinstance(payload, dict):
        LOGGER.warning("Compliance framework %s must contain a mapping", path)
        return "unknown", []
    framework_name = str(payload.get("framework", Path(path).stem))
    raw_controls = payload.get("controls", [])
    if not isinstance(raw_controls, list):
        LOGGER.warning("Compliance framework %s controls must be a list", path)
        return framework_name, []
    controls: list[ComplianceControl] = []
    for raw_control in raw_controls:
        try:
            if isinstance(raw_control, dict):
                controls.append(ComplianceControl.model_validate(raw_control))
        except (TypeError, ValueError) as error:
            LOGGER.warning("Ignoring malformed compliance control: %s", error)
    return framework_name, controls


def _get_path(config: Mapping[str, Any], path: str) -> Any:
    current: Any = config
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _matches(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "exists":
        return actual is not _MISSING and actual is not None
    if actual is _MISSING:
        return False
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "contains":
        try:
            return expected in actual
        except TypeError:
            return False
    if operator in {"gt", "gte", "lt", "lte"}:
        try:
            return {
                "gt": actual > expected,
                "gte": actual >= expected,
                "lt": actual < expected,
                "lte": actual <= expected,
            }[operator]
        except TypeError:
            return False
    LOGGER.warning("Unknown compliance operator %s", operator)
    return False


def _display(value: Any) -> str:
    if value is _MISSING:
        return "missing"
    return json.dumps(value, sort_keys=True, default=str)


def check_framework(
    organization_config: Mapping[str, Any],
    framework: Mapping[str, Any],
) -> ComplianceGapReport:
    """Evaluate a framework mapping against an in-memory organization mapping."""

    framework_name = str(framework.get("framework", "unknown"))
    raw_controls = framework.get("controls", [])
    controls: list[ComplianceControl] = [
        ComplianceControl.model_validate(control)
        for control in raw_controls
        if isinstance(control, dict)
    ]
    results: list[ControlResult] = []
    for control in controls:
        actual = _get_path(organization_config, control.path)
        passed = _matches(actual, control.operator, control.expected)
        status = "pass" if passed else "fail"
        evidence_prefix = control.evidence or f"Checked {control.path}."
        evidence = (
            f"{evidence_prefix} Observed {_display(actual)}; expected "
            f"{control.operator} {_display(control.expected)}."
        )
        remediation = "No remediation required." if passed else control.remediation
        results.append(
            ControlResult(
                control_id=control.id,
                title=control.title,
                status=status,
                evidence=evidence,
                remediation=remediation,
            )
        )
    passed_count = sum(result.status == "pass" for result in results)
    return ComplianceGapReport(
        framework=framework_name,
        controls=results,
        passed_count=passed_count,
        failed_count=len(results) - passed_count,
    )


def check_compliance(
    organization_config_path: str | Path = DEFAULT_ORGANIZATION_CONFIG,
    framework_path: str | Path = DEFAULT_FRAMEWORK_PATH,
) -> ComplianceGapReport:
    """Load files and produce a framework-neutral compliance gap report."""

    organization_config = _load_json(organization_config_path)
    try:
        framework_payload = yaml.safe_load(Path(framework_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        LOGGER.warning("Unable to load compliance framework %s: %s", framework_path, error)
        framework_payload = {"framework": "unknown", "controls": []}
    if not isinstance(framework_payload, dict):
        framework_payload = {"framework": "unknown", "controls": []}
    return check_framework(organization_config, framework_payload)


__all__ = [
    "ComplianceControl",
    "ComplianceGapReport",
    "ControlResult",
    "check_compliance",
    "check_framework",
]