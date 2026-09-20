"""Correlate alerts into deduplicated incidents."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Iterable

from uacda.core.schemas import Alert, Incident, NormalizedEvent


def _event_timestamp(event: NormalizedEvent) -> datetime:
    timestamp = event.timestamp
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _event_fingerprint(event: NormalizedEvent) -> str:
    """Build a stable identity for the same event seen by multiple detectors."""

    payload = event.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


def _event_keys(event: NormalizedEvent) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if event.actor and event.actor.lower() != "unknown":
        keys.add(("actor", event.actor.casefold()))
    if event.asset_id and event.asset_id.lower() != "unknown":
        keys.add(("asset", event.asset_id.casefold()))
    return keys


def _alerts_correlate(first: Alert, second: Alert, time_window: timedelta) -> bool:
    first_fingerprints = {_event_fingerprint(event) for event in first.events}
    second_fingerprints = {_event_fingerprint(event) for event in second.events}
    if first_fingerprints & second_fingerprints:
        return True

    for first_event in first.events:
        for second_event in second.events:
            elapsed = abs(_event_timestamp(first_event) - _event_timestamp(second_event))
            if elapsed > time_window:
                continue
            if _event_keys(first_event) & _event_keys(second_event):
                return True
    return False


def _connected_components(alerts: list[Alert], time_window: timedelta) -> list[list[Alert]]:
    parent = list(range(len(alerts)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first: int, second: int) -> None:
        first_root = find(first)
        second_root = find(second)
        if first_root != second_root:
            parent[second_root] = first_root

    for first_index, first_alert in enumerate(alerts):
        for second_index in range(first_index + 1, len(alerts)):
            if _alerts_correlate(first_alert, alerts[second_index], time_window):
                union(first_index, second_index)

    grouped: dict[int, list[Alert]] = {}
    for index, alert in enumerate(alerts):
        grouped.setdefault(find(index), []).append(alert)
    return list(grouped.values())


def _merge_overlapping_alerts(alerts: list[Alert]) -> list[Alert]:
    """Merge detector alerts that cite at least one identical underlying event."""

    parent = list(range(len(alerts)))

    def find(index: int) -> int:
        if parent[index] != index:
            parent[index] = find(parent[index])
        return parent[index]

    def union(first: int, second: int) -> None:
        first_root = find(first)
        second_root = find(second)
        if first_root != second_root:
            parent[second_root] = first_root

    fingerprints = [{_event_fingerprint(event) for event in alert.events} for alert in alerts]
    for first_index, first_fingerprints in enumerate(fingerprints):
        for second_index in range(first_index + 1, len(alerts)):
            if first_fingerprints & fingerprints[second_index]:
                union(first_index, second_index)

    grouped: dict[int, list[Alert]] = {}
    for index, alert in enumerate(alerts):
        grouped.setdefault(find(index), []).append(alert)

    merged: list[Alert] = []
    for alert_group in grouped.values():
        if len(alert_group) == 1:
            merged.append(alert_group[0])
            continue
        events: list[NormalizedEvent] = []
        seen_events: set[str] = set()
        detector_names: list[str] = []
        descriptions: list[str] = []
        for alert in alert_group:
            if alert.detector_name not in detector_names:
                detector_names.append(alert.detector_name)
            if alert.description and alert.description not in descriptions:
                descriptions.append(alert.description)
            for event in alert.events:
                fingerprint = _event_fingerprint(event)
                if fingerprint not in seen_events:
                    seen_events.add(fingerprint)
                    events.append(event)
        merged.append(
            Alert(
                id=alert_group[0].id,
                events=events,
                detector_name="+".join(detector_names),
                confidence=max(alert.confidence for alert in alert_group),
                description=" ".join(descriptions),
            )
        )
    return merged


def _incident_severity(alerts: list[Alert]) -> str:
    confidence = max((alert.confidence for alert in alerts), default=0.0)
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


def _build_incident(alerts: list[Alert]) -> Incident:
    merged_alerts = _merge_overlapping_alerts(alerts)
    timeline: list[NormalizedEvent] = []
    seen_events: set[str] = set()
    for alert in merged_alerts:
        for event in alert.events:
            fingerprint = _event_fingerprint(event)
            if fingerprint not in seen_events:
                seen_events.add(fingerprint)
                timeline.append(event)
    timeline.sort(key=_event_timestamp)
    affected_assets = list(dict.fromkeys(
        event.asset_id for event in timeline if event.asset_id and event.asset_id.lower() != "unknown"
    ))
    return Incident(
        alerts=merged_alerts,
        severity=_incident_severity(merged_alerts),
        affected_assets=affected_assets,
        status="open",
        timeline=timeline,
    )


def correlate_alerts(
    alerts: Iterable[Alert],
    *,
    time_window: timedelta = timedelta(minutes=30),
) -> list[Incident]:
    """Group related alerts into incidents and deduplicate overlapping evidence."""

    if time_window < timedelta(0):
        raise ValueError("time_window must not be negative")

    unique_alerts: list[Alert] = []
    seen_alert_ids: set[str] = set()
    for alert in alerts:
        if alert.id not in seen_alert_ids:
            seen_alert_ids.add(alert.id)
            unique_alerts.append(alert)

    return [_build_incident(component) for component in _connected_components(unique_alerts, time_window)]


__all__ = ["correlate_alerts"]