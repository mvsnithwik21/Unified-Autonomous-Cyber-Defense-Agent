"""Deterministic threat detectors operating on normalized security events."""

from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from uacda.core.schemas import Alert, NormalizedEvent

LOGGER = logging.getLogger(__name__)

_FAILED_LOGIN_TERMS = ("failed", "failure", "denied", "invalid", "unauthorized")
_LOGIN_TERMS = ("login", "logon", "sign-in", "signin", "authentication", "authenticate")
_SUCCESS_TERMS = ("success", "succeeded", "accepted", "authenticated")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)


def _timestamp(event: NormalizedEvent) -> datetime:
    value = event.timestamp
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _event_text(event: NormalizedEvent) -> str:
    """Flatten event values for format-independent action matching."""

    values: list[str] = [event.action]

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                values.append(str(key))
                collect(nested)
        elif isinstance(value, (list, tuple, set)):
            for nested in value:
                collect(nested)
        elif value is not None:
            values.append(str(value))

    collect(event.raw_data)
    collect(event.metadata)
    return " ".join(values).lower()


def _is_login_failure(event: NormalizedEvent) -> bool:
    text = _event_text(event)
    return any(term in text for term in _LOGIN_TERMS) and any(term in text for term in _FAILED_LOGIN_TERMS)


def _is_login_success(event: NormalizedEvent) -> bool:
    text = _event_text(event)
    return (
        any(term in text for term in _LOGIN_TERMS)
        and any(term in text for term in _SUCCESS_TERMS)
        and not _is_login_failure(event)
    )


def _alert(detector_name: str, events: Iterable[NormalizedEvent], confidence: float, description: str) -> Alert:
    return Alert(
        events=list(events),
        detector_name=detector_name,
        confidence=max(0.0, min(1.0, confidence)),
        description=description,
    )


def detect_repeated_failed_logins(
    events: Iterable[NormalizedEvent],
    *,
    threshold: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Alert]:
    """Detect repeated failed logins by actor and asset within a time window."""

    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    grouped: defaultdict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if _is_login_failure(event):
            grouped[(event.actor, event.asset_id)].append(event)

    alerts: list[Alert] = []
    for (actor, asset_id), failures in grouped.items():
        ordered = sorted(failures, key=_timestamp)
        for end_index, end_event in enumerate(ordered):
            start_index = end_index
            while start_index > 0 and _timestamp(end_event) - _timestamp(ordered[start_index - 1]) <= window:
                start_index -= 1
            burst = ordered[start_index : end_index + 1]
            if len(burst) >= threshold:
                confidence = min(1.0, 0.75 + 0.05 * (len(burst) - threshold))
                alerts.append(
                    _alert(
                        "repeated_failed_logins",
                        burst,
                        confidence,
                        f"{len(burst)} failed login attempts for {actor} against {asset_id} "
                        f"within {window.total_seconds() / 60:g} minutes.",
                    )
                )
                break
    return alerts


def _coordinates(event: NormalizedEvent) -> tuple[float, float, str] | None:
    candidates: list[Any] = [event.metadata, event.raw_data]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        for key in ("geolocation", "geo", "location"):
            nested = candidate.get(key)
            if isinstance(nested, dict):
                candidate = nested
                break
        latitude = candidate.get("latitude", candidate.get("lat"))
        longitude = candidate.get("longitude", candidate.get("lon", candidate.get("lng")))
        if latitude is None or longitude is None:
            continue
        try:
            label = str(candidate.get("country", candidate.get("city", ""))).strip().lower()
            return float(latitude), float(longitude), label
        except (TypeError, ValueError):
            continue
    return None


def _distance_km(first: tuple[float, float], second: tuple[float, float]) -> float:
    """Return great-circle distance using the Haversine formula."""

    latitude_one, longitude_one = map(math.radians, first)
    latitude_two, longitude_two = map(math.radians, second)
    delta_latitude = latitude_two - latitude_one
    delta_longitude = longitude_two - longitude_one
    value = (
        math.sin(delta_latitude / 2) ** 2
        + math.cos(latitude_one) * math.cos(latitude_two) * math.sin(delta_longitude / 2) ** 2
    )
    return 6371.0 * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


def detect_impossible_travel(
    events: Iterable[NormalizedEvent],
    *,
    minimum_distance_km: float = 500.0,
    maximum_speed_kmh: float = 900.0,
    maximum_window: timedelta = timedelta(hours=24),
) -> list[Alert]:
    """Detect successful logins from new locations that imply impossible travel."""

    grouped: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if _is_login_success(event) and _coordinates(event) is not None:
            grouped[event.actor].append(event)

    alerts: list[Alert] = []
    for actor, logins in grouped.items():
        ordered = sorted(logins, key=_timestamp)
        for previous, current in zip(ordered, ordered[1:]):
            previous_coordinates = _coordinates(previous)
            current_coordinates = _coordinates(current)
            if previous_coordinates is None or current_coordinates is None:
                continue
            elapsed = _timestamp(current) - _timestamp(previous)
            if elapsed < timedelta(0) or elapsed > maximum_window:
                continue
            distance = _distance_km(previous_coordinates[:2], current_coordinates[:2])
            hours = max(elapsed.total_seconds() / 3600, 1 / 3600)
            speed = distance / hours
            new_location = (
                current_coordinates[2] != previous_coordinates[2]
                if current_coordinates[2] and previous_coordinates[2]
                else distance >= minimum_distance_km
            )
            if new_location and distance >= minimum_distance_km and speed >= maximum_speed_kmh:
                alerts.append(
                    _alert(
                        "impossible_travel",
                        [previous, current],
                        0.95,
                        f"{actor} logged in from locations approximately {distance:.0f} km apart "
                        f"in {elapsed} ({speed:.0f} km/h).",
                    )
                )
    return alerts


def detect_outside_typical_hours(
    events: Iterable[NormalizedEvent],
    *,
    baseline_events: Iterable[NormalizedEvent] | None = None,
    minimum_baseline_events: int = 3,
) -> list[Alert]:
    """Detect user logins outside the user's frequently observed hourly baseline."""

    current_logins = [event for event in events if _is_login_success(event)]
    baseline_logins = [event for event in (baseline_events if baseline_events is not None else current_logins) if _is_login_success(event)]
    baseline_by_actor: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in baseline_logins:
        baseline_by_actor[event.actor].append(event)

    typical_hours: dict[str, set[int]] = {}
    for actor, actor_events in baseline_by_actor.items():
        if len(actor_events) < minimum_baseline_events:
            continue
        counts = Counter(_timestamp(event).hour for event in actor_events)
        minimum_count = max(2, math.ceil(len(actor_events) * 0.5))
        typical_hours[actor] = {hour for hour, count in counts.items() if count >= minimum_count}

    alerts: list[Alert] = []
    for event in current_logins:
        actor_hours = typical_hours.get(event.actor, set())
        if actor_hours and _timestamp(event).hour not in actor_hours:
            alerts.append(
                _alert(
                    "outside_typical_hours",
                    [event],
                    0.82,
                    f"Successful login for {event.actor} at {_timestamp(event):%H:%M UTC}, "
                    f"outside the typical hours {sorted(actor_hours)}.",
                )
            )
    return alerts


def _normalize_ioc(value: Any) -> str:
    text = str(value).strip().strip("'").strip('"').lower()
    if "://" in text:
        parsed = urlsplit(text)
        text = parsed.hostname or text
    return text.rstrip(".")


def load_ioc_list(path: str | Path) -> set[str]:
    """Load IPs and domains from a JSON IOC list in common list/dict shapes."""

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        LOGGER.warning("Unable to load IOC list %s: %s", path, error)
        return set()

    values: list[Any] = []
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict):
        for key in ("ips", "ip_addresses", "domains", "indicators", "iocs"):
            candidate = payload.get(key, [])
            values.extend(candidate if isinstance(candidate, list) else [candidate])
    iocs: set[str] = set()
    for value in values:
        if isinstance(value, dict):
            value = value.get("value", value.get("indicator"))
        if value:
            iocs.add(_normalize_ioc(value))
    return iocs


def _event_indicators(event: NormalizedEvent) -> set[str]:
    values: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for nested in value.values():
                collect(nested)
        elif isinstance(value, (list, tuple, set)):
            for nested in value:
                collect(nested)
        elif value is not None:
            values.append(str(value))

    collect(event.raw_data)
    collect(event.metadata)
    indicators: set[str] = set()
    for value in values:
        indicators.add(_normalize_ioc(value))
        indicators.update(_normalize_ioc(match) for match in _IP_PATTERN.findall(value))
        indicators.update(_normalize_ioc(match) for match in _DOMAIN_PATTERN.findall(value))
        try:
            indicators.add(str(ip_address(value.strip())))
        except ValueError:
            pass
    return indicators


def detect_ioc_matches(events: Iterable[NormalizedEvent], ioc_path: str | Path) -> list[Alert]:
    """Create alerts for events containing an IP or domain in a local IOC list."""

    iocs = load_ioc_list(ioc_path)
    if not iocs:
        return []
    alerts: list[Alert] = []
    for event in events:
        matches = _event_indicators(event) & iocs
        if matches:
            alerts.append(
                _alert(
                    "known_ioc_match",
                    [event],
                    0.99,
                    f"Event matched known malicious indicator(s): {', '.join(sorted(matches))}.",
                )
            )
    return alerts


def run_rule_detectors(
    events: Iterable[NormalizedEvent],
    *,
    ioc_path: str | Path | None = None,
    baseline_events: Iterable[NormalizedEvent] | None = None,
) -> list[Alert]:
    """Run all deterministic detectors and return their alerts."""

    event_list = list(events)
    alerts = [
        *detect_repeated_failed_logins(event_list),
        *detect_impossible_travel(event_list),
        *detect_outside_typical_hours(event_list, baseline_events=baseline_events),
    ]
    if ioc_path is not None:
        alerts.extend(detect_ioc_matches(event_list, ioc_path))
    return alerts


__all__ = [
    "detect_ioc_matches",
    "detect_impossible_travel",
    "detect_outside_typical_hours",
    "detect_repeated_failed_logins",
    "load_ioc_list",
    "run_rule_detectors",
]