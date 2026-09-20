"""Format-specific parsers that normalize security records into UACDA events."""

from __future__ import annotations

import csv
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from uacda.core.schemas import NormalizedEvent

LOGGER = logging.getLogger(__name__)

_SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<message>.+)$"
)
_SYSLOG_MONTHS = {month: index for index, month in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
    start=1,
)}


def _read_text(path: str | Path) -> str:
    """Read a text input with a predictable encoding for all parsers."""

    return Path(path).read_text(encoding="utf-8-sig", errors="replace")


def _parse_timestamp(value: Any, *, default: datetime | None = None) -> datetime:
    """Parse common timestamp representations and return a timezone-aware value."""

    if isinstance(value, datetime):
        parsed = value
    elif value is None or str(value).strip() == "":
        parsed = default or datetime.now(timezone.utc)
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        parsed = datetime.fromisoformat(text)

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first_value(record: dict[str, Any], *names: str, default: str = "unknown") -> str:
    """Return the first non-empty value for a set of alternate field names."""

    lowered = {str(key).strip().lower(): value for key, value in record.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _event_from_record(
    record: dict[str, Any],
    *,
    source_type: str,
    timestamp_names: tuple[str, ...] = (),
    actor_names: tuple[str, ...] = (),
    asset_names: tuple[str, ...] = (),
    action_names: tuple[str, ...] = (),
    metadata: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """Map a format-specific record to the shared event contract."""

    timestamp_value = next(
        (record.get(name) for name in timestamp_names if record.get(name) not in (None, "")),
        None,
    )
    return NormalizedEvent(
        timestamp=_parse_timestamp(timestamp_value),
        source_type=source_type,
        actor=_first_value(record, *actor_names),
        asset_id=_first_value(record, *asset_names),
        action=_first_value(record, *action_names),
        raw_data=record,
        metadata=metadata or {},
    )


def parse_syslog(path: str | Path) -> list[NormalizedEvent]:
    """Parse RFC 3164-style syslog text, skipping malformed lines."""

    events: list[NormalizedEvent] = []
    for line_number, line in enumerate(_read_text(path).splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        match = _SYSLOG_PATTERN.match(text)
        if not match:
            LOGGER.warning("Skipping malformed syslog line %s:%d", path, line_number)
            continue
        values = match.groupdict()
        try:
            timestamp = datetime(
                datetime.now(timezone.utc).year,
                _SYSLOG_MONTHS[values["month"]],
                int(values["day"]),
                *map(int, values["time"].split(":")),
                tzinfo=timezone.utc,
            )
            message = values["message"]
            process, separator, detail = message.partition(":")
            action = process if separator else message.split(maxsplit=1)[0]
            actor_match = re.search(r"\bfor\s+(\S+)", message, flags=re.IGNORECASE)
            events.append(
                NormalizedEvent(
                    timestamp=timestamp,
                    source_type="syslog",
                    actor=actor_match.group(1) if actor_match else "unknown",
                    asset_id=values["host"],
                    action=action,
                    raw_data={"line": text, "message": message},
                    metadata={"process": process.strip()} if separator else {},
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            LOGGER.warning("Skipping malformed syslog line %s:%d: %s", path, line_number, error)
    return events


def parse_jsonl(path: str | Path) -> list[NormalizedEvent]:
    """Parse newline-delimited JSON audit records, skipping malformed lines."""

    events: list[NormalizedEvent] = []
    for line_number, line in enumerate(_read_text(path).splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("record must be a JSON object")
            events.append(
                _event_from_record(
                    record,
                    source_type="cloud_audit",
                    timestamp_names=("timestamp", "time", "@timestamp", "eventTime"),
                    actor_names=("actor", "user", "username", "principal", "userIdentity"),
                    asset_names=("asset_id", "asset", "host", "hostname", "resource", "resource_id"),
                    action_names=("action", "event_action", "eventName", "operation"),
                    metadata=record.get("metadata") if isinstance(record.get("metadata"), dict) else {},
                )
            )
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            LOGGER.warning("Skipping malformed JSON audit line %s:%d: %s", path, line_number, error)
    return events


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", maxsplit=1)[-1]


def _xml_text(element: ET.Element | None) -> str | None:
    return element.text.strip() if element is not None and element.text else None


def parse_windows_event_xml(path: str | Path) -> list[NormalizedEvent]:
    """Parse Windows Event Log XML exports, skipping invalid event records."""

    try:
        root = ET.fromstring(_read_text(path))
    except (ET.ParseError, OSError) as error:
        LOGGER.warning("Skipping malformed Windows Event XML %s: %s", path, error)
        return []

    event_elements = [element for element in root.iter() if _xml_local_name(element.tag) == "Event"]
    events: list[NormalizedEvent] = []
    for event_number, event_element in enumerate(event_elements, start=1):
        try:
            system = next(
                (child for child in event_element if _xml_local_name(child.tag) == "System"),
                None,
            )
            if system is None:
                raise ValueError("missing System element")
            provider = next((child for child in system if _xml_local_name(child.tag) == "Provider"), None)
            event_id_element = next((child for child in system if _xml_local_name(child.tag) == "EventID"), None)
            time_created = next((child for child in system if _xml_local_name(child.tag) == "TimeCreated"), None)
            computer = next((child for child in system if _xml_local_name(child.tag) == "Computer"), None)
            execution = next((child for child in system if _xml_local_name(child.tag) == "Execution"), None)
            data: dict[str, Any] = {}
            for data_element in event_element.iter():
                if _xml_local_name(data_element.tag) == "Data":
                    name = data_element.attrib.get("Name", f"data_{len(data)}")
                    data[name] = _xml_text(data_element) or ""
            record = {
                "provider": provider.attrib.get("Name", "unknown") if provider is not None else "unknown",
                "event_id": _xml_text(event_id_element) or "unknown",
                "timestamp": time_created.attrib.get("SystemTime") if time_created is not None else None,
                "computer": _xml_text(computer) or "unknown",
                "user_id": execution.attrib.get("UserID", "unknown") if execution is not None else "unknown",
                "event_data": data,
            }
            events.append(
                _event_from_record(
                    record,
                    source_type="windows_event_log",
                    timestamp_names=("timestamp",),
                    actor_names=("user_id",),
                    asset_names=("computer",),
                    action_names=("event_id",),
                    metadata={"provider": record["provider"], "event_data": data},
                )
            )
        except (TypeError, ValueError, KeyError) as error:
            LOGGER.warning("Skipping malformed Windows Event %s:%d: %s", path, event_number, error)
    return events


def parse_vulnerability_csv(path: str | Path) -> list[NormalizedEvent]:
    """Parse CSV vulnerability scanner findings, skipping malformed rows."""

    events: list[NormalizedEvent] = []
    try:
        with Path(path).open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                LOGGER.warning("Skipping vulnerability CSV without a header: %s", path)
                return events
            for row_number, row in enumerate(reader, start=2):
                try:
                    if not any(str(value or "").strip() for value in row.values()):
                        continue
                    asset_id = _first_value(row, "asset_id", "asset", "host", "hostname", "ip", "ip_address")
                    action = _first_value(row, "vulnerability", "title", "name", "plugin", "plugin_name")
                    if asset_id == "unknown" or action == "unknown":
                        raise ValueError("missing asset or vulnerability identifier")
                    metadata = {
                        key: row[key]
                        for key in ("severity", "cve", "cvss", "scanner")
                        if row.get(key)
                    }
                    events.append(
                        _event_from_record(
                            row,
                            source_type="vulnerability_scanner",
                            timestamp_names=("timestamp", "detected_at", "discovered_at", "scan_time"),
                            actor_names=("scanner", "scanner_name"),
                            asset_names=("asset_id", "asset", "host", "hostname", "ip", "ip_address"),
                            action_names=("vulnerability", "title", "name", "plugin", "plugin_name"),
                            metadata=metadata,
                        )
                    )
                except (TypeError, ValueError, KeyError) as error:
                    LOGGER.warning("Skipping malformed vulnerability row %s:%d: %s", path, row_number, error)
    except (OSError, csv.Error) as error:
        LOGGER.warning("Skipping unreadable vulnerability CSV %s: %s", path, error)
    return events


__all__ = [
    "parse_jsonl",
    "parse_syslog",
    "parse_vulnerability_csv",
    "parse_windows_event_xml",
]