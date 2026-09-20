"""Parser registry and automatic file-type detection for log ingestion."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Final

from uacda.core.schemas import NormalizedEvent
from uacda.log_ingestion.parsers import (
    parse_jsonl,
    parse_syslog,
    parse_vulnerability_csv,
    parse_windows_event_xml,
)

LOGGER = logging.getLogger(__name__)
Parser = Callable[[str | Path], list[NormalizedEvent]]

PARSER_REGISTRY: Final[dict[str, Parser]] = {
    ".jsonl": parse_jsonl,
    ".ndjson": parse_jsonl,
    ".csv": parse_vulnerability_csv,
    ".xml": parse_windows_event_xml,
    ".log": parse_syslog,
    ".syslog": parse_syslog,
}


def register_parser(extension: str, parser: Parser) -> None:
    """Register or replace a parser for an extension."""

    normalized_extension = extension.lower()
    if not normalized_extension.startswith("."):
        normalized_extension = f".{normalized_extension}"
    PARSER_REGISTRY[normalized_extension] = parser


def _looks_like_jsonl(text: str) -> bool:
    for line in text.splitlines():
        if line.strip():
            try:
                return isinstance(json.loads(line), dict)
            except json.JSONDecodeError:
                return False
    return False


def _looks_like_windows_event_xml(text: str) -> bool:
    return text.lstrip().startswith("<") and "<Event" in text


def _looks_like_vulnerability_csv(text: str) -> bool:
    header = next((line.lower() for line in text.splitlines() if line.strip()), "")
    return "," in header and any(
        field in header for field in ("vulnerability", "plugin", "asset_id", "hostname", "cve")
    )


def detect_parser(path: str | Path) -> Parser:
    """Choose a parser using extension first, then lightweight content detection."""

    input_path = Path(path)
    extension_parser = PARSER_REGISTRY.get(input_path.suffix.lower())
    if extension_parser is not None:
        return extension_parser

    try:
        text = input_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as error:
        LOGGER.warning("Unable to inspect input for parser detection %s: %s", path, error)
        return parse_syslog

    if _looks_like_windows_event_xml(text):
        return parse_windows_event_xml
    if _looks_like_jsonl(text):
        return parse_jsonl
    if _looks_like_vulnerability_csv(text):
        return parse_vulnerability_csv
    return parse_syslog


def load_events(path: str | Path, parser: Parser | None = None) -> list[NormalizedEvent]:
    """Load normalized events using an explicit parser or automatic detection."""

    selected_parser = parser or detect_parser(path)
    try:
        return selected_parser(path)
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        LOGGER.warning("Unable to load events from %s: %s", path, error)
        return []


__all__ = ["PARSER_REGISTRY", "Parser", "detect_parser", "load_events", "register_parser"]