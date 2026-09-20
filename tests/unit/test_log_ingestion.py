"""Independent unit-test boundary for log ingestion."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from uacda.log_ingestion.loader import load_events
from uacda.log_ingestion.parsers import (
	parse_jsonl,
	parse_syslog,
	parse_vulnerability_csv,
	parse_windows_event_xml,
)


class LogIngestionParserTests(unittest.TestCase):
	"""Verify each supported source becomes resilient normalized events."""

	def test_syslog_parser_skips_malformed_lines(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "events.log"
			path.write_text(
				"Jan 02 03:04:05 web01 sshd: Failed password for alice\n"
				"not a syslog record\n",
				encoding="utf-8",
			)

			with self.assertLogs("uacda.log_ingestion", level="WARNING"):
				events = parse_syslog(path)

		self.assertEqual(len(events), 1)
		self.assertEqual(events[0].asset_id, "web01")
		self.assertEqual(events[0].actor, "alice")

	def test_jsonl_parser_preserves_raw_record(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "audit.jsonl"
			path.write_text(
				'{"timestamp":"2026-01-02T03:04:05Z","user":"alice",'
				'"resource":"bucket-1","eventName":"GetObject"}\n'
				"malformed\n",
				encoding="utf-8",
			)

			events = parse_jsonl(path)

		self.assertEqual(len(events), 1)
		self.assertEqual(events[0].action, "GetObject")
		self.assertEqual(events[0].raw_data["resource"], "bucket-1")

	def test_windows_xml_parser_reads_system_and_event_data(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "events.xml"
			path.write_text(
				"<Events><Event><System>"
				'<Provider Name="Microsoft-Windows-Security-Auditing"/>'
				"<EventID>4624</EventID>"
				'<TimeCreated SystemTime="2026-01-02T03:04:05.000Z"/>'
				"<Computer>workstation-1</Computer>"
				'<Execution UserID="S-1-5-18"/>'
				"</System><EventData>"
				'<Data Name="TargetUserName">alice</Data>'
				"</EventData></Event></Events>",
				encoding="utf-8",
			)

			events = parse_windows_event_xml(path)

		self.assertEqual(len(events), 1)
		self.assertEqual(events[0].asset_id, "workstation-1")
		self.assertEqual(events[0].action, "4624")
		self.assertEqual(events[0].metadata["event_data"]["TargetUserName"], "alice")

	def test_csv_parser_and_loader_content_detection(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "scan.unknown"
			path.write_text(
				"hostname,vulnerability,severity,detected_at\n"
				"db01,Outdated OpenSSL,high,2026-01-02T03:04:05Z\n"
				",Missing host,high,2026-01-02T03:04:05Z\n",
				encoding="utf-8",
			)

			events = load_events(path)

		self.assertEqual(len(events), 1)
		self.assertEqual(events[0].source_type, "vulnerability_scanner")
		self.assertEqual(events[0].asset_id, "db01")
		self.assertEqual(events[0].metadata["severity"], "high")

	def test_csv_parser_handles_missing_header(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "empty.csv"
			path.write_text("", encoding="utf-8")

			with self.assertLogs("uacda.log_ingestion", level="WARNING"):
				events = parse_vulnerability_csv(path)

		self.assertEqual(events, [])
