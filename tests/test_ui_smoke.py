"""Smoke tests for the isolated UACDA Streamlit presentation layer."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from uacda.core.orchestrator import run_pipeline
from ui.app import (
    render_approval_queue,
    render_copilot,
    render_dashboard,
    render_incident_detail,
    render_reports,
)


class _Column:
    def button(self, *args, **kwargs):
        return False


class _Sidebar:
    def radio(self, label, options):
        return options[0]


class FakeStreamlit:
    """Small Streamlit surface sufficient to smoke-test page render functions."""

    def __init__(self):
        self.session_state = {}
        self.sidebar = _Sidebar()

    def __getattr__(self, name):
        def no_op(*args, **kwargs):
            if name == "selectbox":
                return args[1][0]
            if name == "text_input":
                return ""
            if name == "columns":
                return [_Column(), _Column()]
            return None
        return no_op

    def columns(self, count):
        return [_Column() for _ in range(count)]

    def selectbox(self, label, options, **kwargs):
        return options[0]

    def text_input(self, label, **kwargs):
        return ""


class UiSmokeTests(unittest.TestCase):
    def test_page_render_functions_accept_latest_pipeline_result(self):
        workspace = Path(__file__).parents[1]
        samples = workspace / "data" / "samples"
        paths = [
            samples / "sample_syslog.log",
            samples / "cloud_audit.jsonl",
            samples / "vulnerability_scan.csv",
            samples / "clean.eml",
            samples / "phishing.eml",
            samples / "ambiguous.eml",
        ]
        with tempfile.TemporaryDirectory() as directory:
            result = run_pipeline(paths, audit_log_path=Path(directory) / "agent-audit.jsonl")

        st = FakeStreamlit()
        render_dashboard(st, result)
        render_incident_detail(st, result)
        render_approval_queue(st, result)
        render_copilot(st, result)
        render_reports(st, result)


if __name__ == "__main__":
    unittest.main()
