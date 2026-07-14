"""Reporting backends: console, markdown, SARIF."""

from __future__ import annotations

from skepsis.report.console import render as render_console
from skepsis.report.markdown import to_markdown
from skepsis.report.sarif import dumps as to_sarif_json
from skepsis.report.sarif import to_sarif

__all__ = ["render_console", "to_markdown", "to_sarif", "to_sarif_json"]
