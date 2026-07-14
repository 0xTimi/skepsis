"""Skepsis — multi-model consensus + sanitizer verification for C/C++ memory bugs.

The public API mirrors the pipeline stages so the tool can be embedded as a
library:

    from skepsis import Skepsis, load_settings

    engine = Skepsis(load_settings())
    report = engine.audit("path/to/library")
"""

from __future__ import annotations

from skepsis.config import Settings, load_settings
from skepsis.models import (
    Finding,
    ScanReport,
    Severity,
    TriagedFinding,
    Verdict,
    VulnClass,
)
from skepsis.orchestrator import Skepsis

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "ScanReport",
    "Settings",
    "Severity",
    "Skepsis",
    "TriagedFinding",
    "Verdict",
    "VulnClass",
    "__version__",
    "load_settings",
]
