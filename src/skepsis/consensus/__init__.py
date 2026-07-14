"""Multi-model consensus triage (Stage 2 of the Skepsis pipeline)."""

from __future__ import annotations

from skepsis.consensus.aggregate import aggregate
from skepsis.consensus.debate import DebatePanel
from skepsis.consensus.providers import build_panel, build_provider

__all__ = ["DebatePanel", "aggregate", "build_panel", "build_provider"]
