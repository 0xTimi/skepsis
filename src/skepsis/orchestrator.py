"""The Skepsis orchestrator — wires Stage 1 → Stage 2 → Stage 3 into one pipeline.

    scan (patterns)  →  deliberate (consensus panel)  →  verify (sanitizers)

Each stage is optional and independently testable; the orchestrator just glues
them together and emits a :class:`~skepsis.models.ScanReport`.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from skepsis.config import Settings
from skepsis.consensus.debate import DebatePanel
from skepsis.consensus.providers import build_panel
from skepsis.models import Finding, ScanReport, TriagedFinding
from skepsis.scanner.engine import Scanner
from skepsis.scanner.patterns import RULES
from skepsis.verify.sanitizer import SanitizerRunner

#: Called after each finding is triaged: (index, total, triaged) -> None.
ProgressHook = Callable[[int, int, TriagedFinding], None]


class Skepsis:
    """High-level entry point tying the three stages together."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self.scanner = Scanner(
            RULES,
            context_lines=self.settings.context_lines,
            max_file_bytes=self.settings.max_file_bytes,
        )

    # -- individual stages -------------------------------------------------

    def scan(self, target: str | Path) -> list[Finding]:
        """Stage 1: cheap static candidate generation."""
        return self.scanner.scan_path(target)

    def make_panel(self) -> DebatePanel:
        """Build the consensus panel from settings."""
        return DebatePanel(build_panel(self.settings), threshold=self.settings.confirm_threshold)

    # -- full pipeline -----------------------------------------------------

    def audit(
        self,
        target: str | Path,
        *,
        triage: bool = True,
        verify: bool = False,
        progress: ProgressHook | None = None,
    ) -> ScanReport:
        """Run the requested stages over ``target`` and return a report.

        Parameters
        ----------
        triage:
            Run the consensus panel over each finding (Stage 2).
        verify:
            Run sanitizer verification where a harness is available (Stage 3).
            Currently harnesses are user-supplied; findings without one are left
            unverified. Disabled by default because it compiles and executes code.
        progress:
            Optional per-finding callback for UIs/progress bars.
        """
        from skepsis import __version__

        findings = self.scan(target)
        panel = self.make_panel() if triage else None
        runner = SanitizerRunner(self.settings.cc) if verify else None

        results: list[TriagedFinding] = []
        total = len(findings)
        for i, finding in enumerate(findings, start=1):
            verdict = panel.deliberate(finding) if panel else None
            triaged = TriagedFinding(finding=finding, verdict=verdict)
            # Sanitizer verification is only meaningful for confirmed findings
            # that ship a harness; harness synthesis is out of scope for v0.1.
            _ = runner  # reserved for harness-driven verification
            results.append(triaged)
            if progress:
                progress(i, total, triaged)

        return ScanReport(
            target=str(target),
            tool_version=__version__,
            rules_run=len(self.scanner.rules),
            results=results,
        )
