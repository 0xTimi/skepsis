"""The Skepsis orchestrator — wires Stage 1 → Stage 2 → Stage 3 into one pipeline.

    scan (patterns)  →  deliberate (consensus panel)  →  verify (sanitizers)

Each stage is optional and independently testable; the orchestrator just glues
them together and emits a :class:`~skepsis.models.ScanReport`.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        _ = runner  # reserved for harness-driven verification (Stage 3)

        if panel is None:
            results = [TriagedFinding(finding=f) for f in findings]
        else:
            results = self._triage_concurrently(findings, panel, progress)

        # Deterministic output order regardless of triage completion order.
        results.sort(
            key=lambda t: (t.finding.location.path, t.finding.location.line, t.finding.rule_id)
        )
        return ScanReport(
            target=str(target),
            tool_version=__version__,
            rules_run=len(self.scanner.rules),
            results=results,
        )

    def _triage_concurrently(
        self,
        findings: list[Finding],
        panel: DebatePanel,
        progress: ProgressHook | None,
    ) -> list[TriagedFinding]:
        """Deliberate over findings in parallel.

        Provider calls are blocking network I/O, so a thread pool gives a near
        linear speedup — crucial when each finding costs three sequential model
        calls against a slow endpoint.
        """
        results: list[TriagedFinding] = []
        total = len(findings)
        workers = max(1, min(self.settings.max_workers, total or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(panel.deliberate, f): f for f in findings}
            for done, future in enumerate(as_completed(futures), start=1):
                finding = futures[future]
                triaged = TriagedFinding(finding=finding, verdict=future.result())
                results.append(triaged)
                if progress:
                    progress(done, total, triaged)
        return results
