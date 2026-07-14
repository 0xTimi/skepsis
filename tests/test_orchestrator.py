from __future__ import annotations

from pathlib import Path

from skepsis import Skepsis
from skepsis.config import Settings


def test_audit_triages_every_finding_concurrently(vulnerable_c: Path) -> None:
    settings = Settings()  # panel defaults to the offline ["mock"]
    settings.max_workers = 4
    report = Skepsis(settings).audit(vulnerable_c, triage=True)

    assert len(report.results) >= 3
    # Every finding was triaged by the panel.
    assert all(r.verdict is not None for r in report.results)


def test_concurrent_triage_output_is_deterministically_ordered(vulnerable_c: Path) -> None:
    settings = Settings()
    settings.max_workers = 4
    report = Skepsis(settings).audit(vulnerable_c, triage=True)

    keys = [
        (r.finding.location.path, r.finding.location.line, r.finding.rule_id)
        for r in report.results
    ]
    # Concurrency must not disturb the stable file/line/rule ordering.
    assert keys == sorted(keys)


def test_audit_without_triage_leaves_verdicts_unset(vulnerable_c: Path) -> None:
    report = Skepsis(Settings()).audit(vulnerable_c, triage=False)
    assert report.results
    assert all(r.verdict is None for r in report.results)


def test_single_worker_matches_multi_worker(vulnerable_c: Path) -> None:
    one = Settings()
    one.max_workers = 1
    many = Settings()
    many.max_workers = 8
    r1 = Skepsis(one).audit(vulnerable_c, triage=True)
    r8 = Skepsis(many).audit(vulnerable_c, triage=True)
    assert [r.finding.id for r in r1.results] == [r.finding.id for r in r8.results]
