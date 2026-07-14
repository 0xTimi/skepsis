from __future__ import annotations

import json

from skepsis.models import (
    Finding,
    Location,
    ScanReport,
    Severity,
    TriagedFinding,
    Verdict,
    VulnClass,
)
from skepsis.report import to_markdown, to_sarif


def _report(confirmed: bool = True) -> ScanReport:
    finding = Finding(
        id="abc123",
        rule_id="SKEP-UF01",
        vuln_class=VulnClass.UNBOUNDED_FIELD,
        severity=Severity.CRITICAL,
        title="memcpy with non-constant length",
        message="unbounded copy",
        location=Location(path="canparse.c", line=27, column=5),
        snippet="> 27 | memcpy(out, pdu + 1, len);",
        tainted_symbol="len",
    )
    verdict = Verdict(
        finding_id="abc123", confirmed=confirmed, confidence=0.87, summary="CONFIRMED"
    )
    return ScanReport(
        target="lib",
        tool_version="0.1.0",
        rules_run=8,
        results=[TriagedFinding(finding=finding, verdict=verdict)],
    )


def test_sarif_is_valid_shape() -> None:
    doc = to_sarif(_report())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Skepsis"
    result = run["results"][0]
    assert result["ruleId"] == "SKEP-UF01"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 27
    # round-trips through json
    json.dumps(doc)


def test_sarif_excludes_rejected_by_default() -> None:
    doc = to_sarif(_report(confirmed=False))
    assert doc["runs"][0]["results"] == []


def test_markdown_contains_finding() -> None:
    md = to_markdown(_report())
    assert "SKEP-UF01" in md
    assert "Confirmed findings" in md
    assert "CWE-787" in md


def test_markdown_empty_report() -> None:
    md = to_markdown(_report(confirmed=False))
    assert "No findings survived" in md
