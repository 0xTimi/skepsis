"""SARIF 2.1.0 export so results drop straight into GitHub code scanning et al.

Only confirmed findings (or all, if ``include_rejected``) are emitted. Each
finding becomes a ``result`` and each rule a reusable ``reportingDescriptor``.
"""

from __future__ import annotations

import json
from typing import Any

from skepsis.models import ScanReport, Severity, TriagedFinding

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(report: ScanReport, *, include_rejected: bool = False) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log object from a scan report."""
    results = report.results if include_rejected else report.confirmed
    rules = _collect_rules(results)
    rule_index = {rid: i for i, rid in enumerate(rules)}

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Skepsis",
                        "informationUri": "https://github.com/0xTimi/skepsis",
                        "version": report.tool_version,
                        "rules": [rules[rid] for rid in rules],
                    }
                },
                "results": [_result(t, rule_index) for t in results],
            }
        ],
    }


def _collect_rules(results: list[TriagedFinding]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for t in results:
        f = t.finding
        if f.rule_id in rules:
            continue
        rules[f.rule_id] = {
            "id": f.rule_id,
            "name": f.title.replace(" ", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.message},
            "properties": {"tags": [f.vuln_class.value, f.cwe], "cwe": f.cwe},
        }
    return rules


def _result(t: TriagedFinding, rule_index: dict[str, int]) -> dict[str, Any]:
    f = t.finding
    confidence = t.verdict.confidence if t.verdict else 0.0
    text = f.message
    if t.verdict:
        text = f"{text}\n\nConsensus: {t.verdict.summary}"
    if t.sanitizer and t.sanitizer.reproduced:
        text = f"{text}\n\nSanitizer: reproduced ({t.sanitizer.crashes}/{t.sanitizer.runs} runs)."
    return {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index[f.rule_id],
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.path},
                    "region": {"startLine": f.location.line, "startColumn": f.location.column},
                }
            }
        ],
        "properties": {
            "severity": f.severity.value,
            "vulnClass": f.vuln_class.value,
            "consensusConfidence": round(confidence, 3),
            "confirmed": t.is_confirmed,
        },
    }


def dumps(report: ScanReport, *, include_rejected: bool = False, indent: int = 2) -> str:
    return json.dumps(to_sarif(report, include_rejected=include_rejected), indent=indent)
