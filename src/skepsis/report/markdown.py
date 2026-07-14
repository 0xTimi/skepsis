"""Markdown report — good for PR comments, issues, and audit write-ups."""

from __future__ import annotations

from skepsis.models import ScanReport, Severity, TriagedFinding

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def to_markdown(report: ScanReport) -> str:
    confirmed = report.confirmed
    lines: list[str] = []
    lines.append(f"# Skepsis audit — `{report.target}`\n")
    lines.append(_summary_table(report))
    lines.append("")

    if not confirmed:
        lines.append("_No findings survived multi-model consensus._\n")
        return "\n".join(lines)

    lines.append("## Confirmed findings\n")
    for t in sorted(confirmed, key=lambda x: x.finding.severity.rank, reverse=True):
        lines.append(_finding_block(t))
    return "\n".join(lines)


def _summary_table(report: ScanReport) -> str:
    counts = {
        sev: len([t for t in report.confirmed if t.finding.severity is sev]) for sev in Severity
    }
    rows = [
        "| Metric | Count |",
        "| --- | --- |",
        f"| Rules run | {report.rules_run} |",
        f"| Candidates | {len(report.results)} |",
        f"| **Confirmed** | **{len(report.confirmed)}** |",
    ]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        rows.append(f"| {_SEV_EMOJI[sev]} {sev.value.title()} | {counts[sev]} |")
    return "\n".join(rows)


def _finding_block(t: TriagedFinding) -> str:
    f = t.finding
    emoji = _SEV_EMOJI[f.severity]
    out = [
        f"### {emoji} {f.title} — `{f.rule_id}` ({f.cwe})",
        "",
        f"- **Severity:** {f.severity.value}",
        f"- **Location:** `{f.location}`",
    ]
    if f.tainted_symbol:
        out.append(f"- **Tainted symbol:** `{f.tainted_symbol}`")
    if t.verdict:
        out.append(f"- **Consensus:** {t.verdict.summary}")
    if t.sanitizer:
        s = t.sanitizer
        status = "✅ reproduced" if s.reproduced else f"{s.crashes}/{s.runs} crashed"
        detail = f" — `{s.first_error}`" if s.first_error else ""
        out.append(f"- **Sanitizer:** {status}{detail}")
    out.append("")
    out.append(f"> {f.message}")
    out.append("")
    out.append("```c")
    out.append(f.snippet)
    out.append("```")
    if t.verdict and t.verdict.opinions:
        out.append("")
        out.append("<details><summary>Panel opinions</summary>\n")
        for op in t.verdict.opinions:
            vote = "✔" if op.verdict else "✘"
            out.append(
                f"- **{op.role.value}** ({op.model}) {vote} {op.confidence:.0%} — {op.rationale}"
            )
        out.append("\n</details>")
    out.append("")
    return "\n".join(out)
