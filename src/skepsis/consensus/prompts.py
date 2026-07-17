"""Prompt templates for the three adversarial reviewer roles.

Each role is asked to return the *same* JSON shape::

    {"verdict": <bool>, "confidence": <0..1>, "rationale": "<one or two sentences>"}

``verdict`` is normalized so that **True always argues in favour of the bug being
real** — reachable / impactful / genuinely-a-bug — which lets the aggregator
combine the three opinions without special-casing any role.
"""

from __future__ import annotations

from skepsis.models import Finding, Role

_JSON_CONTRACT = (
    'Respond with ONLY a JSON object: {"verdict": true|false, '
    '"confidence": 0.0-1.0, "rationale": "<=2 sentences"}.'
)

ROLE_SYSTEM: dict[Role, str] = {
    Role.REACHABILITY: (
        "You are a program-analysis expert judging REACHABILITY. Decide whether "
        "attacker-controlled input can actually flow into the flagged sink. "
        "verdict=true means it is reachable by untrusted data. " + _JSON_CONTRACT
    ),
    Role.IMPACT: (
        "You are an exploitation expert judging IMPACT. Assuming the sink is "
        "reached with hostile input, decide whether the result is a "
        "security-relevant memory-safety violation (OOB write/read, corruption). "
        "Crucially, compare the MAXIMUM possible index/length against the "
        "destination's ALLOCATION SIZE: a buffer that is deliberately over-allocated "
        "(e.g. calloc(4, w*h)) may fully absorb the write — if so the impact is not "
        "real. verdict=true means the impact is security-relevant. " + _JSON_CONTRACT
    ),
    Role.FALSE_POSITIVE: (
        "You are a skeptical senior reviewer hunting FALSE POSITIVES. Argue as hard "
        "as you can that the finding is NOT a real vulnerability: guarded by a check, "
        "unreachable, constant-bounded, dead code, OR the destination buffer is "
        "over-allocated relative to the maximum index/length written (compare the "
        "allocation size to the worst-case write). Then give your honest verdict: "
        "verdict=true means it IS a genuine bug despite your scrutiny; "
        "verdict=false means it is a false positive. " + _JSON_CONTRACT
    ),
}


def build_user_prompt(finding: Finding) -> str:
    """Render the finding into a compact, self-contained review request."""
    taint = finding.tainted_symbol or "(unknown)"
    return (
        f"Finding {finding.rule_id} — {finding.title} ({finding.cwe})\n"
        f"File: {finding.location}\n"
        f"Suspected tainted symbol: {taint}\n"
        f"Detector note: {finding.message}\n\n"
        f"Source context:\n{finding.snippet}\n"
    )
