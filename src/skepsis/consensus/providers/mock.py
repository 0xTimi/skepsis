"""A deterministic, offline provider.

Its purpose is threefold:

1. Let the *entire* pipeline run (and be tested) with no API keys or network.
2. Give new users an instant, free demo of the tool's behaviour.
3. Serve as the reference implementation of the provider contract.

The verdicts are derived from cheap, transparent heuristics over the prompt — it
is emphatically **not** a real reviewer, but it produces stable, plausible output
so the plumbing around it can be exercised end to end.
"""

from __future__ import annotations

import hashlib
from typing import Any


class MockProvider:
    """Rule-of-thumb reviewer with no external dependencies."""

    def __init__(self, name: str = "mock") -> None:
        self.name = name

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        role = _role_from_system(system)
        text = user.lower()

        # A stable pseudo-random lever in [0, 1) seeded by the finding text, so
        # results are reproducible across runs but vary between findings.
        jitter = _seed_unit(user)

        has_bounds_check = any(k in text for k in ("if (", "assert", "min(", "sizeof", "<= "))
        looks_tainted = any(
            k in text for k in ("packet", "buf", "len", "recv", "input", "msg", "frame", "payload")
        )
        is_constant = "sizeof" in text or "0x" in text

        if role == "false-positive":
            # Argue it is NOT a real bug. verdict=True means "genuinely a bug".
            is_bug = looks_tainted and not (has_bounds_check and jitter < 0.5)
            confidence = 0.55 + 0.4 * jitter
            rationale = (
                "A nearby bounds check plausibly constrains the value."
                if has_bounds_check
                else "No guarding check is visible on the surrounding lines."
            )
            return _op(is_bug, confidence, rationale)

        if role == "reachability":
            reachable = looks_tainted and not is_constant
            confidence = 0.5 + 0.45 * jitter
            rationale = (
                "The sink argument name suggests externally-derived data."
                if looks_tainted
                else "No evidence the value is attacker-controlled."
            )
            return _op(reachable, confidence, rationale)

        # impact
        impactful = looks_tainted
        confidence = 0.5 + 0.4 * jitter
        rationale = (
            "Out-of-bounds write to a memcpy/strcpy sink is typically exploitable."
            if "memcpy" in text or "strcpy" in text
            else "Impact bounded to a read or controlled index."
        )
        return _op(impactful, confidence, rationale)


def _op(verdict: bool, confidence: float, rationale: str) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "confidence": round(min(0.99, confidence), 2),
        "rationale": rationale,
    }


def _role_from_system(system: str) -> str:
    s = system.lower()
    if "false" in s and "positive" in s:
        return "false-positive"
    if "reach" in s:
        return "reachability"
    return "impact"


def _seed_unit(text: str) -> float:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") / 2**32
