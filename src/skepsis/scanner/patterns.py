"""Heuristic rule set for candidate generation (the "Stage 1" stage).

These rules are deliberately *high-recall, low-precision*: their only job is to
surface suspicious sinks cheaply so the consensus panel ("Stage 2") can triage
them. A missed candidate here can never be recovered downstream, whereas a false
alarm is exactly what the panel exists to reject.

Each rule matches a single physical line. Cross-line reasoning (e.g. "the length
check comes *after* the copy") is intentionally left to the LLM panel, which is
far better at it than a regex would be.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from skepsis.models import Severity, VulnClass


@dataclass(frozen=True)
class Rule:
    """A single detection heuristic."""

    id: str
    vuln_class: VulnClass
    severity: Severity
    title: str
    message: str
    pattern: re.Pattern[str]
    # Group whose match names the tainted symbol, if the regex captures one.
    taint_group: int | None = None
    # Substrings that, if present on the same line, suppress the match
    # (cheap guard against the most obvious false positives).
    negative_guards: tuple[str, ...] = field(default_factory=tuple)


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


#: The built-in rule set. Ordering is irrelevant; ids must be unique.
RULES: tuple[Rule, ...] = (
    # --- Unbounded protocol fields (CWE-120 / CWE-787) -------------------
    Rule(
        id="SKEP-UF01",
        vuln_class=VulnClass.UNBOUNDED_FIELD,
        severity=Severity.CRITICAL,
        title="memcpy with non-constant length",
        message=(
            "memcpy length is not a compile-time constant; if it derives from a "
            "protocol field it can overflow the destination buffer."
        ),
        pattern=_c(r"\bmemcpy\s*\(\s*[^,]+,\s*[^,]+,\s*(?P<taint>[A-Za-z_]\w*)"),
        taint_group=1,
        negative_guards=("sizeof",),
    ),
    Rule(
        id="SKEP-UF02",
        vuln_class=VulnClass.UNBOUNDED_FIELD,
        severity=Severity.HIGH,
        title="Unbounded string copy",
        message="strcpy/strcat/gets/sprintf perform no bounds checking on the destination.",
        pattern=_c(r"\b(?:strcpy|strcat|gets|sprintf)\s*\("),
    ),
    Rule(
        id="SKEP-UF03",
        vuln_class=VulnClass.UNBOUNDED_FIELD,
        severity=Severity.HIGH,
        title="Stack buffer indexed by external length",
        message="alloca()/VLA sized by a runtime value can be driven to exhaust the stack.",
        pattern=_c(r"\balloca\s*\(\s*(?P<taint>[A-Za-z_]\w*)"),
        taint_group=1,
    ),
    # --- Integer underflow indices (CWE-191 / CWE-125) -------------------
    Rule(
        id="SKEP-IU01",
        vuln_class=VulnClass.INTEGER_UNDERFLOW,
        severity=Severity.HIGH,
        title="Subtraction on an unsigned length",
        message=(
            "'len - N' on an unsigned type underflows to a huge value when len < N, "
            "producing an out-of-bounds size or index."
        ),
        pattern=_c(r"(?P<taint>[A-Za-z_]\w*(?:_len|_size|len|size))\s*-\s*\d+"),
        taint_group=1,
    ),
    Rule(
        id="SKEP-IU02",
        vuln_class=VulnClass.INTEGER_UNDERFLOW,
        severity=Severity.MEDIUM,
        title="Array indexed by a decremented value",
        message="buf[i - 1] underflows to buf[SIZE_MAX] when i is 0.",
        pattern=_c(r"\[\s*(?P<taint>[A-Za-z_]\w*)\s*-\s*\d+\s*\]"),
        taint_group=1,
    ),
    # --- Uncontrolled format string (CWE-134) ----------------------------
    Rule(
        id="SKEP-FS01",
        vuln_class=VulnClass.FORMAT_STRING,
        severity=Severity.HIGH,
        title="Non-literal format string",
        message=(
            "printf-family call whose format argument is a variable; if it holds "
            "attacker data this is an info-leak or write primitive."
        ),
        pattern=_c(
            r"\b(?:printf|fprintf|sprintf|snprintf|syslog|vprintf)\s*\("
            r"(?:\s*[A-Za-z_]\w*\s*,\s*)?(?P<taint>[A-Za-z_]\w*)\s*\)"
        ),
        taint_group=1,
        negative_guards=('"',),
    ),
    # --- Verification-order flaws (CWE-696) ------------------------------
    Rule(
        id="SKEP-VO01",
        vuln_class=VulnClass.VERIFY_ORDER,
        severity=Severity.MEDIUM,
        title="Length read before validation",
        message=(
            "A length/size field is dereferenced or used before any visible bounds "
            "check; verify the check precedes the use."
        ),
        pattern=_c(r"\b(?:ntohs|ntohl|be16toh|be32toh|le16toh|le32toh)\s*\("),
    ),
    # --- Unchecked return (CWE-252) --------------------------------------
    Rule(
        id="SKEP-UR01",
        vuln_class=VulnClass.UNCHECKED_RETURN,
        severity=Severity.LOW,
        title="Allocation result used without NULL check",
        message="malloc/calloc/realloc result should be checked before use.",
        pattern=_c(r"=\s*(?:malloc|calloc|realloc)\s*\("),
    ),
)


def rules_by_class() -> dict[VulnClass, list[Rule]]:
    grouped: dict[VulnClass, list[Rule]] = {}
    for rule in RULES:
        grouped.setdefault(rule.vuln_class, []).append(rule)
    return grouped
