"""Core domain models shared across the scan → consensus → verify → report pipeline.

Everything the tool passes around is a Pydantic model so that findings can be
serialized to/from JSON at any stage boundary (useful for caching, resuming a
run, or feeding results into another tool).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    """CVSS-aligned severity buckets."""

    CRITICAL = "critical"  # CVSS >= 9.0
    HIGH = "high"  # CVSS >= 7.0
    MEDIUM = "medium"  # CVSS >= 4.0
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


class VulnClass(str, Enum):
    """The recurring memory-safety bug classes this tool hunts for.

    The first four are the patterns that dominate hand-written binary protocol
    parsers: unbounded protocol fields, integer-underflow indices, uncontrolled
    format strings, and check-after-use ordering flaws.
    """

    UNBOUNDED_FIELD = "unbounded-field"  # CWE-120 / CWE-787
    INTEGER_UNDERFLOW = "integer-underflow"  # CWE-191 / CWE-125
    FORMAT_STRING = "format-string"  # CWE-134
    VERIFY_ORDER = "verify-order"  # CWE-696 / TOCTOU-style
    OOB_WRITE = "oob-write"  # CWE-787 (computed array index)
    USE_AFTER_FREE = "use-after-free"  # CWE-416
    UNCHECKED_RETURN = "unchecked-return"  # CWE-252
    OTHER = "other"

    @property
    def cwe(self) -> str:
        return {
            VulnClass.UNBOUNDED_FIELD: "CWE-787",
            VulnClass.INTEGER_UNDERFLOW: "CWE-191",
            VulnClass.FORMAT_STRING: "CWE-134",
            VulnClass.VERIFY_ORDER: "CWE-696",
            VulnClass.OOB_WRITE: "CWE-787",
            VulnClass.USE_AFTER_FREE: "CWE-416",
            VulnClass.UNCHECKED_RETURN: "CWE-252",
            VulnClass.OTHER: "CWE-000",
        }[self]


class Location(BaseModel):
    """A precise source location, 1-indexed to match editors and SARIF."""

    path: str
    line: int = Field(ge=1)
    column: int = Field(default=1, ge=1)
    end_line: int | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"


class Finding(BaseModel):
    """A candidate vulnerability produced by the scanner (pre-triage)."""

    id: str = Field(description="Stable identifier, e.g. sha1 of rule+location.")
    rule_id: str
    vuln_class: VulnClass
    severity: Severity
    title: str
    message: str
    location: Location
    snippet: str = Field(description="Source context around the finding.")
    tainted_symbol: str | None = Field(
        default=None, description="The variable/argument believed to carry attacker data."
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cwe(self) -> str:
        return self.vuln_class.cwe


class Role(str, Enum):
    """The three adversarial reviewer roles in the consensus debate."""

    REACHABILITY = "reachability"  # Can attacker-controlled input reach this sink?
    IMPACT = "impact"  # If reached, what is the security impact?
    FALSE_POSITIVE = "false-positive"  # Argue that this is NOT a real bug.


class Opinion(BaseModel):
    """One reviewer model's structured judgement on a finding."""

    role: Role
    model: str = Field(description="Provider/model that produced this opinion.")
    verdict: bool = Field(
        description="Role-specific boolean: reachable? / impactful? / genuinely-a-bug?"
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class Verdict(BaseModel):
    """Aggregated consensus decision for a single finding."""

    finding_id: str
    confirmed: bool
    confidence: float = Field(ge=0.0, le=1.0)
    opinions: list[Opinion] = Field(default_factory=list)
    summary: str = ""

    @property
    def dissent(self) -> bool:
        """True when reviewers disagreed on whether this is a real bug."""
        verdicts = {o.verdict for o in self.opinions}
        return len(verdicts) > 1


class SanitizerResult(BaseModel):
    """Outcome of dynamic verification for a finding's proof-of-concept harness."""

    finding_id: str
    runs: int
    crashes: int
    sanitizer: str = "address,undefined"
    first_error: str | None = None

    @property
    def crash_rate(self) -> float:
        return self.crashes / self.runs if self.runs else 0.0

    @property
    def reproduced(self) -> bool:
        # Confirmation bar: a 100% crash rate for the overflow scenario.
        return self.runs > 0 and self.crashes == self.runs


class TriagedFinding(BaseModel):
    """A finding bundled with everything the pipeline learned about it."""

    finding: Finding
    verdict: Verdict | None = None
    sanitizer: SanitizerResult | None = None

    @property
    def is_confirmed(self) -> bool:
        return bool(self.verdict and self.verdict.confirmed)


class ScanReport(BaseModel):
    """Top-level result object; the unit of serialization for a whole run."""

    target: str
    tool_version: str
    rules_run: int
    results: list[TriagedFinding] = Field(default_factory=list)

    @property
    def confirmed(self) -> list[TriagedFinding]:
        return [r for r in self.results if r.is_confirmed]

    def by_severity(self, severity: Severity) -> list[TriagedFinding]:
        return [r for r in self.results if r.finding.severity is severity]
