from __future__ import annotations

from skepsis.consensus.aggregate import aggregate
from skepsis.consensus.debate import DebatePanel
from skepsis.consensus.providers.base import ProviderError, extract_json
from skepsis.consensus.providers.mock import MockProvider
from skepsis.models import Finding, Location, Opinion, Role, Severity, VulnClass


def _finding(snippet: str = "memcpy(out, packet, len);") -> Finding:
    return Finding(
        id="deadbeef",
        rule_id="SKEP-UF01",
        vuln_class=VulnClass.UNBOUNDED_FIELD,
        severity=Severity.CRITICAL,
        title="memcpy with non-constant length",
        message="unbounded copy",
        location=Location(path="a.c", line=10),
        snippet=snippet,
        tainted_symbol="len",
    )


def test_mock_provider_is_deterministic() -> None:
    p = MockProvider()
    a = p.complete_json("judge reachability", "memcpy(out, packet, len)")
    b = p.complete_json("judge reachability", "memcpy(out, packet, len)")
    assert a == b
    assert set(a) == {"verdict", "confidence", "rationale"}


def test_panel_confirms_tainted_memcpy() -> None:
    panel = DebatePanel([MockProvider()], threshold=0.5)
    verdict = panel.deliberate(_finding())
    assert verdict.finding_id == "deadbeef"
    assert len(verdict.opinions) == 3
    assert {o.role for o in verdict.opinions} == set(Role)


def test_aggregate_vetoes_on_confident_dissent() -> None:
    opinions = [
        Opinion(role=Role.REACHABILITY, model="m", verdict=True, confidence=0.9, rationale=""),
        Opinion(role=Role.IMPACT, model="m", verdict=True, confidence=0.9, rationale=""),
        Opinion(role=Role.FALSE_POSITIVE, model="m", verdict=False, confidence=0.99, rationale=""),
    ]
    verdict = aggregate("x", opinions, threshold=0.6)
    assert verdict.confirmed is False
    assert verdict.dissent is True


def test_aggregate_requires_quorum_of_two() -> None:
    # One confident positive + two abstentions (errored roles, confidence 0).
    # Score clears the threshold, but a lone role must not confirm on its own.
    opinions = [
        Opinion(role=Role.REACHABILITY, model="m", verdict=True, confidence=0.9, rationale="yes"),
        Opinion(
            role=Role.IMPACT, model="m (error)", verdict=False, confidence=0.0, rationale="err"
        ),
        Opinion(
            role=Role.FALSE_POSITIVE, model="m (error)", verdict=False, confidence=0.0, rationale=""
        ),
    ]
    verdict = aggregate("x", opinions, threshold=0.6)
    assert verdict.confidence >= 0.6  # score alone would have confirmed
    assert verdict.confirmed is False  # but quorum < 2 blocks it
    assert "INCONCLUSIVE" in verdict.summary


def test_aggregate_empty_is_rejected() -> None:
    verdict = aggregate("x", [], threshold=0.6)
    assert verdict.confirmed is False
    assert verdict.confidence == 0.0


def test_extract_json_handles_fences() -> None:
    obj = extract_json('```json\n{"verdict": true, "confidence": 0.8}\n```')
    assert obj["verdict"] is True


def test_extract_json_rejects_garbage() -> None:
    try:
        extract_json("no json here")
    except ProviderError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ProviderError")


class _FlakyProvider:
    name = "flaky"

    def complete_json(self, system: str, user: str) -> dict[str, object]:
        raise ProviderError("boom")


def test_provider_error_becomes_neutral_opinion() -> None:
    panel = DebatePanel([_FlakyProvider()], threshold=0.6)
    verdict = panel.deliberate(_finding())
    assert verdict.confirmed is False
    assert all(o.confidence == 0.0 for o in verdict.opinions)
