"""The consensus panel: distribute the three reviewer roles across providers.

Each suspicious pattern is examined by three *independent* viewpoints — one for
reachability, one for impact, one dedicated to refuting the finding. With a
multi-provider panel these roles land on different
models (true cross-model consensus); with a single-provider panel the same model
argues all three positions, which still meaningfully reduces false positives
because the refutation role is prompted adversarially.
"""

from __future__ import annotations

from collections.abc import Sequence

from skepsis.consensus.aggregate import aggregate
from skepsis.consensus.prompts import ROLE_SYSTEM, build_user_prompt
from skepsis.consensus.providers.base import LLMProvider, ProviderError
from skepsis.models import Finding, Opinion, Role, Verdict

#: Fixed role order; index i is served by ``panel[i % len(panel)]``.
_ROLES: tuple[Role, ...] = (Role.REACHABILITY, Role.IMPACT, Role.FALSE_POSITIVE)


class DebatePanel:
    """Runs the three-role deliberation for findings."""

    def __init__(self, panel: Sequence[LLMProvider], *, threshold: float = 0.6) -> None:
        if not panel:
            raise ValueError("A debate panel needs at least one provider.")
        self.panel = list(panel)
        self.threshold = threshold

    def deliberate(self, finding: Finding) -> Verdict:
        """Collect one opinion per role and aggregate them into a verdict."""
        user = build_user_prompt(finding)
        opinions: list[Opinion] = []
        for i, role in enumerate(_ROLES):
            provider = self.panel[i % len(self.panel)]
            opinions.append(self._ask(provider, role, user))
        return aggregate(finding.id, opinions, threshold=self.threshold)

    def _ask(self, provider: LLMProvider, role: Role, user: str) -> Opinion:
        system = ROLE_SYSTEM[role]
        try:
            raw = provider.complete_json(system, user)
        except ProviderError as exc:
            # A dead provider must not sink the whole run; record a neutral,
            # low-confidence opinion and carry on.
            return Opinion(
                role=role,
                model=f"{provider.name} (error)",
                verdict=False,
                confidence=0.0,
                rationale=f"Provider error: {exc}",
            )
        return Opinion(
            role=role,
            model=provider.name,
            verdict=bool(raw.get("verdict", False)),
            confidence=_clamp(raw.get("confidence", 0.5)),
            rationale=str(raw.get("rationale", "")).strip()[:500],
        )


def _clamp(value: object) -> float:
    try:
        f = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.5
    return min(1.0, max(0.0, f))
