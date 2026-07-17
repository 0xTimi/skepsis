"""Turn a set of role opinions into a single consensus :class:`Verdict`.

The aggregation is a continuous vote rather than a hard AND/OR so that a single
confidently-dissenting reviewer meaningfully moves the outcome:

For each opinion we compute ``p_real`` — the probability the reviewer assigns to
the finding being real::

    p_real = confidence      if verdict is True   (argues FOR the bug)
    p_real = 1 - confidence  if verdict is False  (argues AGAINST the bug)

The finding's aggregate score is the geometric mean of the per-opinion
``p_real`` values. Geometric mean (rather than arithmetic) means one reviewer
who is *very* sure the bug is unreal can veto the consensus — which is exactly
the false-positive-suppression behaviour we want.

``p_real`` is centred on 0.5 and pushed toward the verdict in proportion to
confidence, so a zero-confidence (or errored) opinion is genuinely *neutral*
rather than counting as strong evidence in either direction::

    p_real = 0.5 + 0.5 * confidence   if verdict is True
    p_real = 0.5 - 0.5 * confidence   if verdict is False
"""

from __future__ import annotations

import math

from skepsis.models import Opinion, Verdict


def _p_real(opinion: Opinion) -> float:
    signed = opinion.confidence if opinion.verdict else -opinion.confidence
    p = 0.5 + 0.5 * signed
    # Clamp away from 0/1 so a single opinion can't hard-zero the geometric mean.
    return min(0.99, max(0.01, p))


def aggregate(finding_id: str, opinions: list[Opinion], *, threshold: float) -> Verdict:
    """Combine ``opinions`` into a confirmed/rejected verdict."""
    if not opinions:
        return Verdict(
            finding_id=finding_id,
            confirmed=False,
            confidence=0.0,
            opinions=[],
            summary="No opinions were produced.",
        )

    log_sum = sum(math.log(_p_real(o)) for o in opinions)
    score = math.exp(log_sum / len(opinions))

    # Require a real quorum: a confirmation must rest on at least two roles that
    # actually returned a signal. Errored/timed-out roles abstain (confidence 0);
    # without this a single surviving positive role could confirm on its own.
    quorum = sum(1 for o in opinions if o.confidence > 0.0)
    confirmed = score >= threshold and quorum >= 2

    summary = _summarize(opinions, score, confirmed)
    if score >= threshold and quorum < 2:
        summary += f" — INCONCLUSIVE (only {quorum} role(s) responded)"
    return Verdict(
        finding_id=finding_id,
        confirmed=confirmed,
        confidence=round(score, 3),
        opinions=opinions,
        summary=summary,
    )


def _summarize(opinions: list[Opinion], score: float, confirmed: bool) -> str:
    verb = "CONFIRMED" if confirmed else "rejected"
    votes = ", ".join(
        f"{o.role.value}={'yes' if o.verdict else 'no'}({o.confidence:.0%})" for o in opinions
    )
    return f"{verb} at {score:.0%} consensus [{votes}]"
