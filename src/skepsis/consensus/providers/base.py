"""Provider abstraction: anything that can answer a single-turn prompt with JSON.

Keeping the surface this small means adding a new backend (a local model server,
a different vendor, a cached replay) is a ~20-line file. The debate layer never
imports a concrete provider — only this protocol.
"""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable


class ProviderError(RuntimeError):
    """Raised when a provider cannot fulfil a request (auth, network, quota)."""


@runtime_checkable
class LLMProvider(Protocol):
    """A minimal, synchronous single-shot completion interface."""

    #: Human-readable id used in ``Opinion.model`` and the panel config.
    name: str

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Return the provider's reply parsed as a JSON object.

        Implementations must coerce the model into returning a single JSON
        object and raise :class:`ProviderError` on transport/auth failure.
        """
        ...


def extract_json(text: str) -> dict[str, Any]:
    """Best-effort extraction of the first JSON object from a model reply.

    Models occasionally wrap JSON in prose or fenced code blocks; this pulls the
    outermost ``{...}`` span and parses it.
    """
    text = text.strip()
    if text.startswith("```"):
        # Strip a ```json ... ``` fence.
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[:-3]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ProviderError(f"No JSON object found in reply: {text[:200]!r}")
    try:
        obj = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Malformed JSON in reply: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProviderError("Expected a JSON object at the top level.")
    return obj
