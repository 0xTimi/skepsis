"""Anthropic (Claude) provider. Requires the optional ``anthropic`` extra."""

from __future__ import annotations

from typing import Any

from skepsis.consensus.providers.base import ProviderError, extract_json


class AnthropicProvider:
    """Claude-backed reviewer.

    Install with ``pip install 'skepsis[anthropic]'`` and set
    ``ANTHROPIC_API_KEY``.
    """

    def __init__(self, api_key: str | None, model: str = "claude-sonnet-5") -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ProviderError(
                "The 'anthropic' extra is not installed. Run: pip install 'skepsis[anthropic]'"
            ) from exc
        if not api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set.")
        self.name = model
        self._model = model
        self._client = anthropic.Anthropic(api_key=api_key)

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=system + "\n\nReply with a single JSON object and nothing else.",
                messages=[{"role": "user", "content": user}],
            )
        except Exception as exc:
            raise ProviderError(f"Anthropic request failed: {exc}") from exc
        text = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
        return extract_json(text)
