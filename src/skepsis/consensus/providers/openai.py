"""OpenAI provider. Requires the optional ``openai`` extra."""

from __future__ import annotations

from typing import Any

from skepsis.consensus.providers.base import ProviderError, extract_json


class OpenAIProvider:
    """GPT-backed reviewer.

    Install with ``pip install 'skepsis[openai]'`` and set
    ``OPENAI_API_KEY``.
    """

    def __init__(self, api_key: str | None, model: str = "gpt-4.1") -> None:
        try:
            import openai
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ProviderError(
                "The 'openai' extra is not installed. Run: pip install 'skepsis[openai]'"
            ) from exc
        if not api_key:
            raise ProviderError("OPENAI_API_KEY is not set.")
        self.name = model
        self._model = model
        self._client = openai.OpenAI(api_key=api_key)

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
        except Exception as exc:
            raise ProviderError(f"OpenAI request failed: {exc}") from exc
        text = resp.choices[0].message.content or ""
        return extract_json(text)
