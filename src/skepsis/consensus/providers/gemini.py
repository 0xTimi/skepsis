"""Google Gemini provider (native ``generateContent`` API).

Speaks Gemini's native protocol rather than the OpenAI wire format, so it works
with a Vertex AI API key (``aiplatform.googleapis.com``) as well as an AI Studio
key (``generativelanguage.googleapis.com``) — authenticating with the
``x-goog-api-key`` header either way. It asks for ``responseMimeType:
application/json`` so replies are strict JSON, no prompt-coaxing required.

Uses ``httpx`` (already a core dependency); no vendor SDK needed.
"""

from __future__ import annotations

from typing import Any

import httpx

from skepsis.consensus.providers.base import ProviderError, extract_json

#: Vertex AI global publisher endpoint. For AI Studio use
#: ``https://generativelanguage.googleapis.com/v1beta/models``.
DEFAULT_BASE_URL = "https://aiplatform.googleapis.com/v1/publishers/google/models"


class GeminiProvider:
    """Reviewer backed by Google Gemini via the native generateContent API."""

    def __init__(
        self,
        api_key: str | None,
        model: str = "gemini-2.5-flash",
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 60.0,
    ) -> None:
        if not api_key:
            raise ProviderError("GEMINI_API_KEY is not set.")
        self.name = model
        self._model = model
        self._url = f"{base_url.rstrip('/')}/{model}:generateContent"
        self._key = api_key
        self._timeout = timeout

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                # Generous cap + thinking disabled: 2.5 models otherwise spend the
                # output budget on hidden reasoning and truncate the JSON verdict.
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json",
                "temperature": 0.2,
                "thinkingConfig": {"thinkingBudget": 0},
            },
        }
        try:
            resp = httpx.post(
                self._url,
                json=body,
                timeout=self._timeout,
                headers={"x-goog-api-key": self._key, "content-type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"Gemini request failed: {exc}") from exc
        if resp.status_code != 200:
            raise ProviderError(f"Gemini HTTP {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            # No candidate usually means a safety block or an empty completion.
            raise ProviderError(f"Gemini returned no text: {str(data)[:200]}") from exc
        return extract_json(text)
