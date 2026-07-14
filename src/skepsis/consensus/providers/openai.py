"""OpenAI-compatible provider. Requires the optional ``openai`` extra.

Works against the official OpenAI API *and* any endpoint that speaks the same
protocol — Ollama, OpenRouter, vLLM, LM Studio, a self-hosted gateway — simply by
pointing ``base_url`` at it (``OPENAI_BASE_URL``). This keeps a single code path
for every backend instead of a bespoke client per vendor.
"""

from __future__ import annotations

from typing import Any

from skepsis.consensus.providers.base import ProviderError, extract_json


class OpenAIProvider:
    """Reviewer backed by any OpenAI-compatible chat-completions endpoint.

    Install with ``pip install 'skepsis[openai]'``. For the official API set
    ``OPENAI_API_KEY``; for a custom endpoint set ``OPENAI_BASE_URL`` (and a key
    if that endpoint requires one — local servers like Ollama often don't).
    """

    def __init__(
        self,
        api_key: str | None,
        model: str = "gpt-4.1",
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        try:
            import openai
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ProviderError(
                "The 'openai' extra is not installed. Run: pip install 'skepsis[openai]'"
            ) from exc
        # A custom endpoint (e.g. a local model server) may not need a real key;
        # the official API does.
        if not api_key and not base_url:
            raise ProviderError("OPENAI_API_KEY is not set.")
        self.name = model
        self._model = model
        self._base_url = base_url
        # A bounded timeout matters for slow/hung endpoints: without it a single
        # stalled request blocks the whole audit. On timeout the SDK raises, which
        # surfaces as a neutral opinion rather than a hang.
        # ``max_retries=0`` because the SDK otherwise retries a timed-out request
        # twice, tripling the wall-clock cost of a slow endpoint; the panel already
        # degrades gracefully, so we prefer to fail fast.
        self._client = openai.OpenAI(
            api_key=api_key or "no-key-required",
            base_url=base_url,
            timeout=timeout,
            max_retries=0,
        )

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": 1024,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        # ``response_format=json_object`` is an OpenAI-native feature that many
        # compatible servers reject, so only request it against the official API.
        # For everything else we rely on the prompt + ``extract_json`` fallback.
        if not self._base_url:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            raise ProviderError(f"OpenAI request failed: {exc}") from exc
        text = resp.choices[0].message.content or ""
        return extract_json(text)
