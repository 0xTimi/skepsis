"""Provider registry and factory.

A *panel* is just a list of provider ids (e.g. ``["mock"]`` or
``["anthropic", "openai", "anthropic"]``). :func:`build_panel` turns that list
into concrete provider instances using the current settings.
"""

from __future__ import annotations

from skepsis.config import Settings
from skepsis.consensus.providers.base import LLMProvider, ProviderError, extract_json
from skepsis.consensus.providers.mock import MockProvider

__all__ = [
    "LLMProvider",
    "MockProvider",
    "ProviderError",
    "available_providers",
    "build_panel",
    "build_provider",
    "extract_json",
]

available_providers = ("mock", "anthropic", "openai")


def build_provider(provider_id: str, settings: Settings) -> LLMProvider:
    """Instantiate a single provider by id."""
    pid = provider_id.strip().lower()
    if pid == "mock":
        return MockProvider()
    if pid == "anthropic":
        from skepsis.consensus.providers.anthropic import AnthropicProvider

        return AnthropicProvider(settings.anthropic_api_key, settings.anthropic_model)
    if pid == "openai":
        from skepsis.consensus.providers.openai import OpenAIProvider

        return OpenAIProvider(settings.openai_api_key, settings.openai_model)
    raise ProviderError(
        f"Unknown provider {provider_id!r}. Available: {', '.join(available_providers)}."
    )


def build_panel(settings: Settings) -> list[LLMProvider]:
    """Build every provider named in ``settings.panel``."""
    if not settings.panel:
        raise ProviderError("The consensus panel is empty; configure SKEPSIS_PANEL.")
    return [build_provider(pid, settings) for pid in settings.panel]
