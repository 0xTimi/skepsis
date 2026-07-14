"""Runtime configuration, layered from defaults < env vars < CLI flags.

Environment variables use the ``SKEPSIS_`` prefix, e.g. ``SKEPSIS_PANEL``.
Provider API keys use the providers' own conventional names
(``ANTHROPIC_API_KEY``, ``OPENAI_API_KEY``) so existing setups just work.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global settings resolved once per process."""

    model_config = SettingsConfigDict(
        env_prefix="SKEPSIS_",
        env_file=".env",
        extra="ignore",
    )

    # --- Consensus panel -------------------------------------------------
    panel: list[str] = Field(
        default=["mock"],
        description="Ordered list of provider ids forming the review panel.",
    )
    confirm_threshold: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Minimum aggregate confidence for a finding to be confirmed.",
    )

    # --- Provider credentials / models -----------------------------------
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = "claude-sonnet-5"
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = "gpt-4.1"
    openai_base_url: str | None = Field(
        default=None,
        alias="OPENAI_BASE_URL",
        description="Custom OpenAI-compatible endpoint (Ollama, OpenRouter, self-hosted, …).",
    )

    # --- Triage performance / robustness ---------------------------------
    request_timeout: float = Field(
        default=60.0, ge=1.0, description="Per-request timeout (seconds) for LLM providers."
    )
    max_workers: int = Field(
        default=4, ge=1, description="Findings triaged concurrently by the consensus panel."
    )

    # --- Verification ----------------------------------------------------
    sanitizer_runs: int = Field(default=20, ge=1)
    cc: str = Field(default="cc", description="C compiler used for sanitizer harnesses.")

    # --- Scanner ---------------------------------------------------------
    context_lines: int = Field(default=3, ge=0, description="Snippet context radius.")
    max_file_bytes: int = Field(default=2_000_000, description="Skip files larger than this.")


def load_settings() -> Settings:
    """Load settings from env/.env. Kept as a function for easy test injection."""
    return Settings()
