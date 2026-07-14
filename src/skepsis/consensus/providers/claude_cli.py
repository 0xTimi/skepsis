"""Claude via the Claude Code CLI (``claude -p``).

Uses the user's existing Claude Code installation and auth — **no API key**. Each
review is one headless ``claude -p`` invocation; the reply is parsed from the
``--output-format json`` envelope. Handy for anyone who already has Claude Code
but no separate API billing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from skepsis.consensus.providers.base import ProviderError, extract_json


class ClaudeCliProvider:
    """Reviewer backed by the ``claude`` CLI in print/headless mode."""

    def __init__(
        self, model: str | None = None, timeout: float = 120.0, binary: str = "claude"
    ) -> None:
        if shutil.which(binary) is None:
            raise ProviderError(f"Claude Code CLI {binary!r} not found on PATH.")
        self.name = f"claude-cli:{model or 'default'}"
        self._model = model
        self._timeout = timeout
        self._binary = binary

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        # Fold the role instruction into the prompt so this works regardless of
        # which system-prompt flags the installed CLI version supports.
        prompt = f"{system}\n\n{user}"
        cmd = [self._binary, "-p", prompt, "--output-format", "json"]
        if self._model:
            cmd += ["--model", self._model]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self._timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderError(f"claude -p timed out after {self._timeout}s") from exc
        if proc.returncode != 0:
            raise ProviderError(f"claude -p failed ({proc.returncode}): {proc.stderr[:200]}")
        # --output-format json wraps the reply: {"result": "<text>", ...}
        text = proc.stdout
        try:
            envelope = json.loads(proc.stdout)
            if isinstance(envelope, dict) and "result" in envelope:
                text = str(envelope["result"])
        except json.JSONDecodeError:
            pass
        return extract_json(text)
