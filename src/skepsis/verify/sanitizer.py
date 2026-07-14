"""Dynamic verification via compiler sanitizers (Stage 3 of the protocol).

Given a self-contained C proof-of-concept, compile it with AddressSanitizer and
UndefinedBehaviorSanitizer, run it ``runs`` times, and report the crash rate.
Skepsis's bar for confirming an overflow is a **100% crash rate** across the
runs (and, symmetrically, 0% on a benign input) — :pyattr:`SanitizerResult.reproduced`
encodes the positive half of that check.

This module shells out to a C compiler (``cc`` by default). If none is present,
:meth:`SanitizerRunner.available` returns ``False`` and callers should skip
verification rather than fail the run.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from skepsis.models import SanitizerResult

_SANITIZER_ERROR = re.compile(
    r"(?:AddressSanitizer|UndefinedBehaviorSanitizer|runtime error"
    r"|ERROR: AddressSanitizer|SUMMARY:)",
    re.IGNORECASE,
)


class SanitizerRunner:
    """Compiles and repeatedly executes sanitizer-instrumented C harnesses."""

    def __init__(
        self,
        cc: str = "cc",
        *,
        sanitizers: str = "address,undefined",
        compile_timeout: float = 60.0,
        run_timeout: float = 10.0,
    ) -> None:
        self.cc = cc
        self.sanitizers = sanitizers
        self.compile_timeout = compile_timeout
        self.run_timeout = run_timeout

    def available(self) -> bool:
        """True if the configured C compiler is on PATH."""
        return shutil.which(self.cc) is not None

    def verify_source(
        self, finding_id: str, source: str, *, runs: int, argv: list[str] | None = None
    ) -> SanitizerResult:
        """Compile ``source`` and run it ``runs`` times, counting sanitizer crashes."""
        if not self.available():
            raise RuntimeError(f"C compiler {self.cc!r} not found on PATH.")
        with tempfile.TemporaryDirectory(prefix="skepsis-asan-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "poc.c"
            binary = tmpdir / "poc"
            src.write_text(source, encoding="utf-8")
            self._compile(src, binary)
            return self._run_many(finding_id, binary, runs=runs, argv=argv or [])

    def verify_file(
        self, finding_id: str, source_path: Path, *, runs: int, argv: list[str] | None = None
    ) -> SanitizerResult:
        return self.verify_source(
            finding_id, Path(source_path).read_text(encoding="utf-8"), runs=runs, argv=argv
        )

    # -- internals --------------------------------------------------------

    def _compile(self, src: Path, binary: Path) -> None:
        cmd = [
            self.cc,
            f"-fsanitize={self.sanitizers}",
            "-fno-omit-frame-pointer",
            "-g",
            "-O1",
            str(src),
            "-o",
            str(binary),
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.compile_timeout, check=False
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Harness failed to compile:\n{proc.stderr.strip()}")

    def _run_many(
        self, finding_id: str, binary: Path, *, runs: int, argv: list[str]
    ) -> SanitizerResult:
        crashes = 0
        first_error: str | None = None
        env_note = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:exitcode=99"}
        for _ in range(runs):
            proc = subprocess.run(
                [str(binary), *argv],
                capture_output=True,
                text=True,
                timeout=self.run_timeout,
                check=False,
                env=_env(env_note),
            )
            output = proc.stdout + proc.stderr
            crashed = proc.returncode != 0 or bool(_SANITIZER_ERROR.search(output))
            if crashed:
                crashes += 1
                if first_error is None:
                    first_error = _first_error_line(output)
        return SanitizerResult(
            finding_id=finding_id,
            runs=runs,
            crashes=crashes,
            sanitizer=self.sanitizers,
            first_error=first_error,
        )


def _env(extra: dict[str, str]) -> dict[str, str]:
    import os

    env = dict(os.environ)
    env.update(extra)
    return env


def _first_error_line(output: str) -> str | None:
    for line in output.splitlines():
        if _SANITIZER_ERROR.search(line):
            return line.strip()[:300]
    return None
