from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from skepsis.verify.sanitizer import SanitizerRunner

_HAS_CC = shutil.which("cc") is not None
requires_cc = pytest.mark.skipif(not _HAS_CC, reason="no C compiler available")

_OVERFLOW = """
#include <string.h>
int main(void){ char b[4]; char s[16]="AAAAAAAAAAAAAAA"; memcpy(b, s, 16); return b[0]; }
"""

_CLEAN = """
int main(void){ int x = 41; return x - 41; }
"""


@requires_cc
def test_overflow_reproduces_every_run() -> None:
    runner = SanitizerRunner()
    result = runner.verify_source("t", _OVERFLOW, runs=5)
    assert result.reproduced is True
    assert result.crash_rate == 1.0
    assert result.first_error is not None


@requires_cc
def test_clean_program_never_crashes() -> None:
    runner = SanitizerRunner()
    result = runner.verify_source("t", _CLEAN, runs=5)
    assert result.crashes == 0
    assert result.reproduced is False


@requires_cc
def test_compile_error_raises(tmp_path: Path) -> None:
    runner = SanitizerRunner()
    with pytest.raises(RuntimeError, match="compile"):
        runner.verify_source("t", "this is not C", runs=1)


def test_available_reflects_path() -> None:
    assert SanitizerRunner("cc").available() == _HAS_CC
    assert SanitizerRunner("definitely-not-a-compiler-xyz").available() is False
