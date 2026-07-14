from __future__ import annotations

from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "vulnerable-canlib"


@pytest.fixture
def vulnerable_c(tmp_path: Path) -> Path:
    """A small C file exercising every rule class."""
    src = tmp_path / "lib.c"
    src.write_text(
        """
#include <string.h>
#include <stdio.h>
void f(const unsigned char *pkt, unsigned char *out, unsigned char len) {
    memcpy(out, pkt, len);        // SKEP-UF01
    char name[16];
    strcpy(name, (const char*)pkt); // SKEP-UF02
}
size_t g(size_t frame_len) {
    return frame_len - 3;         // SKEP-IU01
}
unsigned char h(const unsigned char *buf, size_t i) {
    return buf[i - 1];            // SKEP-IU02
}
void l(const char *msg) {
    printf(msg);                  // SKEP-FS01
}
""",
        encoding="utf-8",
    )
    return src


@pytest.fixture
def example_canlib() -> Path:
    return EXAMPLE / "canparse.c"


@pytest.fixture
def example_poc() -> Path:
    return EXAMPLE / "poc_isotp_overflow.c"
