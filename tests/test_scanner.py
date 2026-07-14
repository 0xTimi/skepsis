from __future__ import annotations

from pathlib import Path

from skepsis.models import VulnClass
from skepsis.scanner.engine import Scanner


def test_scanner_finds_all_rule_classes(vulnerable_c: Path) -> None:
    findings = Scanner().scan_path(vulnerable_c)
    classes = {f.vuln_class for f in findings}
    assert VulnClass.UNBOUNDED_FIELD in classes
    assert VulnClass.INTEGER_UNDERFLOW in classes
    assert VulnClass.FORMAT_STRING in classes


def test_findings_are_deterministic(vulnerable_c: Path) -> None:
    a = Scanner().scan_path(vulnerable_c)
    b = Scanner().scan_path(vulnerable_c)
    assert [f.id for f in a] == [f.id for f in b]
    assert all(a[i].id == b[i].id for i in range(len(a)))


def test_memcpy_with_sizeof_is_ignored(tmp_path: Path) -> None:
    src = tmp_path / "safe.c"
    src.write_text("void f(char*a,char*b){ memcpy(a,b,sizeof(x)); }", encoding="utf-8")
    findings = Scanner().scan_path(src)
    assert not any(f.rule_id == "SKEP-UF01" for f in findings)


def test_comments_do_not_trigger(tmp_path: Path) -> None:
    src = tmp_path / "c.c"
    src.write_text("int x; // strcpy(a,b) in a comment\n", encoding="utf-8")
    assert Scanner().scan_path(src) == []


def test_taint_symbol_captured(vulnerable_c: Path) -> None:
    findings = Scanner().scan_path(vulnerable_c)
    memcpy = next(f for f in findings if f.rule_id == "SKEP-UF01")
    assert memcpy.tainted_symbol == "len"


def test_non_c_files_skipped(tmp_path: Path) -> None:
    (tmp_path / "readme.md").write_text("memcpy(a,b,len);", encoding="utf-8")
    assert Scanner().scan_path(tmp_path) == []
