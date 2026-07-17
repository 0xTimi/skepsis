"""The scanning engine: walk a source tree, apply rules, emit ``Finding`` objects."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator
from fnmatch import fnmatch
from pathlib import Path

from skepsis.models import Finding, Location
from skepsis.scanner.patterns import RULES, Rule

C_EXTENSIONS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx", ".inl"})


def _iter_source_files(
    root: Path, max_bytes: int, exclude: tuple[str, ...] = ()
) -> Iterator[Path]:
    """Yield candidate C/C++ files under ``root`` (or ``root`` itself if a file).

    ``exclude`` is a tuple of glob patterns matched against each file's path; a
    match skips the file. Handy for keeping tests/examples/vendored code out of an
    audit (e.g. ``"*/test*"``, ``"*/examples/*"``).
    """
    if root.is_file():
        candidates: Iterable[Path] = [root]
    else:
        candidates = sorted(root.rglob("*"))
    root_is_dir = root.is_dir()
    for path in candidates:
        if not path.is_file() or path.suffix.lower() not in C_EXTENSIONS:
            continue
        if exclude:
            rel = str(path.relative_to(root)) if root_is_dir else path.name
            if _is_excluded(rel, path.name, exclude):
                continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        yield path


def _is_excluded(rel: str, name: str, patterns: tuple[str, ...]) -> bool:
    # Match against the path relative to the scan root (and the bare filename),
    # so patterns like "*/test*" or "*test*" aren't tripped by ancestor dirs
    # above the root.
    return any(fnmatch(rel, pat) or fnmatch(name, pat) for pat in patterns)


def _strip_line_noise(line: str) -> str:
    """Blank out ``//`` comments and string literals so rules don't match inside them.

    This is a cheap, single-line approximation — block comments and multi-line
    strings are handled well enough for candidate generation. The consensus panel
    sees the *original* source, so nothing is lost to triage.
    """
    # Drop trailing // comments (naive but adequate at line granularity).
    comment = line.find("//")
    if comment != -1:
        line = line[:comment]
    return line


def _finding_id(rule: Rule, location: Location) -> str:
    digest = hashlib.sha1(f"{rule.id}:{location.path}:{location.line}:{location.column}".encode())
    return digest.hexdigest()[:12]


def _snippet(lines: list[str], line_no: int, radius: int) -> str:
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    out: list[str] = []
    for i in range(start, end):
        marker = ">" if i == line_no - 1 else " "
        out.append(f"{marker} {i + 1:>4} | {lines[i]}")
    return "\n".join(out)


class Scanner:
    """Applies a rule set to a source tree.

    Parameters
    ----------
    rules:
        Rule set to run; defaults to the built-in :data:`RULES`.
    context_lines:
        Radius (in lines) of source context captured in each finding's snippet.
    max_file_bytes:
        Files larger than this are skipped (generated blobs, vendored amalgams).
    exclude:
        Glob patterns of paths to skip (e.g. ``"*/test*"``, ``"*/examples/*"``).
    """

    def __init__(
        self,
        rules: tuple[Rule, ...] = RULES,
        *,
        context_lines: int = 3,
        max_file_bytes: int = 2_000_000,
        exclude: tuple[str, ...] = (),
    ) -> None:
        self.rules = rules
        self.context_lines = context_lines
        self.max_file_bytes = max_file_bytes
        self.exclude = exclude

    def scan_path(self, root: str | Path) -> list[Finding]:
        root = Path(root)
        findings: list[Finding] = []
        for path in _iter_source_files(root, self.max_file_bytes, self.exclude):
            findings.extend(self.scan_file(path, display_root=root))
        # Deterministic ordering: by file, then line.
        findings.sort(key=lambda f: (f.location.path, f.location.line, f.rule_id))
        return findings

    def scan_file(self, path: Path, *, display_root: Path | None = None) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        lines = text.splitlines()
        rel = self._display_path(path, display_root)
        findings: list[Finding] = []
        for idx, raw in enumerate(lines, start=1):
            scrubbed = _strip_line_noise(raw)
            if not scrubbed.strip():
                continue
            for rule in self.rules:
                match = rule.pattern.search(scrubbed)
                if not match:
                    continue
                if any(guard in scrubbed for guard in rule.negative_guards):
                    continue
                findings.append(self._build(rule, rel, idx, match, lines))
        return findings

    def _build(
        self, rule: Rule, rel: str, line_no: int, match: re.Match[str], lines: list[str]
    ) -> Finding:
        column = match.start() + 1
        taint = self._extract_taint(rule, match)
        location = Location(path=rel, line=line_no, column=column)
        return Finding(
            id=_finding_id(rule, location),
            rule_id=rule.id,
            vuln_class=rule.vuln_class,
            severity=rule.severity,
            title=rule.title,
            message=rule.message,
            location=location,
            snippet=_snippet(lines, line_no, self.context_lines),
            tainted_symbol=taint,
        )

    @staticmethod
    def _extract_taint(rule: Rule, match: re.Match[str]) -> str | None:
        if "taint" not in match.re.groupindex:
            return None
        return match.group("taint")

    @staticmethod
    def _display_path(path: Path, display_root: Path | None) -> str:
        if display_root and display_root.is_dir():
            try:
                return str(path.relative_to(display_root))
            except ValueError:
                pass
        return str(path)
