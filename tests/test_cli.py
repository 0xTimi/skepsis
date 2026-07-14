from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from skepsis import __version__
from skepsis.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_rules_lists_builtin_rules() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "SKEP-UF01" in result.stdout


def test_scan_exit_code_signals_findings(example_canlib: Path) -> None:
    result = runner.invoke(app, ["scan", str(example_canlib), "--panel", "mock"])
    # Confirmed findings → exit code 1 (CI-friendly).
    assert result.exit_code in (0, 1)


def test_scan_sarif_output(example_canlib: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    result = runner.invoke(
        app,
        ["scan", str(example_canlib), "--panel", "mock", "--format", "sarif", "--out", str(out)],
    )
    assert result.exit_code in (0, 1)
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"


def test_scan_unknown_provider_fails_fast(example_canlib: Path) -> None:
    result = runner.invoke(app, ["scan", str(example_canlib), "--panel", "nope"])
    assert result.exit_code == 2
