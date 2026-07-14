# Contributing to Skepsis

Thanks for wanting to make Skepsis better! This project thrives on new detection
rules, new model providers, and new reporters — all of which are designed to be
small, self-contained additions.

## Getting set up

```bash
git clone https://github.com/0xTimi/skepsis && cd skepsis
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pre-commit install
```

Run the full local check before pushing:

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## Ways to contribute

### Add a detection rule (Stage 1)

Rules live in [`src/skepsis/scanner/patterns.py`](src/skepsis/scanner/patterns.py).
A rule is a single `Rule(...)` entry. Keep rules **high-recall**: it is the
consensus panel's job to reject false positives, so prefer catching too much over
too little. Add a matching case to `tests/test_scanner.py`.

### Add a provider (Stage 2)

Implement the tiny `LLMProvider` protocol in
[`src/skepsis/consensus/providers/base.py`](src/skepsis/consensus/providers/base.py)
— a single `complete_json(system, user)` method — then register it in
`providers/__init__.py`. See `mock.py` for the reference implementation.

### Add a reporter

Drop a module in [`src/skepsis/report/`](src/skepsis/report/) that turns a
`ScanReport` into your format, and export it from `report/__init__.py`.

## Guidelines

- **Style & types:** Ruff (lint + format) and `mypy --strict` must pass. CI enforces both.
- **Tests:** new behaviour needs a test; the offline `mock` panel means everything
  is testable without API keys or a network.
- **Commits:** we use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, …).
- **Scope:** keep PRs focused; a rule, a provider, and a bug fix are three PRs.

## Reporting bugs & security issues

Open a [bug report](https://github.com/0xTimi/skepsis/issues/new/choose)
for functional issues. For anything security-sensitive, follow
[SECURITY.md](SECURITY.md) instead of filing a public issue.

By contributing you agree that your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.
