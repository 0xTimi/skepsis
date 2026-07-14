# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-07-14

### Added
- **Stage 1 — Scanner:** dependency-free heuristic rule engine covering unbounded
  fields, integer underflows, format strings, verification-order flaws, and
  unchecked returns (`skepsis rules`).
- **Stage 2 — Consensus panel:** three-role adversarial debate (reachability /
  impact / false-positive) with a geometric-mean vote and configurable providers
  (`mock`, `anthropic`, `openai`).
- **Stage 3 — Sanitizer:** `skepsis verify` compiles a PoC with
  `-fsanitize=address,undefined` and measures crash rate over N runs.
- Reporters for console (Rich), Markdown, and **SARIF 2.1.0**.
- Offline `mock` panel so the full pipeline runs with no API keys.
- Library API (`from skepsis import Skepsis`), typed with `py.typed`.
- Bundled `examples/vulnerable-canlib` teaching fixture and a reproducing PoC.

[Unreleased]: https://github.com/0xTimi/skepsis/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0xTimi/skepsis/releases/tag/v0.1.0
