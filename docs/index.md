# Skepsis

**Hunt memory-safety bugs in C/C++ with a panel of models as your jury.**

Skepsis finds the dangerous patterns, then makes three adversarial AI reviewers
debate every one and confirms the survivors with a sanitizer — so what lands in
your inbox is signal, not a wall of false positives.

```bash
pip install skepsis
skepsis scan examples/vulnerable-canlib      # offline, no API key
```

## The three stages

<div class="grid cards" markdown>

- :material-magnify: **Stage 1 — Scanner**

    Fast, dependency-free heuristics surface candidate sinks. Tuned for recall.

- :material-scale-balance: **Stage 2 — Consensus**

    Three roles — reachability, impact, refutation — debate and vote. Kills false positives.

- :material-bug-check: **Stage 3 — Sanitizer**

    Compile a PoC with ASan/UBSan and demand a 100% crash rate. Proof, not opinion.

</div>

See [**the methodology**](methodology.md) for the full design and the aggregation
math, or jump to the [rules reference](methodology.md#stage-1--scanner-recall).

## Next steps

- [Quickstart & configuration](https://github.com/0xTimi/skepsis#-quickstart)
- [Contributing a rule or provider](https://github.com/0xTimi/skepsis/blob/main/CONTRIBUTING.md)
- [Roadmap](https://github.com/0xTimi/skepsis#-roadmap)
