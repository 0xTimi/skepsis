# The Skepsis pipeline

Skepsis runs a three-stage review — **find, debate, prove**. Each stage is cheap
and broad first, expensive and precise last, so effort is spent only where earlier
stages leave genuine uncertainty.

## Stage 1 — Scanner (recall)

The scanner walks a C/C++ source tree and applies single-line heuristic
[rules](../src/skepsis/scanner/patterns.py). It is intentionally tuned for
**recall, not precision**: a candidate the scanner misses can never be recovered
by later stages, whereas a false alarm is exactly what Stage 2 exists to reject.

Design choices:

- **Line-granular matching.** Cross-line reasoning ("the bounds check comes
  *after* the copy") is deliberately deferred to the LLM panel, which handles it
  far better than a regex.
- **Comment/string scrubbing.** `//` comments and string literals are blanked
  before matching so they don't create noise; the panel still sees original source.
- **Taint hints.** Where a rule can name the suspicious symbol (the `memcpy`
  length, the format argument), it is captured and passed to the panel.

## Stage 2 — Consensus panel (precision)

Each candidate is examined by three **adversarial roles**:

| Role | Question | `verdict = true` means |
| --- | --- | --- |
| `reachability` | Can attacker input reach this sink? | reachable |
| `impact` | If reached, is it a memory-safety violation? | impactful |
| `false-positive` | *Argue it is NOT a bug.* | genuinely a bug anyway |

With a multi-provider panel the roles land on **different models** (true
cross-model consensus); with a single-provider panel one model argues all three
positions — still valuable, because the refutation role is prompted adversarially.

### The vote

Every role returns `{verdict: bool, confidence: 0..1}`. We convert each opinion
to a probability that the finding is real, centred on 0.5 so a zero-confidence
(or errored) opinion is genuinely neutral:

$$
p_\text{real} =
\begin{cases}
0.5 + 0.5 \cdot c & \text{if verdict is true} \\
0.5 - 0.5 \cdot c & \text{if verdict is false}
\end{cases}
$$

The finding's score is the **geometric mean** of the per-role $p_\text{real}$:

$$
\text{score} = \left( \prod_i p_{\text{real},i} \right)^{1/n}
$$

Geometric mean (not arithmetic) is the key choice: one reviewer who is *very*
sure the bug is unreal drives the product toward zero and **vetoes** the
consensus. That is precisely the false-positive-suppression behaviour we want. A
finding is confirmed when `score ≥ confirm_threshold` (default `0.6`).

## Stage 3 — Sanitizer (proof)

A confirmed finding is still just an argument until code crashes. `skepsis verify`
compiles a self-contained proof-of-concept with `-fsanitize=address,undefined`
and runs it `N` times (default 20). Skepsis's bar for confirming an overflow is
a **100% crash rate** on the hostile input (and, symmetrically, 0% on a benign
input); `SanitizerResult.reproduced` encodes the positive half.

Automatic harness synthesis — closing the loop so Stage 2's confirmed findings feed
Stage 3 without a human writing the PoC — is on the [roadmap](../README.md#-roadmap).

## Why three stages instead of one big model?

- **Cost.** The scanner triages thousands of lines for free; the panel only ever
  sees a handful of candidates.
- **Calibration.** A single model asked to "find bugs" has no incentive to doubt
  itself. Splitting the work into a proponent and a dedicated skeptic surfaces the
  disagreement that a monolithic prompt hides.
- **Auditability.** Every confirmed finding carries the three opinions and the
  arithmetic behind its score, so a human can see *why* it survived.
