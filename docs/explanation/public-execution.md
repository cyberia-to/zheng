# Public execution validation — 2026-09-11

Status: implemented and tested for the bounded public relation in
[the execution specification](../../specs/execution.md). This is a public
execution certificate, not a succinct or zero-knowledge production release.

## What is authenticated

`zheng::execution::verify_execution` derives CCS constraints from the canonical
public program and subject shape. It authenticates the complete public witness
using Lens `PublicTensor`, checks every CCS row exactly, and pins the constant
wire, public inputs, public outputs and reduction count. The program, values
and budget are bound into the statement/transcript. Verification does not call
the native nox evaluator or the prover's witness generator.

The full-table authentication and exact constraint checks are essential:
acceptance does not rely on the legacy PCS's empirical distance or on a
small-field sumcheck soundness estimate. This is linear work with full witness
disclosure. It still depends on the correctness of the relation compiler and
implementation; testing is not a formal proof of those components.

Joy defaults to this path, including its `Prover` and `Verifier` traits. New
artifacts have the distinct `JOYEXEC1` header and bind canonical program tokens
to their assembly. Malformed new artifacts cannot fall back to the old parser.
Legacy Joy verification requires `--legacy-trace-statement` and cannot satisfy
requested public IO claims. The standalone `zheng` CLI still uses the legacy
API and explicitly reports `execution_output = unverified`.

Implementation commits: Lens `9b134c4`, Zheng `b996798`, Joy `6b8dfd3`.
The Trident compiler used for the end-to-end smoke is `c113af4`.

## Validation

| Check | Result |
|---|---|
| Zheng execution unit tests | 23 passed |
| Independent adversarial execution tests | 5 passed |
| Joy public execution library and subprocess tests | 4 + 4 passed |
| Lens PublicTensor tests | 4 passed |
| Joy workspace / all targets check | Passed without warnings |
| Zheng CLI check after legacy scope labels | Passed |
| Release Joy installation and fresh-process certificate verification | Passed |

These 40 new tests cover native/symbolic agreement, compiled Trident imports,
loops and branches, structural hashing, intermediate witness mutations,
changed program/input/output/cost/budget, malicious proofs constructed outside
the honest prover, malformed/noncanonical wire encodings and Merkle openings,
and rejection of secret/state inputs. The independent review is recorded in
[direct-execution-review](../../specs/props/direct-execution-review.md).

The full legacy gates are **not green**. Zheng's bounded serde suite reports
150 passes and 20 failures, with two exhaustive bit stress tests excluded.
The same command against pre-change `cdd61ef` reports 127 passes and the same
20 failures. These are legacy recursive-opening / retired Tensor checks.
Joy's broader suite has 10 unit passes, 24 existing integration passes and
three existing state-proof failures. Its final new CLI and library tests pass
separately. Lens's broader run reached 44 passes; the long existing
`empirical_distance_probe` was stopped, so this is not a full-suite pass.

## Installed binary examples

Measured once on Darwin arm64 through separate CLI processes; these are smoke
measurements, not statistical performance benchmarks. Trident and Joy were
installed under an isolated prefix, with `TRIDENT_*` unset.

The Trident fixture imports `calc.step(x) = x + 3`, applies it three times in a
loop and branches on whether the result is 13. Input `4` produces `113`.

| Fixture | Native result / reductions | Certificate | Prove process | Verify process |
|---|---|---:|---:|---:|
| Imported Trident loop and branch | `113` / 98 | 6,106 bytes | 14.02 ms through Trident | 8.49 ms through Trident |
| Structural hash `[15 [1 42]]` | Four field elements / 26 | 47,228 bytes | 70.61 ms through Joy | 68.57 ms through Joy |

Hash result:
`[6803612062017117542, 16108407419388424977, 5953547194136236495, 12113770363582242872]`.

`joy verify loop.zheng --claim 113 --input-values 4` passes in a fresh process.
Changing the claim to `114` or input to `5` returns failure. A request to prove
with secret inputs fails and creates no certificate.

Local binaries, source fixtures, certificates, exact commands, logs and
SHA-256 checksums are retained in
[`joy/target/public-execution-20260911`](../../../joy/target/public-execution-20260911).
These ignored build artifacts are development evidence, not published releases.
The earlier migration candidates retain their original legacy semantics.

## Remaining scope

The supported relation is stateless, bounded and public. It supports the
specified subset of nox tags 0–15, including constrained structural hashing.
Dynamic continuations, calls/lookups, pair equality and branches with different
result shapes are rejected. Both branches are constrained; invalid operations
in an inactive branch can conservatively prevent proving. The budget must cover
the static upper bound, while the selected execution's reduction count is pinned.
See the specification for size limits and precise restrictions.

Private execution, state transitions, hiding, succinct verification and the
remaining legacy release gates are still unresolved. This change closes public
execution/output binding for the stated relation; it does not establish those
other guarantees or complete the full warrior release.
