---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: decide, decider, zheng decider, decide()
---
# decider

the final step of a [[HyperNova]] folding chain. takes an [[accumulator]] that has absorbed N computation steps and produces a single, immediately-verifiable [[zheng]] proof. cost: ~825 constraints — the same whether N is 1 or 1,000,000.

```
decide(accumulator) -> proof
  cost:         ~825 constraints  (CCS jet + batch + algebraic FS)
  verification: 10–50 μs
  proof size:   ~2.4 KiB per decided group (measured, see below)
```

## measured: the universal step decider (0.3.1)

one Layer-1 accumulator per program, closed by one decider. the accumulated instance is the universal step ([[constraints]]): m = 64 rows, 15 matrices, degree ≤ 4, witness padded to n = 128.

| component | size |
|---|---|
| witness commitment + step count | 40 B |
| error vector (64 Goldilocks, varint) | ~0.5 KiB |
| matrix evaluations (15) | ~0.13 KiB |
| outer sumcheck: log m = 6 rounds × degree-5 polynomials | ~0.3 KiB |
| inner sumcheck: log n = 7 rounds × degree-2 polynomials | ~0.2 KiB |
| Brakedown opening at n = 128: 7 round commitments + final polynomial + 140 query indices | ~0.4 KiB |
| **universal group** | **1.1–1.5 KiB** |
| binding group (eq instance: m = 1, 2 matrices, n = 64) | ~1.0 KiB, only when the program opens something |

measured with joy on real programs (postcard wire form, proof only): `(a+b)*a` 1127 B, two `divine()` 1179 B, one `hash` 2154 B, a depth-32 Merkle path of 33 chained hashes (1906 reductions) 2161 B. the size is a constant of the system; the trace length changes only the step count. every byte on the wire is verifier-checked (`zheng::wire`): the opening carries only what `Brakedown::verify` reads — the queried codeword symbols it does not read stay off the wire.

the decider's own cost does not depend on the trace either: one sumcheck over 64 rows, one over 128 columns, one Brakedown opening — the same work for 5 reductions and for 1906.

## what it does

N steps of [[HyperNova]] folding produce an accumulator — a compressed CCS instance that encodes all N computations. the accumulator is an open claim: mathematically sound if all folds were honest, but not yet verifiable by an outside party without running the decider.

the decider closes it. it runs one [[SuperSpartan]] + [[sumcheck]] + [[Brakedown]] check on the folded instance and outputs a standard proof anyone can verify immediately.

```
step_1 → fold → acc_1
step_2 → fold → acc_2
...
step_N → fold → acc_N
                  ↓
            decide(acc_N)       ~825 constraints, once
                  ↓
              proof              verifiable in 10–50 μs
```

## the constant-cost property

the decider's cost does not depend on N. one transaction or one million — the same ~825 constraints.

| computation | folding cost | decider cost | total verifier work |
|---|---|---|---|
| 1 transaction | ~30 field ops | ~825 constraints | ~825 constraints |
| 1,000 txns (block) | ~30K field ops | ~825 constraints | ~825 constraints |
| 1,000 blocks (epoch) | ~30M field ops | ~825 constraints | ~825 constraints |
| full chain history | ~30 · history ops | ~825 constraints | ~825 constraints |

the folding happens on the prover side — cheap (~30 field ops per step). the verifier only ever sees the final decided proof.

## algorithm

```
decide(acc, params):
  1. extract folded CCS instance (E, u, w) from acc
  2. run SuperSpartan sumcheck over the folded CCS matrices
  3. open Brakedown commitment at the sumcheck challenge point r
  4. return (sumcheck_transcript, pcs_opening)
```

cost breakdown:
- CCS jet:              ~400 constraints  (sumcheck over folded matrices)
- batch evaluation:     ~250 constraints  (multi-scalar opening)
- algebraic FS:         ~175 constraints  (transcript binding via [[hemera]])

## when to run

the decider is deferred as long as the accumulator will continue folding. running it collapses the open chain — no further folds can be added.

natural decision points:

| scope | fold until | then decide |
|---|---|---|
| signal | all cyberlinks in the signal | once per signal |
| block | all signals in the block | once per block |
| epoch | all blocks in the epoch | once per epoch |
| sync | universal accumulator from genesis | once on arrival |

a light client that was offline downloads one [[accumulator]] and runs `decide()` once — 10–50 μs — to verify the entire chain from genesis. no block replay. no sequential verification.

## cross-algebra

when the accumulator contains folds from multiple algebras (F_p, F_2, ring), `decide()` runs entirely in F_p. the cross-algebra boundary cost (~766 F_p constraints per crossing) is absorbed into the folding step, not the decider.

## soundness

folding preserves CCS satisfiability. if any step produced a dishonest trace row, the accumulated error term `e` will be non-zero with overwhelming probability over the fold challenge β. the decider checks satisfiability of the folded instance — a non-zero `e` causes it to reject.

**current implementation residual.** the relaxed fold as implemented recomputes `e` from the folded witness and the verifier receives `e` as public accumulator data without a verifier-side fold check (no cross-term commitment chain — Brakedown is not additively homomorphic). for a degree-1 instance this is closed by the zero-error rule: satisfied steps fold to `e = 0` exactly, so the binding group must carry a zero error vector. for the universal instance (degree ≤ 4) the honest error vector is non-zero, so a violated Layer-1 row is not visible to the verifier through `e`; `commit()` refuses to fold one (`CommitError::StepUnsatisfied`), which makes the prover honest but leaves the verifier trusting the fold. closing this needs a verifier-checked fold (a HyperNova-style sumcheck fold or a hash-based accumulation scheme) — the recursion milestone.

**empirically confirmed, 0.3.2.** three attacks were built directly against `decide()`/`verify()`, bypassing `commit()`'s honesty gates entirely (constructing witnesses and, in earlier drafts of these tests, accumulators by hand):

1. a witness with the right shape but a wrong register (e.g. an add row claiming `5 + 3 = 9`) folded through the public `fold_step`/[[fold]] entry point used to be accepted unconditionally — `fold_step` trusted the caller (in practice, only `commit()`'s own separate, caller-side gate, `CommitError::StepUnsatisfied`) to have screened the witness first. **closed in 0.3.2**: the per-witness satisfiability check moved into `fold_step` itself (`FoldError::UnsatisfyingWitness`), so no caller — `commit()`, a downstream crate calling `crate::fold` directly, or a future bug in some other caller — can skip it. `Accumulator`'s fields are also `pub(crate)` now (were `pub`): the type can only be produced by folding through this gate, not by a bare struct literal from outside the crate. Regression: `fold_step_rejects_witness_with_wrong_register` (`rs/src/folding/fold.rs`).
2. a SHARPER bug in the same family: the "constant" witness column (`z[32]` in the universal instance's `Z_LEN = 96` layout, meant to always hold the field element 1) is never independently pinned by any CCS row — every row that references it to mean "the literal 1" (the selector-sum row `Σ s_p − z[32] = 0`, the axis budget row `r9 − r8 + z[32] = 0`, …) is itself gated by a pattern selector that is *also* a free witness column. The all-zero vector — `z[32]` included — therefore satisfies the ENTIRE universal instance exactly (`error_evals` comes back all-zero, not merely undetected): every gated row is `0 × (anything) = 0`, and every ungated row is a homogeneous linear relation among witness columns with no independent additive constant, so it is `0 = 0` too. **NOT closed in 0.3.2** — finding 1's gate cannot reject this witness because it is not lying about its own error; the CCS relation itself does not notice. Closing it needs the constant wire to be independently, verifier-checked pinned to 1 — a public/private witness split (the standard R1CS/CCS construction, where the verifier supplies the "1" and any public inputs directly rather than trusting the prover's commitment for them), or, short of that architecture change, an extra fixed-point PCS opening of the committed witness at column 32 checked to equal 1. `commit()`'s honest path always sets `z[32] = 1` (`ccs::universal::universal_witness`), so real proofs are unaffected; recorded here as follow-up work comparable in size to the universal-step-CCS milestone. Regression: `attack_zeroed_constant_wire_satisfies_universal_instance` (`rs/src/folding/fold.rs`) — left as a passing "attack" test (documents the residual; would need to start failing once this is closed).
3. the deepest residual, unchanged from 0.3.0 and NOT closed by 0.3.2: a witness that is honestly, genuinely satisfying — a real solution of the CCS, `z[32] = 1` included — but corresponds to no real nox execution and bears no relationship to the `Statement`, still decides and verifies for ANY `Statement` the caller supplies. `decide()`'s SuperSpartan sumcheck proves "`e` is consistent with the committed `z`" (and, if the PCS opening is sound, ties `e` to that specific `z`) — it says nothing about whether `z` reflects a real execution, or has anything to do with `program_hash`/`input_hash`/`output_hash`/`focus_bound`/`bbg_root`. `Statement` is absorbed into the Fiat-Shamir transcript, so a proof is bound to the exact statement bytes `decide()` used, but nothing stops a caller from choosing the witness AND the statement independently and honestly with respect to each other. Closing this needs a verifier-checked fold over the N real steps that produced the witness (a HyperNova-style recursive argument, or a hash-based accumulation scheme) — the recursion milestone; no per-witness gate closes it, because there is nothing internally inconsistent to catch. Regression: `attack_satisfying_but_meaningless_witness_passes_for_any_statement` (`rs/src/folding/fold.rs`) — left as a passing "attack" test for the same reason.

**what this means for shipped 0.3.0/0.3.1 proofs.** none of the three findings retroactively invalidate a proof HONESTLY produced by `commit()` from a real nox trace: `commit()`'s own gates (`StepUnsatisfied`, the axis/hash/look `*Binding` gates, `StatementMismatch`) already ensured the witness was a genuine, satisfying encoding of that trace, with `z[32] = 1` by construction — those proofs remain valid and `verify()` accepts them exactly as before. 0.3.2 closes what a caller who bypasses `commit()` and calls the folding API directly could get away with going forward for finding 1; findings 2 and 3 were already true of every prior version back to 0.3.0 (finding 2 further back, to whenever the universal instance landed) and remain true after 0.3.2 — they describe what the accumulator/decider layer alone can and cannot prove about a witness's provenance, independent of which shipped version produced the wire bytes.

**lens residual.** the Brakedown opening as implemented in lens checks that `round_commitments[0]` equals the commitment, that each proximity query index equals the transcript-derived one, and that `final_poly` equals the claimed value. it does not check the queried codeword symbols (a flat hash of the codeword cannot authenticate one symbol) and does not tie consecutive round commitments to each other through the tensor reduction — so the opening does not yet bind the claimed evaluation to the committed polynomial. the proximity test is owed by lens; zheng's wire form carries only what the verifier reads today, and grows when the verifier does.

see [[recursion]] for the full HyperNova folding protocol. see [[accumulator]] for the accumulator format and serialization. see [[verifier]] for standalone (non-folding) proof verification.
