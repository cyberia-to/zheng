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
  proof size:   ~2 KiB
```

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

see [[recursion]] for the full HyperNova folding protocol. see [[accumulator]] for the accumulator format and serialization. see [[verifier]] for standalone (non-folding) proof verification.
