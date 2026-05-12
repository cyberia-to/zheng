# zheng: release-grade implementation plan

## goal

working prover hitting spec numbers: ~2 KiB proof, ~5 μs verify, ~825-constraint decider.
lens from day one.

## module structure

```
src/
  lib.rs           commit, open, verify, fold, decide (API)
  types.rs         Proof, Statement, ProofParams, Accumulator,
                   CCSInstance, CCSWitness, error enums
  transcript.rs    Fiat-Shamir over hemera, domain separators, wire encoding
  multilinear.rs   MultilinearPoly<F>, bookkeeping table, evaluate()
  sumcheck/
    prover.rs      round-poly construction, bookkeeping fold, O(N)
    verifier.rs    consistency checks, squeeze challenges
  ccs/
    mod.rs         CCSInstance construction from trace, sparse matrix
    patterns.rs    17 nox pattern constraint encodings
    selector.rs    Lagrange selectors, universal + boundary constraints
  spartan/
    prover.rs      outer + inner sumchecks, MLE of M·z, lens::commit + open
    verifier.rs    VERIFY algorithm from specs/verifier.md
  folding/
    fold.rs        cross-term, beta challenge, fold()
    decide.rs      decider: SuperSpartan on folded CCS
```

## phases

### phase 0: cargo + types (1 session)

fix `Cargo.toml`:
- `nebu = { path = "../strata/nebu/rs", package = "cyb-nebu" }`
- `lens = { path = "../lens/src", package = "cyber-lens" }`
- `hemera = { package = "cyber-hemera", version = "0.2" }`
- `nox = { path = "../nox/rs" }`

`src/types.rs`: Proof, Statement, ProofParams, Accumulator, CCSInstance, CCSWitness,
LensBackend enum (Brakedown default, Binius secondary), SecurityLevel, all error enums.

deliverable: `cargo check` passes.

### phase 1: transcript (1 session)

`src/transcript.rs` per specs/transcript.md:
- hemera sponge wrapper: absorb() + squeeze()
- domain separators: DOMAIN_SEP, COMMIT, SUMCHECK_ROUND_i, EVAL, PCS_OPEN, RECURSE
- canonical wire encoding: GoldilocksElement (8-byte LE), Commitment (32 bytes),
  SumcheckPoly (degree u8 + coefficients), BrakedownProof (recursive levels)

tests:
- same message sequence → same challenges
- different domain separators → different outputs on identical messages
- GoldilocksElement encoding rejects v >= p

### phase 2: multilinear + sumcheck (3 sessions)

`src/multilinear.rs`:
- MultilinearPoly<F> over &[F] evaluations (length must be 2^k)
- bookkeeping table: the halving structure used by sumcheck prover
- evaluate(point: &[F]) -> F

`src/sumcheck/prover.rs`:
- build_round_poly(): sum out one variable, keep earlier pinned to challenges
- evaluates g_i at d+1 points (degree d = max constraint degree for current CCS)
- bookkeeping fold after each round

`src/sumcheck/verifier.rs`:
- check g_i(0) + g_i(1) == claim_{i-1} each round
- absorb g_i, squeeze challenge r_i
- return final claim + evaluation point r = (r_1, ..., r_k)

tests:
- property: prove(f) → verify(proof) always accepts
- property: any modified proof always rejected
- degree-1 and degree-7 polynomials
- edge: k=1 (single-variable)

### phase 3: CCS encoding (4 sessions)

`src/ccs/mod.rs`:
- SparseMatrix (row-indexed CSR, entries are (col, coeff) pairs)
- CCSInstance: matrices M_1..M_t, index sets S_j, coefficients c_j
- CCSWitness: z vector = trace row t || trace row t+1 || constant 1
- build_ccs_from_trace(trace: &ExecutionTrace) -> Vec<(CCSInstance, CCSWitness)>

`src/ccs/patterns.rs` — one function per nox pattern returning (matrices, sets, coeffs):
- 5, 6 (add, sub): degree 1, 3 matrices, 3 terms
- 7, 8, 9 (mul, inv, eq): degree 2
- 10-14 (lt, xor, and, not, shl): bit-decomposition chains, ~64 sub-constraints each
- 15 (hash): Poseidon2 S-box decomposition, 4 degree-2 sub-constraints per state element
- 0-4 (axis, quote, compose, cons, branch): tree + control patterns
- 16 (hint): stub — status-unchanged constraint only

`src/ccs/selector.rs`:
- selector_p(v0): Lagrange interpolation over {0..16}
- constraint_eval(v, r, statement): eq(r_row, r) * sum_p selector_p * C_p
- universal constraints: focus accounting, step index, halting
- boundary constraints: input/output hashes, status, focus bound

tests:
- each pattern: satisfying row → constraint evaluates to zero
- adversarial: wrong register value → constraint non-zero
- selector_p(p) = 1, selector_p(q) = 0 for p ≠ q

### phase 4: SuperSpartan IOP (3 sessions)

`src/spartan/prover.rs`:
1. for each M_i: compute MLE û_i(y) = sum_x M̃_i(y,x) * ẑ(x) via inner sumcheck
2. outer sumcheck: sum_{x} eq(r,x) * g(x) = 0, g(x) = sum_j c_j * prod_{i in S_j} û_i(x)
3. inner sumchecks: reduce each û_i(s) to ẑ(t)
4. lens::Brakedown::commit(ẑ), lens::Brakedown::open(ẑ, t, transcript)

`src/spartan/verifier.rs` — exactly the VERIFY algorithm from specs/verifier.md:
- init transcript, absorb statement + commitment
- sumcheck rounds (step 2)
- constraint_eval check (step 3)
- lens::Brakedown::verify (step 4)

tests:
- prove(valid_trace) → verify always accepts
- one row modified → verify rejects
- proof size within 10% of ~2 KiB at N=2^20
- verify time within 2x of ~5 μs

### phase 5: HyperNova folding (3 sessions)

`src/folding/fold.rs`:
- cross_term(acc, instance) per specs/recursion.md
- fold(acc, instance, witness, transcript): beta from transcript,
  fold instances/witnesses/error terms, update commitment
- fold_row(acc, row_t, row_{t+1}): sliding-window wrapper for AIR

`src/folding/decide.rs`:
- decide(acc, params): SuperSpartan + Brakedown proof on folded CCS

`src/lib.rs` — five API entry points wired through all layers:
- commit(): execute nox → trace → CCS → SuperSpartan → (Proof, Accumulator)
- open(): Brakedown opening at sumcheck output point
- verify(): standalone verifier
- fold(): HyperNova fold step
- decide(): decider for accumulated folds

tests:
- single fold: fold(empty_acc, instance) → decide() → verifies
- 100-fold sequence: correct proof at the end
- mismatched instance → decide() rejects
- Accumulator serialization round-trip (~200 bytes)

### phase 6: test vectors + property tests (3 sessions)

test vectors in `tests/vectors/`:
- full prove/verify per pattern: 1, 5, 7, 8, 15
- one sumcheck transcript for degree-7 polynomial
- one fold+decide sequence (3 steps)

property tests:
- for all valid traces: prove → verify always accepts
- for all proofs: any single byte flip → verify rejects
- Accumulator::empty() as identity for first fold
- fold is deterministic (same inputs → same accumulator)

### phase 7: benchmarks + optimization (3 sessions)

targets from specs/verifier.md:

| metric | spec | acceptable |
|--------|------|------------|
| proof size (N=2^20) | ~2 KiB | ≤ 2.5 KiB |
| verify time | ~5 μs | ≤ 10 μs |
| decider constraints | ~825 | ≤ 1000 |

optimization levers in order of impact:
1. batch lens opening: all û_i share one Brakedown opening
2. algebraic Fiat-Shamir: replace hemera in inner rounds with field arithmetic
3. CCS jet: precomputed constraint eval for common pattern combinations
4. rayon parallel bookkeeping fold for N > 2^18

## deferred (not in this release)

- tensor prover (O(√N) memory) — specs/tensor.md
- cross-algebra folding (sel_Fp / sel_F2) — needs binius patterns in nox first
- pattern 16 full hint elaboration — Layer 1 interface not yet defined
- GPU prover — roadmap/gpu-prover.md
- gravity-commitment — roadmap/gravity-commitment.md

## release audit (quality.md release-tier)

passes 1, 3, 4, 5, 6, 11, 12:
- 1: no float, no non-deterministic iteration, canonical encoding
- 3: all Goldilocks reductions correct, no overflow before reduce
- 4: hemera domain-separated per phase, no secret-dependent branching
- 5: newtypes (Commitment, round index), no unwrap in library code
- 6: every error meaningful, no panic in library code
- 11: proof size measured, O(N) prover verified empirically
- 12: property tests for all invariants, edge cases: empty trace, max rows, malformed proof
