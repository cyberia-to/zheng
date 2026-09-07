# axis (pattern 0) + look (pattern 17): verifier_steps() integration

## status: approved 2026-09-07 — part of trident soft3-release M4

## context

`verifier_steps()` is implemented (`zheng/src/ccs/verifier_steps.rs`, 62 tests pass).
The function encodes a Brakedown opening as a flat sequence of m=1 CCS instances
with `VZ_LEN=3` ([a, b, 1]). All steps are structurally uniform — they fold.

`pattern_axis()` and `pattern_look_inline()` both return `trivial_ccs()` — the proof
system currently does not verify Lens/Brakedown openings. This is a soundness gap:
a prover can return any value for any axis or look instruction.

## the core problem

Main trace CCS steps use `Z_LEN=33` (16 registers at t, 16 at t+1, constant 1).
Verifier steps use `VZ_LEN=3`. These cannot be folded into the same accumulator
because `fold_step()` rejects mismatched `num_cols` as `FoldError::InstanceMismatch`.

**Solution: two-accumulator design.**

```
main_acc:  fold all per-row nox trace CCS steps  (num_cols = 33)
axis_acc:  fold all verifier_steps() sequences    (num_cols = 3)
```

The decider runs `decide()` on both, producing two proofs. The verifier checks both.

## linkage constraint (what prevents the prover from cheating)

Without linkage, a prover could provide a valid axis_acc for a *different* opening
than what the main trace's axis row used. The inline constraint in pattern_axis()
must bind the axis row's commitment/value fields to the axis_acc binding steps.

Specifically, verifier_steps() already emits 4 `eq_step` binding checks:
```
eq_step(rc0_limb_k, commitment_limb_k)  for k = 0..3
```
where `rc0` is the round_commitments[0] in the opening (the "outer Brakedown
commitment" that the verifier checks matches the prover's committed polynomial).

For axis (pattern 0), r4 = noun polynomial commitment. The linkage is:
```
axis_row.r4 == axis_acc.binding_commitment
```

This cross-accumulator reference is the architectural crux. Options:

### option A: hash-of-commitment linkage (recommended)

The main proof absorbs `axis_acc.witness_commitment` into the Fiat-Shamir transcript.
The verifier independently computes the same commitment from the axis opening it verifies.
No additional inline constraint in pattern_axis() — the shared transcript enforces linkage.

Advantages: no new pattern_axis() constraint, no nox trace change, works now.
Limitation: implicit linkage via Fiat-Shamir; not an explicit circuit constraint.

### option B: inline commitment constraint

Add `r7..r10` to the axis trace row to carry the Brakedown commitment bytes (4×8 bytes
= 32 bytes = 4 Goldilocks elements). Then pattern_axis() can verify:
```
r7 = commitment_limb_0
r8 = commitment_limb_1   (wait: r8 = budget_in, CONFLICT)
```
But r8 = budget_in, r9 = budget_out. Reserved slots r10-r13 are free for axis (4 regs
= 32 bytes = exactly one Brakedown commitment).

So with nox emitting commitment in r10-r13:
```rust
fn pattern_axis() -> CCSInstance {
    // axis_commitment_limb_k = r10+k_t (k = 0..3)
    // eq_step links these to axis_acc's binding steps
    // 4 eq constraints between r10..r13 and the axis_acc binding commitment
}
```

This requires a nox trace update (emit commitment in r10-r13 for pattern 0).
Advantage: explicit verifiable circuit constraint.

## current nox trace layout for axis (from nox/specs/trace.md)

```
r4  = noun polynomial commitment  — Lens commitment to the object noun polynomial
r5  = axis index
r6  = evaluation point
r7  = result value
r10-r15 = 0 (reserved, unused)
```

The commitment (r4) is already in the trace. The opening proof itself is NOT in the
trace (unlike look/17 which embeds proof elements in r7/r10/r11).

For axis, since r4 = commitment already, option A (Fiat-Shamir linkage via r4) is
sufficient without any nox trace change.

## implementation plan

### phase 1: two-accumulator infrastructure (no nox change needed)

1. **`src/types.rs`**: Add `AxisAccumulator` or reuse `Accumulator` with a flag.
   Actually: `Accumulator` already works for VZ_LEN=3 steps; just use a second
   instance. No new type needed.

2. **`src/ccs/mod.rs`**: Add `build_axis_steps_from_trace(trace, openings)`.
   Signature:
   ```rust
   pub fn build_axis_steps_from_trace(
       trace: &[TraceRow],
       openings: &[(Commitment, Vec<Goldilocks>, Goldilocks, Opening)],
   ) -> Vec<(CCSInstance, CCSWitness)>
   ```
   Scans for rows with `r0 == 0` (axis), calls `verifier_steps()` for each,
   flattens into one sequence. The `openings` slice is prover-provided and
   parallel to the axis rows in order.

3. **`src/lib.rs`**: The `commit()` entry point needs to:
   - Execute nox → trace
   - For each axis row, perform the Brakedown opening and collect `(commitment, point, value, opening)`
   - Build `main_steps` via `build_ccs_from_trace()`
   - Build `axis_steps` via `build_axis_steps_from_trace()`
   - Fold `main_steps` → `main_acc`, fold `axis_steps` → `axis_acc`
   - Return both accumulators

4. **`src/folding/decide.rs`**: Extend `decide()` or add `decide_pair()` that takes
   `(main_acc, axis_acc)` and returns `(main_proof, axis_proof)`.

5. **`src/spartan/verifier.rs`**: Extend `verify()` or add `verify_pair()`.

### phase 2: inline pattern_axis() linkage constraint (option A)

pattern_axis() encodes the budget constraint only (inline linear):
```
r9_t = r8_t - 1  →  r9_t - r8_t + 1 = 0
```
Using existing `select_matrix` on `reg_t(9)`, `reg_t(8)`, `CONST_IDX`:
```rust
fn pattern_axis() -> CCSInstance {
    let m_r9 = select_matrix(reg_t(9));
    let m_r8 = select_matrix(reg_t(8));
    let m_c  = select_matrix(CONST_IDX);
    build_ccs(vec![m_r9, m_r8, m_c], vec![
        (vec![0], Goldilocks::ONE),  // +r9
        (vec![1], neg_one()),        // -r8
        (vec![2], Goldilocks::ONE),  // +1 (= +const)
    ])
}
```
The Brakedown opening correctness is guaranteed by the axis_acc; the Fiat-Shamir
transcript of the main proof absorbs both commitments, providing implicit linkage.

### phase 3: option B inline commitment constraint (requires nox update)

Deferred. Requires nox to emit commitment bytes in r10-r13 for pattern 0.
If nox adds this, pattern_axis() can be upgraded to 4 explicit eq constraints
that bind the axis row's commitment to the axis_acc binding steps.

## what blocks each phase

| phase | blocker |
|-------|---------|
| 1 (two-acc infra) | none — can implement now |
| 2 (budget constraint) | none — can implement now |
| 3 (option B commitment constraint) | nox trace update for axis r10-r13 |
| look (pattern 17) | BBG_root in Statement (blocked on bbg) |

## implemented (2026-09-07, branch feat/axis-openings)

The repo had grown past this plan's draft state before implementation began:
`build_axis_steps_from_trace()`, the `pattern_axis()` budget constraint,
per-CCS-structure accumulator groups in `commit()` (a generalization of the
two-accumulator design — one group per distinct instance, so main/hash/axis/
look each land in their own accumulators), and the full look (17) binding
suite were already in place. What this milestone added:

### 1. axis trace bindings (`rs/src/ccs/mod.rs`)

For every prover-active axis row (r11-r14 non-zero, i.e. the executor's
`CallProvider::axis_commitment()` was live), `build_axis_steps_from_trace()`
now emits eq steps binding the opening to the trace:

- commitment limbs ↔ r11-r14
- evaluation point ↔ `axis_eval_point(r5)` (binary path of the axis address)
- opened value ↔ r7 (result particle)

A strictness gate rejects at commit time (`CommitError::AxisBinding`).
This settles the axis opening derivation: **point = binary path of r5,
value = r7, commitment = r11-r14**. Interpreter mode (NullCalls, registers
zero) keeps opening-only behavior per specs/trace.md.

### 2. option A linkage (`rs/src/lib.rs`, `rs/src/folding/decide.rs`, `rs/src/transcript.rs`)

`linkage_digest` = hemera hash over group count + every group's witness
commitment in order. `commit()` folds all groups first, computes the digest,
then decides each group with the digest absorbed (domain `\x08linkage`)
right after the statement. `verify()` recomputes the digest from the proof's
own groups and absorbs identically. Demonstrated: without the digest, an
axis group spliced from another valid proof verifies (test observed
accepting before the change); with it, splicing breaks every group's
Fiat-Shamir chain (`verify_rejects_spliced_axis_group`).

### 3. zero-error rule for degree-1 groups (`rs/src/lib.rs::verify`)

Error is linear in the witness for degree-1 CCS, so satisfied steps fold to
exactly zero error. `verify()` now rejects (`VerifyError::LinearErrorNonzero`)
any all-linear group carrying a non-zero error term — closing the relaxed-
fold loophole where a malicious prover folds an unsatisfied binding step and
reports its honest error. Negative tests fold a wrong-commitment binding and
a forged-result binding directly (bypassing the commit gate) and are
rejected at verify time.

### surfaced by the zero-error rule: pattern_quote fix

The quote constraint was stale (r5_{t+1} = r4_t, cross-row) and no real
trace satisfied it — the relaxed fold masked the violation. Fixed to the
spec's r7 = r4 (same row). Any linear pattern that real traces violate
would now surface the same way; compose (2) and cons (3) still use the
old cross-row wiring (r5_{t+1} = r3_t) and are untested against real
traces — flagged for the same treatment when their e2e coverage lands.

### known limitation (accepted by option A)

The eq-step witnesses binding opening ↔ trace registers are prover-supplied;
no cross-accumulator constraint forces them to equal the main accumulator's
committed register values. A fully malicious prover who *omits or rewrites*
binding steps is not caught by the verifier — the linkage digest binds
groups to each other, not step content to the main trace witness. Closing
this requires option B (commitment limbs constrained inside pattern_axis(),
nox already emits r11-r14) plus recursion over the step count, or a
permutation argument across accumulators. Tracked as the residual gap for
the recursion milestone.

## remaining

- phase 3 / option B: explicit r11-r14 constraint in pattern_axis()
  (nox already emits the limbs; needs per-row constant matrices at fold time)
- hash openings: same binding treatment for pattern 15 sponge inputs
- look (17): bindings already implemented pre-milestone; BBG_root in
  Statement still blocked on bbg
