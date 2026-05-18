# zheng audit fix plan — release tier

synthesized from three-agent parallel audit (2026-05-17).
agents covered: ccs/types/transcript, sumcheck/spartan, folding/lib.
no code changes applied yet. user reviews this plan before fixes begin.

---

## tier 1 — safety: eliminate panics in library code

### S-1: `mul_vec` out-of-bounds on column index
**file:** `src/types.rs:156`
**code:** `out[i] += c * z[j];`
**problem:** panics if any matrix entry has `col >= z.len()`. occurs on adversarial
or incorrectly constructed CCS instances. audit agents 2 and 3 both flagged.
**fix:** `z.get(j).copied().unwrap_or(Goldilocks::ZERO)` — mirrors how eval_matrix()
in fold.rs already handles this (line 24). one-line change.

### S-2: `evals_to_coeffs` panics on empty input
**file:** `src/multilinear.rs:64`
**code:** `let d = evals.len() - 1;`
**problem:** integer underflow panic when `evals` is empty. called from sumcheck
prover which could receive zero-length input under malformed CCS.
**fix:** early return `vec![]` if `evals.is_empty()`.

### S-3: `fold_inplace` debug_assert stripped in release
**file:** `src/multilinear.rs:33`
**code:** `debug_assert!(sz >= 2 && sz.is_power_of_two(), ...)`
**problem:** assertion only fires in debug builds. in release, calling fold_inplace
with sz=1 or non-power-of-two silently produces wrong output (half of 1 = 0,
truncate to empty). this corrupts the sumcheck without any error.
**fix:** change to `assert!` — this is an invariant the caller must enforce,
and silent corruption is worse than a panic.

### S-4: `build_axis_steps_from_trace` panics on short openings slice
**file:** `src/ccs/mod.rs:116`
**code:** `let ao = &openings[opening_idx];`
**problem:** panics with `index out of bounds` if caller provides fewer axis
openings than axis rows in the trace. documented in a comment above (line 107-108)
but a comment is not a safeguard.
**fix:** change return type to `Result<Vec<(CCSInstance, CCSWitness)>, CommitError>`,
return `Err(CommitError::TraceOverflow)` on short slice.
update `build_ccs_from_trace` call-site in `lib.rs:94` accordingly.

### S-5: `build_hash_steps_from_trace` panics on short aux slice
**file:** `src/ccs/particle.rs` (exact line: verify before fix)
**problem:** parallel to S-4 — panics if `hash_aux` has fewer entries than
Poseidon2 hash blocks in the trace.
**fix:** same pattern — return `Result<..., CommitError>` and propagate in lib.rs.

---

## tier 2 — correctness: wrong behavior, not just wrong error

### C-1: verifier silently ignores invalid multiset index
**file:** `src/spartan/verifier.rs:49`
**code:** `proof.matrix_evals.get(idx).copied().unwrap_or(Goldilocks::ZERO)`
**problem:** if multiset contains an index beyond `matrix_evals`, the product
uses 0 for that factor. this does not fail verification — the constraint check
at line 53 still passes if the malformed proof was crafted accordingly.
soundness hole: prover could produce a proof where some matrix indices are
out-of-range and the 0-replacement makes the CCS constraint appear satisfied.
**fix:** replace `unwrap_or(Goldilocks::ZERO)` with:
```rust
.ok_or(VerifyError::EvaluationMismatch)?
```
requires the fold to produce an error instead of a silent zero.

### C-2: test names swapped in `sumcheck/verifier.rs`
**file:** `src/sumcheck/verifier.rs:83,97`
**problem:** `consistency_check_rejects_wrong_sum` (line 83) actually calls `assert!(... .is_ok())`
— it accepts a correct sum, not rejects a wrong one.
`consistency_check_accepts_correct_sum` (line 97) calls `assert!(... .is_err())`
— it rejects a bad sum. names are inverted.
**fix:** swap the function names. logic is correct.

### C-3: `SparseMatrix::mul_vec` used in `is_satisfied_by` vs `eval_matrix` divergence
**file:** `src/types.rs:183-198`
**note:** `is_satisfied_by` calls `mul_vec(z)` which after fix S-1 will silently
zero OOB columns. This is consistent with how `eval_matrix` in fold.rs behaves.
No additional fix needed beyond S-1 — document in is_satisfied_by's comment that
OOB column indices evaluate as zero.

### C-4: tag truncation `r()[0] as u8`
**file:** `src/ccs/mod.rs:82,83`
**code:** `let tag_t = w[0].r()[0] as u8;`
**problem:** truncating cast — if a malicious witness stores r[0] = 256, it reads
as tag 0 (axis), bypassing the intended constraint. nox VM only writes tags 0-17,
so this is not exploitable from honest traces. but for soundness against arbitrary
witness inputs, the cast should be bounds-checked.
**fix:** `let tag_t = u8::try_from(w[0].r()[0]).unwrap_or(255);` — tag 255
falls through to `trivial_ccs()` which is the correct handling for unknown tags.

### C-5: `fold()` public API breaks Fiat-Shamir chaining
**file:** `src/lib.rs:226-233`
**problem:** `pub fn fold()` creates `Transcript::new()` on each call. a user
calling `fold()` N times then `decide()` gets N independent transcripts instead
of one chained transcript per group. this means beta challenges are not bound to
the accumulated commitment chain, breaking HyperNova's Fiat-Shamir soundness for
sequential use. the internal `commit()` function handles this correctly by sharing
`cur_transcript` across the group (lib.rs:116-134).
**fix:** either:
  - (preferred) remove `pub fn fold()` — it is not used by `commit()` and is unsound as exposed
  - or change signature to `fold(acc, instance, witness, transcript: &mut Transcript)`
    and let caller own the transcript

---

## tier 3 — architecture: design issues worth fixing before release

### A-1: `DecideError` mapping loses context
**file:** `src/lib.rs:124-125`
**code:** `.map_err(|_| CommitError::TraceOverflow)?`
**problem:** `run_decide` can return `DecideError::EmptyAccumulator`,
`DecideError::SumcheckFailed { round }`, or `DecideError::LensFailed`.
all are collapsed to `CommitError::TraceOverflow`, making it impossible to
distinguish a prover bug (SumcheckFailed) from a capacity issue (TraceOverflow).
**fix:** add `CommitError::DecideFailed(DecideError)` variant and propagate.
or at minimum `CommitError::ProveFailed` vs `CommitError::TraceOverflow`.

### A-2: `fold_step` / `commit()` use different committed_instance logic
**file:** `src/folding/fold.rs:99`
**code:** `if acc.committed_instance.matrices.len() != instance.matrices.len()`
**problem:** structure check only compares matrix count. after fix in lib.rs
(full CCSInstance equality for grouping), fold_step itself still only checks
`matrices.len()`. if two instances have the same matrix count but different
coefficients, fold_step proceeds without error while the verifier will check
against `committed_instance` (the first instance). result: soundness issue if
someone uses the lower-level `fold_step` directly.
**fix:** add full equality check in fold_step: `if acc.step_count > 0 && acc.committed_instance != *instance`.
requires CCSInstance: PartialEq (already derived).

### A-3: multi-row enforcement limitation — promote the warning
**file:** `src/ccs/particle.rs:27-30`
**current:** NOTE comment in particle.rs module doc.
**problem:** the limitation is only visible if you read particle.rs. prover.rs
and fold.rs have no indication that they only enforce row 0 of each matrix.
**fix:** add a module-level `//! NOTE: m=1 implementation...` to both
`spartan/prover.rs` and `folding/fold.rs` so the limitation is visible at each
site that makes the m=1 assumption.

---

## tier 4 — tests: property coverage for release

### T-1: fold determinism property test
**location:** `src/folding/fold.rs` tests section
**property:** `fold_step(acc.clone(), instance, witness, &mut Transcript::new())`
called twice with identical inputs produces identical accumulators.
**why:** confirms transcript is stateless between independent fold sequences
and that beta derives purely from the absorbed data.

### T-2: single-byte flip rejection test
**location:** `src/lib.rs` tests section or `src/spartan/` tests
**property:** take a valid `TraceProof`, flip one byte in `pcs_opening`,
call `verify()` → must return `Err(VerifyError::LensFailed)`.
**why:** basic anti-tamper coverage; required for release-tier pass 12.

### T-3: `mul_vec` OOB test (regression for S-1)
**location:** `src/types.rs` tests section
**property:** `SparseMatrix::mul_vec` with a column index beyond z.len() returns
zero, does not panic.

---

## deferred — not in this release

### D-1: multi-row CCS enforcement (m > 1)
fully enforcing all 16 rows of the Poseidon2 partial-round CCS requires:
- sumcheck prover: sum over all matrix rows instead of row 0
- fold.rs: `eval_matrix` currently sums all rows, which is already correct —
  the limitation is that Spartan only encodes û_i for row 0
- `spartan/prover.rs`: `matrix_dot` sums all rows correctly; the issue is
  the decider only proves one û_i per matrix, so multi-row constraints collapse
see particle.rs lines 27-30 for the canonical note. this is a Phase 6 item
in the original release-plan.md.

---

## execution order

1. **S-1, S-2, S-3** — multilinear/types — single file each, no API change
2. **S-4, S-5** — signature change in ccs/mod.rs and particle.rs → update lib.rs call-sites
3. **C-1** — verifier.rs — one-line change, add `?`
4. **C-2** — rename two test functions (zero logic change)
5. **C-4** — ccs/mod.rs — two-line change
6. **C-5** — remove or redesign `pub fn fold()`
7. **A-1** — add CommitError variant, update mapping
8. **A-2** — add full equality check to fold_step
9. **A-3** — add two module-level comments
10. **T-1, T-2, T-3** — new tests (can run in parallel with A-*)

estimated: 2-3 pomodoros for S-tier and C-tier; 1 pomodoro for A-tier and T-tier.
