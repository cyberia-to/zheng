// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! HyperNova fold: cross-term computation, beta challenge, witness folding.
//!
//! For a sequence of CCS instances all sharing the same structure,
//! fold() accumulates them into a single accumulator. The decider then
//! proves the accumulated instance is satisfiable.

use nebu::Goldilocks;

use lens::brakedown::Brakedown;

use crate::multilinear::pad_to_power_of_two;
use crate::transcript::Transcript;
use crate::types::{Accumulator, CCSInstance, CCSWitness, FoldError};

/// Compute M[row r] · z — the dot product for a single row.
fn row_dot(matrix: &crate::types::SparseMatrix, r: usize, z: &[Goldilocks]) -> Goldilocks {
    matrix.entries.get(r).map_or(Goldilocks::ZERO, |row| {
        row.iter().fold(Goldilocks::ZERO, |acc, &(col, c)| {
            acc + c * z.get(col).copied().unwrap_or(Goldilocks::ZERO)
        })
    })
}

/// Compute the HyperNova cross-term vector T (one entry per row).
///
/// For each degree-2 term and each row r:
///   T[r] = c · ((M_i[r]·w_acc)·(M_k[r]·w_new) + (M_i[r]·w_new)·(M_k[r]·w_acc))
///
/// Row-by-row computation ensures only diagonal contributions appear (r=s terms).
fn cross_term(instance: &CCSInstance, w_acc: &[Goldilocks], w_new: &[Goldilocks]) -> Vec<Goldilocks> {
    let m = instance.num_rows;
    let mut t = vec![Goldilocks::ZERO; m];
    for (multiset, &coeff) in instance.multisets.iter().zip(instance.coeffs.iter()) {
        if multiset.len() < 2 {
            continue;
        }
        let i = multiset[0];
        let k = multiset[1];
        for (r, t_r) in t.iter_mut().enumerate() {
            let mi_acc_r = row_dot(&instance.matrices[i], r, w_acc);
            let mk_acc_r = row_dot(&instance.matrices[k], r, w_acc);
            let mi_new_r = row_dot(&instance.matrices[i], r, w_new);
            let mk_new_r = row_dot(&instance.matrices[k], r, w_new);
            *t_r += coeff * (mi_acc_r * mk_new_r + mi_new_r * mk_acc_r);
        }
    }
    t
}

/// Compute the per-row CCS error vector from a witness.
///
/// error_evals[r] = Σ_j c_j · ∏_{i ∈ S_j} (M_i[row r] · z)
/// For a satisfying witness, all entries are 0.
pub(crate) fn error_evals(instance: &CCSInstance, z: &[Goldilocks]) -> Vec<Goldilocks> {
    let m = instance.num_rows;
    let mut e = vec![Goldilocks::ZERO; m];
    for (multiset, &coeff) in instance.multisets.iter().zip(instance.coeffs.iter()) {
        for (r, e_r) in e.iter_mut().enumerate() {
            let product = multiset.iter().fold(Goldilocks::ONE, |p, &idx| {
                p * row_dot(&instance.matrices[idx], r, z)
            });
            *e_r += coeff * product;
        }
    }
    e
}

/// Fold one CCS step into the accumulator.
///
/// On the first fold (step_count == 0): adopt the instance and witness directly.
/// On subsequent folds: apply the HyperNova fold protocol.
///
/// Rejects a fresh `witness` that does not individually satisfy `instance`
/// (`FoldError::UnsatisfyingWitness`) BEFORE folding it in. `commit()`
/// already filters every real trace pair this way
/// (`CommitError::StepUnsatisfied`); enforcing it here too means the check
/// cannot be skipped by a caller that reaches `fold_step`/[`crate::fold`]
/// directly, bypassing `commit()` — e.g. a downstream crate calling the
/// public folding API by hand. This does not, by itself, prove `witness`
/// reflects a real nox execution — only that it is a genuine solution of
/// `instance` — see [`FoldError::UnsatisfyingWitness`] and
/// `specs/decider.md` §soundness for the residual this does not close.
pub fn fold_step(
    acc: &mut Accumulator,
    instance: &CCSInstance,
    witness: &CCSWitness,
    transcript: &mut Transcript,
) -> Result<(), FoldError> {
    let mut z_new = witness.z.clone();
    pad_to_power_of_two(&mut z_new, 64);
    let z_new_error = error_evals(instance, &z_new);
    if z_new_error.iter().any(|&e| e != Goldilocks::ZERO) {
        return Err(FoldError::UnsatisfyingWitness);
    }
    fold_step_inner(acc, instance, z_new, z_new_error, transcript)
}

/// Fold-in logic with no satisfiability gate — the pre-fix behavior of
/// `fold_step`, kept only so tests can build the accumulator a party who
/// bypasses BOTH `commit()`'s strictness gates AND `fold_step`'s own gate
/// would get, to check that `decide()`/`verify()` still behave correctly (or
/// document that they don't) in that scenario. No production caller reaches
/// this; [`fold_step`] is the only public entry point, and it always gates
/// first.
#[cfg(test)]
pub(crate) fn fold_step_unchecked(
    acc: &mut Accumulator,
    instance: &CCSInstance,
    witness: &CCSWitness,
    transcript: &mut Transcript,
) -> Result<(), FoldError> {
    let mut z_new = witness.z.clone();
    pad_to_power_of_two(&mut z_new, 64);
    let z_new_error = error_evals(instance, &z_new);
    fold_step_inner(acc, instance, z_new, z_new_error, transcript)
}

/// Pad new witness to 64 elements (2^6) for PCS compatibility (already done
/// by callers), then run the HyperNova fold. `z_new_error` is
/// `error_evals(instance, &z_new)`, computed once by the caller.
fn fold_step_inner(
    acc: &mut Accumulator,
    instance: &CCSInstance,
    z_new: Vec<Goldilocks>,
    z_new_error: Vec<Goldilocks>,
    transcript: &mut Transcript,
) -> Result<(), FoldError> {
    if acc.step_count == 0 {
        // First fold: adopt the CCS structure and witness directly.
        acc.committed_instance = instance.clone();
        acc.folded_witness = CCSWitness { z: z_new.clone() };
        acc.witness_commitment = Brakedown::commit_raw(&z_new);
        acc.error_evals = z_new_error;
        acc.step_count = 1;
        return Ok(());
    }

    // Verify the instance matches the accumulator exactly.
    if acc.committed_instance != *instance {
        return Err(FoldError::InstanceMismatch);
    }

    let w_acc = &acc.folded_witness.z;
    if w_acc.len() != z_new.len() {
        return Err(FoldError::WitnessMismatch);
    }

    // ── HyperNova fold ───────────────────────────────────────────────────────

    // 1. Compute cross-term T for Fiat-Shamir binding.
    let t = cross_term(instance, w_acc, &z_new);

    // 2. Derive beta from transcript.
    transcript.absorb(acc.witness_commitment.as_bytes());
    let new_commitment = Brakedown::commit_raw(&z_new);
    transcript.absorb(new_commitment.as_bytes());
    for &t_r in &t {
        transcript.absorb(&t_r.as_u64().to_le_bytes());
    }
    let beta = transcript.squeeze_challenge();

    // 3. Fold witnesses: w_folded = w_acc + beta · w_new
    let mut w_folded = w_acc.clone();
    for (wf, &wn) in w_folded.iter_mut().zip(z_new.iter()) {
        *wf += beta * wn;
    }

    // 4. Fold error: evaluate constraint on the folded witness directly.
    let e_folded = error_evals(instance, &w_folded);

    // 5. Update commitment.
    let c_folded = Brakedown::commit_raw(&w_folded);

    acc.folded_witness = CCSWitness { z: w_folded };
    acc.witness_commitment = c_folded;
    acc.error_evals = e_folded;
    acc.step_count += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::universal::{test_witness, universal_ccs};
    use crate::ccs::reg_t;

    fn zero_accumulator(instance: &CCSInstance) -> Accumulator {
        let z = vec![Goldilocks::ZERO; 64];
        Accumulator {
            committed_instance: instance.clone(),
            folded_witness: CCSWitness { z: z.clone() },
            witness_commitment: Brakedown::commit_raw(&z),
            error_evals: vec![Goldilocks::ZERO; instance.num_rows],
            step_count: 0,
        }
    }

    /// An add row (tag 5): r6 = r4 + r5.
    fn make_witness(r4: u64, r5: u64, r6: u64) -> CCSWitness {
        test_witness(&[(reg_t(0), 5), (reg_t(4), r4), (reg_t(5), r5), (reg_t(6), r6)])
    }

    #[test]
    fn first_fold_adopts_witness() {
        let instance = universal_ccs().clone();
        let witness = make_witness(5, 3, 8);
        let mut acc = zero_accumulator(&instance);
        let mut transcript = Transcript::new();
        fold_step(&mut acc, &instance, &witness, &mut transcript).unwrap();
        assert_eq!(acc.step_count, 1);
        // Error is all-zero for a satisfying witness (every row zero).
        assert!(acc.error_evals.iter().all(|&e| e == Goldilocks::ZERO));
    }

    #[test]
    fn two_folds_increase_step_count() {
        let instance = universal_ccs().clone();
        let w1 = make_witness(5, 3, 8);
        let w2 = make_witness(2, 4, 6);
        let mut acc = zero_accumulator(&instance);
        let mut t = Transcript::new();
        fold_step(&mut acc, &instance, &w1, &mut t).unwrap();
        fold_step(&mut acc, &instance, &w2, &mut t).unwrap();
        assert_eq!(acc.step_count, 2);
    }

    #[test]
    fn fold_step_is_deterministic() {
        let instance = universal_ccs().clone();
        let witness = make_witness(5, 3, 8);

        let mut acc1 = zero_accumulator(&instance);
        let mut t1 = Transcript::new();
        fold_step(&mut acc1, &instance, &witness, &mut t1).unwrap();

        let mut acc2 = zero_accumulator(&instance);
        let mut t2 = Transcript::new();
        fold_step(&mut acc2, &instance, &witness, &mut t2).unwrap();

        assert_eq!(acc1.step_count, acc2.step_count);
        assert!(acc1.error_evals.iter().zip(acc2.error_evals.iter()).all(|(a, b)| a.as_u64() == b.as_u64()));
        assert!(acc1.folded_witness.z.iter().zip(acc2.folded_witness.z.iter()).all(|(a, b)| a.as_u64() == b.as_u64()));
    }

    // ── SOUNDNESS ─────────────────────────────────────────────────────────────
    //
    // Background: `decide()`'s SuperSpartan sumcheck proves "e is consistent
    // with the committed z", which — if z's PCS opening is sound — ties e to
    // a SPECIFIC witness. It says nothing about whether that witness came
    // from a real nox execution. `commit()` alone enforced honesty, via a
    // caller-side gate (`CommitError::StepUnsatisfied`) that a caller
    // reaching `fold_step`/`crate::fold` directly could skip entirely.
    //
    // Two DISTINCT findings came out of empirically attacking this:
    //
    // 1. A crafted-but-plausible bad witness (right shape, wrong register —
    //    e.g. an add row whose sum is wrong) folded via the public API used
    //    to be accepted with whatever error the prover honestly computed for
    //    it. `fold_step_rejects_witness_with_wrong_register` pins the fix:
    //    the gate now moves into `fold_step` itself, so no caller — commit(),
    //    a downstream crate calling `crate::fold` directly, or a bug in a
    //    future caller — can skip it.
    //
    // 2. A SHARPER, distinct bug: the "constant" witness column
    //    (`ccs::universal::CONST_IDX`, meant to always hold 1) is never
    //    independently pinned by any CCS row — every row that references it
    //    to mean "the literal 1" is GATED by a pattern selector that is
    //    ALSO a free witness column. So the all-zero vector — CONST_IDX
    //    included — satisfies the ENTIRE universal instance exactly (e ≡ 0,
    //    not just "some computed e"): every gated row is 0×(anything)=0, and
    //    every ungated row is a homogeneous linear relation among witness
    //    columns with no independent additive constant, so it is 0=0 too.
    //    `attack_zeroed_constant_wire_satisfies_universal_instance` proves
    //    this directly against `is_satisfied_by`, then shows the (correctly
    //    working) new gate cannot reject it — because it is not lying about
    //    its own error, the relation itself is silent on it — and that
    //    `decide()`/`verify()` accept the resulting proof for ANY Statement.
    //    Closing this needs an independent, verifier-checked pin on the
    //    constant wire (a public/private witness split, or an extra
    //    fixed-point PCS opening checked against the field element 1) — an
    //    architecture change, not a gate. See `specs/decider.md` §soundness.
    //
    // A THIRD test shows the residual that remains even once (1) and (2) are
    // both closed: a witness that is genuinely, honestly satisfying (a real
    // solution of the CCS) but corresponds to no real nox execution and no
    // relationship to the Statement still decides and verifies for ANY
    // Statement — `attack_satisfying_but_meaningless_witness_passes_for_any_statement`.
    // That is the recursion-milestone residual: no gate on one entry point
    // closes it, because there is nothing internally inconsistent to catch.

    /// Regression: a plausible forged witness — right shape, `CONST_IDX = 1`
    /// as an honest prover would set it, but a wrong register (add row
    /// claiming 5 + 3 = 9) — is rejected by the public `fold_step` before it
    /// is folded in. Before this fix, `fold_step` folded any witness
    /// unconditionally; only `commit()`'s own caller-side gate stopped this,
    /// and only for its own internal path.
    #[test]
    fn fold_step_rejects_witness_with_wrong_register() {
        let instance = universal_ccs().clone();
        let bad = make_witness(5, 3, 9); // 5 + 3 != 9
        let mut acc = zero_accumulator(&instance);
        let mut t = Transcript::new();
        let err = fold_step(&mut acc, &instance, &bad, &mut t);
        assert!(matches!(err, Err(FoldError::UnsatisfyingWitness)), "{err:?}");
        assert_eq!(acc.step_count, 0, "a rejected fold must not mutate the accumulator");
    }

    /// The gate applies on the second (HyperNova relaxed-fold) path too, not
    /// just the step_count == 0 adopt-directly path: a genuine first row
    /// followed by a fabricated second row is rejected before folding.
    #[test]
    fn fold_step_rejects_witness_with_wrong_register_after_first_fold() {
        let instance = universal_ccs().clone();
        let good = make_witness(5, 3, 8);
        let bad = make_witness(2, 4, 7); // 2 + 4 != 7
        let mut acc = zero_accumulator(&instance);
        let mut t = Transcript::new();
        fold_step(&mut acc, &instance, &good, &mut t).unwrap();
        assert_eq!(acc.step_count, 1);
        let err = fold_step(&mut acc, &instance, &bad, &mut t);
        assert!(matches!(err, Err(FoldError::UnsatisfyingWitness)), "{err:?}");
        assert_eq!(acc.step_count, 1, "a rejected fold must not mutate the accumulator");
    }

    /// Sharper finding: the all-zero witness — no selector set, no `CONST_IDX
    /// = 1` — is not merely "not caught", it genuinely SATISFIES the
    /// universal instance (`error_evals` is exactly zero), because every row
    /// is either gated by a selector that is itself zero, or a homogeneous
    /// linear relation with no independent constant. `fold_step`'s new gate
    /// (finding 1, above) cannot reject this: it is not being lied to, the
    /// relation itself does not notice. `decide()`/`verify()` then accept a
    /// proof of this witness for any Statement. Closing this needs the
    /// constant wire to be independently, verifier-checked pinned to 1 (a
    /// public/private witness split, or an extra fixed-point PCS opening) —
    /// out of scope for this fix; recorded in `specs/decider.md` §soundness.
    #[test]
    fn attack_zeroed_constant_wire_satisfies_universal_instance() {
        use crate::folding::decide::decide;
        use crate::types::{ProofGroup, ProofParams, Statement, TraceProof};

        let instance = universal_ccs().clone();
        let all_zero = CCSWitness { z: vec![Goldilocks::ZERO; instance.num_cols] };
        assert!(
            instance.is_satisfied_by(&all_zero),
            "the all-zero witness — CONST_IDX included — satisfies the universal \
             instance outright: the constant wire is never independently pinned"
        );

        let mut acc = zero_accumulator(&instance);
        let mut t = Transcript::new();
        fold_step(&mut acc, &instance, &all_zero, &mut t)
            .expect("the gate cannot reject a witness whose error is genuinely zero");
        assert!(acc.error_evals.iter().all(|&e| e == Goldilocks::ZERO));

        // Any statement the attacker likes — nothing ties it to the witness.
        let statement = Statement {
            program_hash: [0xAAu8; 32],
            input_hash: [0xBBu8; 32],
            output_hash: [0xCCu8; 32],
            focus_bound: 999_999,
            bbg_root: [0xDDu8; 32],
        };
        let linkage = crate::linkage_digest(&[&acc.witness_commitment]);
        let proof = decide(&acc, &statement, &linkage, &ProofParams::default())
            .expect("decide() has no way to notice the constant wire is zeroed");

        let trace_proof =
            TraceProof { universal: ProofGroup { proof, accumulator: acc }, binding: None };
        assert!(
            crate::verify(&trace_proof, &statement, &ProofParams::default()).is_ok(),
            "documents the residual: the zeroed-constant-wire witness verifies for any statement"
        );
    }

    /// The deepest residual: even with a HONEST, non-degenerate, genuinely
    /// satisfying witness (`CONST_IDX = 1`, a real solution of the CCS — a
    /// valid quote row, `r7 = r4`) that corresponds to no real nox execution
    /// and bears no relationship whatsoever to the Statement, `decide()`/
    /// `verify()` accept it — via the ordinary, gated, public `fold_step`
    /// API, no bypass needed. There is nothing internally inconsistent for
    /// any gate to catch: this witness IS a genuine solution. Closing this
    /// needs a verifier-checked fold over N real steps (the recursion
    /// milestone) — not a per-witness gate, however strict.
    #[test]
    fn attack_satisfying_but_meaningless_witness_passes_for_any_statement() {
        use crate::folding::decide::decide;
        use crate::types::{ProofGroup, ProofParams, Statement, TraceProof};

        let instance = universal_ccs().clone();
        // Pattern 1 (quote): r7 = r4. Genuinely satisfying, means nothing.
        let quote_row = test_witness(&[(reg_t(0), 1), (reg_t(4), 5), (reg_t(7), 5)]);
        assert!(instance.is_satisfied_by(&quote_row));

        let mut acc = zero_accumulator(&instance);
        let mut t = Transcript::new();
        fold_step(&mut acc, &instance, &quote_row, &mut t).unwrap();
        assert!(acc.error_evals.iter().all(|&e| e == Goldilocks::ZERO));

        let statement = Statement {
            program_hash: [0x11u8; 32],
            input_hash: [0x22u8; 32],
            output_hash: [0x33u8; 32],
            focus_bound: 42,
            bbg_root: [0x44u8; 32],
        };
        let linkage = crate::linkage_digest(&[&acc.witness_commitment]);
        let proof = decide(&acc, &statement, &linkage, &ProofParams::default()).unwrap();
        let trace_proof =
            TraceProof { universal: ProofGroup { proof, accumulator: acc }, binding: None };
        assert!(
            crate::verify(&trace_proof, &statement, &ProofParams::default()).is_ok(),
            "documents the recursion-milestone residual: a real but unrelated \
             solution of the CCS verifies against a Statement it has nothing to do with"
        );
    }
}
