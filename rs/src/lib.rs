// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! zheng — proof system: SuperSpartan IOP + sumcheck + Brakedown PCS.
//!
//! Five entry points: `commit`, `open`, `verify`, `fold`, `decide`.
//!
//! `fold` requires a caller-managed `&mut Transcript` shared across all fold
//! calls within one CCS group — see its doc comment for the contract.

pub mod ccs;
pub mod folding;
pub mod multilinear;
pub mod phi;
pub mod spartan;
pub mod sumcheck;
pub mod transcript;
pub mod types;

pub use crate::ccs::{
    AxisOpening, HashAux, LookOpening, RootLeaves, build_axis_transcript_steps,
    build_look_transcript_steps, look_openings_from_provider, root_from_leaves, root_to_bytes,
    standalone_root,
};
pub use phi::{
    PhiError, PhiProof, PhiStatement, SparseGraph, SpmvError, SpmvProof, SpmvStatement,
    TriKernelParams, prove_phi_star, prove_spmv, spmv_native, verify_phi_star, verify_spmv,
};
pub use transcript::Transcript;
pub use types::{
    Accumulator, CCSInstance, CCSWitness, CommitError, DecideError, FoldError, LensBackend,
    OpenError, Proof, ProofParams, SecurityLevel, SparseMatrix, Statement, SumcheckPoly,
    TraceProof, VerifyError,
};

use nebu::Goldilocks;
use nox::VecTrace;

use lens::brakedown::Brakedown;
use lens::{Commitment, Lens, MultilinearPoly, Opening};

use crate::ccs::{
    build_axis_steps_from_trace, build_ccs_from_trace, build_hash_binding_steps_from_trace,
    build_hash_steps_from_trace, build_look_steps_from_trace,
};
use crate::folding::{decide as run_decide, fold_step};
use crate::spartan::verifier::SpartanVerifier;

// ── five entry points ─────────────────────────────────────────────────────────

/// Compute the hemera hash of a trace row's 16 registers as a 32-byte digest.
fn hash_row(row: &nox::TraceRow) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(128);
    for &v in row.r().iter() {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    *hemera::hash(&bytes).as_bytes()
}

/// Digest binding all accumulator groups of one TraceProof together.
///
/// hemera hash over the group count and every group's witness commitment,
/// in group order. Absorbed into each group's decide transcript (option A
/// linkage of the axis design): a valid group spliced in from another
/// proof changes the digest and breaks every group's Fiat-Shamir chain.
pub(crate) fn linkage_digest(commitments: &[&Commitment]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(8 + commitments.len() * 32);
    bytes.extend_from_slice(&(commitments.len() as u64).to_le_bytes());
    for c in commitments {
        bytes.extend_from_slice(c.as_bytes());
    }
    *hemera::hash(&bytes).as_bytes()
}

/// Initialize a blank accumulator for a given CCS instance structure.
fn blank_acc(instance: &CCSInstance) -> Accumulator {
    let init_z = vec![Goldilocks::ZERO; 64];
    Accumulator {
        committed_instance: instance.clone(),
        folded_witness: CCSWitness { z: init_z.clone() },
        witness_commitment: Brakedown::commit_raw(&init_z),
        error_evals: vec![Goldilocks::ZERO; instance.num_rows],
        step_count: 0,
    }
}

/// Prove a nox execution trace.
///
/// Groups trace steps by CCS structure (one group per distinct pattern type),
/// folds each group into its own HyperNova accumulator, and runs the decider
/// on each accumulator. Returns a TraceProof containing one (Proof, Accumulator)
/// per group.
///
/// `hash_aux` provides prover hints for Poseidon2 hash blocks (one per block).
/// `axis_openings` provides Brakedown opening proofs for axis reads (one per axis row).
/// `look_openings` provides Brakedown opening proofs for BBG look reads (one per look row).
/// Pass empty slices for traces without hash, axis, or look operations.
pub fn commit(
    trace: &VecTrace,
    hash_aux: &[HashAux],
    axis_openings: &[AxisOpening],
    look_openings: &[LookOpening],
    statement: &Statement,
    params: &ProofParams,
) -> Result<TraceProof, CommitError> {
    // Statement binding.
    if statement.focus_bound > 0 && trace.0.len() as u64 > statement.focus_bound {
        return Err(CommitError::FocusExhausted);
    }
    if statement.input_hash != [0u8; 32]
        && let Some(first) = trace.0.first()
        && hash_row(first) != statement.input_hash
    {
        return Err(CommitError::StatementMismatch);
    }
    if statement.output_hash != [0u8; 32]
        && let Some(last) = trace.0.last()
        && hash_row(last) != statement.output_hash
    {
        return Err(CommitError::StatementMismatch);
    }

    // Build all step sequences and chain them.
    let main_steps = build_ccs_from_trace(&trace.0);
    let hash_steps = build_hash_steps_from_trace(&trace.0, hash_aux)?;
    let hash_binding = build_hash_binding_steps_from_trace(&trace.0, hash_aux)?;
    let axis_steps = build_axis_steps_from_trace(&trace.0, axis_openings)?;
    let axis_transcript = build_axis_transcript_steps(&trace.0, axis_openings)?;
    let look_steps = build_look_steps_from_trace(&trace.0, look_openings, &statement.bbg_root)?;
    let look_transcript = build_look_transcript_steps(&trace.0, look_openings)?;

    let all_steps: Vec<(CCSInstance, CCSWitness)> = main_steps
        .into_iter()
        .chain(hash_steps)
        .chain(hash_binding)
        .chain(axis_steps)
        .chain(axis_transcript)
        .chain(look_steps)
        .chain(look_transcript)
        .collect();

    if all_steps.is_empty() {
        return Err(CommitError::TraceOverflow);
    }

    // Pass 1 — fold. Sequential grouping: start a new group whenever the CCS
    // instance changes. Full equality is required because instances with the
    // same structural shape (matrix count, dimensions) but different matrix
    // coefficients (e.g. distinct Poseidon2 partial-round constants) must not
    // fold together — their error_evals are computed against the current
    // instance's matrices while the verifier checks against
    // committed_instance, which only holds the first instance in the group.
    let mut folded: Vec<Accumulator> = Vec::new();
    let mut cur_instance: Option<CCSInstance> = None;
    let mut cur_acc: Option<Accumulator> = None;
    let mut cur_transcript = Transcript::new();

    for (instance, witness) in &all_steps {
        let same = cur_instance.as_ref() == Some(instance);

        if !same {
            if let Some(acc) = cur_acc.take() {
                folded.push(acc);
            }
            cur_instance = Some(instance.clone());
            cur_acc = Some(blank_acc(instance));
            cur_transcript = Transcript::new();
        }

        fold_step(
            cur_acc.as_mut().unwrap(),
            instance,
            witness,
            &mut cur_transcript,
        )
        .map_err(|_| CommitError::TraceOverflow)?;
    }
    if let Some(acc) = cur_acc.take() {
        folded.push(acc);
    }

    // Pass 2 — cross-group linkage over every group's witness commitment.
    let commitments: Vec<&Commitment> = folded.iter().map(|a| &a.witness_commitment).collect();
    let linkage = linkage_digest(&commitments);

    // Pass 3 — decide each group under the shared linkage digest.
    let mut groups: Vec<(Proof, Accumulator)> = Vec::with_capacity(folded.len());
    for acc in folded {
        let proof =
            run_decide(&acc, statement, &linkage, params).map_err(CommitError::DecideFailed)?;
        groups.push((proof, acc));
    }

    Ok(TraceProof { groups })
}

/// Commit a polynomial and open it at an evaluation point.
///
/// `poly` is the evaluation table (any length; padded to `1 << point.len()`).
/// `point` has `num_vars` coordinates — one per variable of the multilinear poly.
/// Returns the binding commitment and an opening proof that `poly(point) = value`.
///
/// Pair with `verify_eval` for the full commit-open-verify cycle.
pub fn open(
    poly: &[Goldilocks],
    point: &[Goldilocks],
    _params: &ProofParams,
) -> Result<(Commitment, Opening), OpenError> {
    let num_vars = point.len();
    if num_vars == 0 {
        return Err(OpenError::InvalidPoint);
    }
    let target_len = 1usize << num_vars;
    if poly.len() > target_len {
        return Err(OpenError::InvalidPoint);
    }
    let mut padded = poly.to_vec();
    while padded.len() < target_len {
        padded.push(Goldilocks::ZERO);
    }
    let mp = MultilinearPoly::new(padded);
    let commitment = Brakedown::commit(&mp);
    let mut lt = lens::Transcript::new(b"zheng-open");
    let opening = Brakedown::open(&mp, point, &mut lt);
    Ok((commitment, opening))
}

/// Verify a polynomial evaluation proof produced by `open`.
///
/// Returns `Ok(())` if the opening proves that the polynomial committed in
/// `commitment` evaluates to `value` at `point`. Returns `Err` otherwise.
pub fn verify_eval(
    commitment: &Commitment,
    point: &[Goldilocks],
    value: Goldilocks,
    opening: &Opening,
    _params: &ProofParams,
) -> Result<(), OpenError> {
    let mut lt = lens::Transcript::new(b"zheng-open");
    if Brakedown::verify(commitment, point, value, opening, &mut lt) {
        Ok(())
    } else {
        Err(OpenError::LensFailed)
    }
}

/// Verify a zheng proof against a public statement.
///
/// Checks each CCS-structure group in the TraceProof independently.
/// All groups must verify for the overall proof to be valid.
pub fn verify(
    proof: &TraceProof,
    statement: &Statement,
    _params: &ProofParams,
) -> Result<(), VerifyError> {
    // Recompute the cross-group linkage digest from the proof's own groups —
    // it must match what every group's decide transcript absorbed.
    let commitments: Vec<&Commitment> = proof
        .groups
        .iter()
        .map(|(_, acc)| &acc.witness_commitment)
        .collect();
    let linkage = linkage_digest(&commitments);

    for (group_proof, acc) in &proof.groups {
        // Degree-1 groups (all multisets of size ≤ 1) fold satisfied steps to
        // exactly zero error — error is linear in the witness. A non-zero
        // entry means an unsatisfied step (e.g. a forged axis binding) was
        // folded in; the relaxed Spartan check alone would accept it.
        let linear = acc
            .committed_instance
            .multisets
            .iter()
            .all(|multiset| multiset.len() <= 1);
        if linear && acc.error_evals.iter().any(|&e| e != Goldilocks::ZERO) {
            return Err(VerifyError::LinearErrorNonzero);
        }

        let mut transcript = Transcript::new_recursive();
        transcript.absorb_statement(statement);
        transcript.absorb_linkage(&linkage);
        transcript.absorb(acc.witness_commitment.as_bytes());
        for &e in &acc.error_evals {
            transcript.absorb(&e.as_u64().to_le_bytes());
        }
        transcript.absorb(&acc.step_count.to_le_bytes());
        SpartanVerifier::verify(
            &acc.committed_instance,
            group_proof,
            &acc.error_evals,
            &mut transcript,
        )?;
    }
    Ok(())
}

/// Fold one trace step into an accumulator.
///
/// `transcript` must be shared across all fold calls within one CCS group so
/// that beta challenges are chained (Fiat-Shamir binding). Start a fresh
/// `Transcript::new()` at the beginning of each group and pass the same
/// instance throughout the group. Mixing instances or transcripts across groups
/// breaks soundness.
pub fn fold(
    acc: &mut Accumulator,
    instance: &CCSInstance,
    witness: &CCSWitness,
    transcript: &mut Transcript,
) -> Result<(), FoldError> {
    fold_step(acc, instance, witness, transcript)
}

/// Run the SuperSpartan decider on an accumulated HyperNova state.
///
/// Produces the final proof from the accumulated CCS instance and witness,
/// bound to the given statement via Fiat-Shamir. The proof carries a
/// single-group linkage digest, so a one-group `TraceProof` built from it
/// verifies with [`verify`].
pub fn decide(
    acc: &Accumulator,
    statement: &Statement,
    params: &ProofParams,
) -> Result<Proof, DecideError> {
    let linkage = linkage_digest(&[&acc.witness_commitment]);
    run_decide(acc, statement, &linkage, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lens::brakedown::Brakedown;
    use lens::{Lens, MultilinearPoly, Transcript as LensTranscript};
    use nox::{NullCalls, Reduction, VecTrace};

    fn malformed_trace() -> VecTrace {
        // Two rows with tag=255 (unknown) → trivial_ccs (no constraints).
        // Used to test the full commit→verify pipeline without constraint logic.
        let mut order = Reduction::<1024>::new();
        let obj = order.atom(Goldilocks::new(0)).unwrap();
        let tag_255 = order.atom(Goldilocks::new(255)).unwrap();
        let body = order.atom(Goldilocks::new(0)).unwrap();
        let formula = order.pair(tag_255, body).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
        nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
        trace
    }

    fn zero_statement() -> Statement {
        Statement {
            program_hash: [0u8; 32],
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
            focus_bound: 0,
        bbg_root: [0u8; 32],
        }
    }

    #[test]
    fn commit_verify_roundtrip() {
        let trace = malformed_trace();
        let stmt = zero_statement();
        let params = ProofParams::default();
        let trace_proof = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&trace_proof, &stmt, &params).is_ok());
    }

    // ── helpers for manual CCS witness construction ───────────────────────────

    fn make_z_33(vals: &[(usize, u64)]) -> CCSWitness {
        use crate::ccs::{CONST_IDX, Z_LEN};
        let mut z = vec![Goldilocks::ZERO; Z_LEN];
        z[CONST_IDX] = Goldilocks::ONE;
        for &(idx, v) in vals {
            z[idx] = Goldilocks::new(v);
        }
        CCSWitness { z }
    }

    #[test]
    fn fold_add_multi_step_commit_verify() {
        use crate::ccs::patterns::build_step_ccs;
        use crate::ccs::{reg_t, reg_t1};
        use crate::folding::fold::fold_step;

        let instance = build_step_ccs(5); // add: r5_{t+1} - r3_t - r4_t = 0
        let witnesses = [
            make_z_33(&[(reg_t(3), 3), (reg_t(4), 4), (reg_t1(5), 7)]),
            make_z_33(&[(reg_t(3), 10), (reg_t(4), 20), (reg_t1(5), 30)]),
            make_z_33(&[(reg_t(3), 1), (reg_t(4), 1), (reg_t1(5), 2)]),
        ];
        for w in &witnesses {
            assert!(instance.is_satisfied_by(w));
        }

        let mut acc = blank_acc(&instance);
        let mut transcript = Transcript::new();
        for w in &witnesses {
            fold_step(&mut acc, &instance, w, &mut transcript).unwrap();
        }
        assert_eq!(acc.step_count, 3);
        assert!(acc.error_evals.iter().all(|&e| e == Goldilocks::ZERO)); // degree-1: stays 0

        let stmt = zero_statement();
        let proof = decide(&acc, &stmt, &ProofParams::default()).unwrap();
        let trace_proof = TraceProof {
            groups: vec![(proof, acc)],
        };
        assert!(verify(&trace_proof, &stmt, &ProofParams::default()).is_ok());
    }

    #[test]
    fn fold_mul_multi_step_commit_verify() {
        use crate::ccs::patterns::build_step_ccs;
        use crate::ccs::{reg_t, reg_t1};
        use crate::folding::fold::fold_step;

        let instance = build_step_ccs(7); // mul: r5_{t+1} - r3_t * r4_t = 0
        let witnesses = [
            make_z_33(&[(reg_t(3), 6), (reg_t(4), 7), (reg_t1(5), 42)]),
            make_z_33(&[(reg_t(3), 2), (reg_t(4), 5), (reg_t1(5), 10)]),
            make_z_33(&[(reg_t(3), 3), (reg_t(4), 3), (reg_t1(5), 9)]),
        ];
        for w in &witnesses {
            assert!(instance.is_satisfied_by(w));
        }

        let mut acc = blank_acc(&instance);
        let mut transcript = Transcript::new();
        for w in &witnesses {
            fold_step(&mut acc, &instance, w, &mut transcript).unwrap();
        }
        assert_eq!(acc.step_count, 3);
        // degree-2 multi-fold: e_acc = error_evals(w_folded) ≠ 0 in general;
        // Spartan proves/verifies against this accumulated error.

        let stmt = zero_statement();
        let proof = decide(&acc, &stmt, &ProofParams::default()).unwrap();
        let trace_proof = TraceProof {
            groups: vec![(proof, acc)],
        };
        assert!(verify(&trace_proof, &stmt, &ProofParams::default()).is_ok());
    }

    fn make_poly(values: &[u64]) -> Vec<Goldilocks> {
        values.iter().map(|&v| Goldilocks::new(v)).collect()
    }

    #[test]
    fn open_verify_eval_roundtrip_small() {
        // 2-variable polynomial: f(x0,x1) evals [3, 7, 11, 19]
        let poly = make_poly(&[3, 7, 11, 19]);
        let point = vec![Goldilocks::new(2), Goldilocks::new(5)];
        let params = ProofParams::default();

        let (commitment, opening) = open(&poly, &point, &params).unwrap();

        // Compute expected value via multilinear extension.
        let mp = MultilinearPoly::new(poly.clone());
        let expected = mp.evaluate(&point);

        verify_eval(&commitment, &point, expected, &opening, &params).unwrap();
    }

    #[test]
    fn open_verify_eval_roundtrip_six_vars() {
        // 64 elements — the witness size used by SuperSpartan.
        let poly: Vec<Goldilocks> = (0u64..64).map(Goldilocks::new).collect();
        let point: Vec<Goldilocks> = (1u64..=6).map(Goldilocks::new).collect();
        let params = ProofParams::default();

        let (commitment, opening) = open(&poly, &point, &params).unwrap();
        let mp = MultilinearPoly::new(poly);
        let expected = mp.evaluate(&point);

        verify_eval(&commitment, &point, expected, &opening, &params).unwrap();
    }

    #[test]
    fn open_pads_short_poly_to_point_size() {
        // poly has 2 elements but point has 3 variables → padded to 8 elements.
        let poly = make_poly(&[5, 13]);
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO];
        let params = ProofParams::default();

        let (commitment, opening) = open(&poly, &point, &params).unwrap();
        // f(0,0,0) = poly[0] = 5 (zero-padding preserves this).
        let expected = Goldilocks::new(5);
        verify_eval(&commitment, &point, expected, &opening, &params).unwrap();
    }

    #[test]
    fn open_larger_than_witness_size() {
        // 256 elements (2^8) — larger than the 64-element witness vector.
        let poly: Vec<Goldilocks> = (0u64..256).map(|v| Goldilocks::new(v * 3 + 1)).collect();
        let point: Vec<Goldilocks> = (0u64..8).map(|v| Goldilocks::new(v + 2)).collect();
        let params = ProofParams::default();

        let (commitment, opening) = open(&poly, &point, &params).unwrap();
        let mp = MultilinearPoly::new(poly);
        let expected = mp.evaluate(&point);
        verify_eval(&commitment, &point, expected, &opening, &params).unwrap();
    }

    #[test]
    fn verify_eval_wrong_value_rejected() {
        let poly = make_poly(&[1, 2, 3, 4]);
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let params = ProofParams::default();

        let (commitment, opening) = open(&poly, &point, &params).unwrap();
        let wrong = Goldilocks::new(999);
        assert!(verify_eval(&commitment, &point, wrong, &opening, &params).is_err());
    }

    #[test]
    fn open_zero_vars_rejected() {
        let poly = make_poly(&[42]);
        let params = ProofParams::default();
        assert!(open(&poly, &[], &params).is_err());
    }

    #[test]
    fn open_poly_longer_than_point_rejected() {
        // poly has 8 elements but point has 2 vars → target = 4 < 8.
        let poly = make_poly(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let params = ProofParams::default();
        assert!(open(&poly, &point, &params).is_err());
    }

    // ── end-to-end tests ─────────────────────────────────────────────────────

    /// Build a real Brakedown opening for a small 2-variable polynomial.
    fn make_axis_opening() -> AxisOpening {
        let evals: Vec<Goldilocks> = (1u64..=4).map(Goldilocks::new).collect();
        let poly = MultilinearPoly::new(evals);
        let commitment = Brakedown::commit(&poly);
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let value = Goldilocks::new(1);
        let opening = {
            let mut lt = LensTranscript::new(b"e2e-axis-open");
            Brakedown::open(&poly, &point, &mut lt)
        };
        AxisOpening {
            commitment,
            point,
            value,
            opening,
            transcript_seed: b"e2e-axis-open".to_vec(),
        }
    }

    /// E2E: trace with Poseidon2 hash operation → hash_aux drives particle CCS.
    ///
    /// formula = [15, [1, s]] hashes subject s, producing 25 rows (tag=15)
    /// plus 1 quote row (tag=1) — 26 total.  HashAux supplies the rate (the
    /// structural digest of s) so build_hash_steps_from_trace can replay the
    /// sponge and recover capacity elements.
    #[test]
    fn e2e_hash_accumulator_roundtrip() {
        let mut order = Reduction::<1024>::new();
        let s = order.atom(Goldilocks::new(42)).unwrap();
        let tag1 = order.atom(Goldilocks::new(1)).unwrap();
        let tag15 = order.atom(Goldilocks::new(15)).unwrap();
        let quote_f = order.pair(tag1, s).unwrap();
        let hash_f = order.pair(tag15, quote_f).unwrap();

        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, hash_f, 100, &NullCalls, &mut trace);
        // 1 quote row + 24 round rows + 1 squeeze row
        assert_eq!(trace.0.len(), 26);

        // Rate = structural digest of s (4 Goldilocks elements), zero-padded to 8.
        let in_digest = *order.digest(s).unwrap();
        let rate = [
            in_digest[0],
            in_digest[1],
            in_digest[2],
            in_digest[3],
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ];
        let hash_aux = HashAux { rate };

        let stmt = zero_statement();
        let params = ProofParams::default();
        let trace_proof = commit(&trace, &[hash_aux], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&trace_proof, &stmt, &params).is_ok());
    }

    /// E2E: trace with two axis operations → axis verifier steps fold into
    /// separate accumulator group.  Statement input/output hashes are computed
    /// from real trace rows and embedded in the statement, exercising all three
    /// new commit() features simultaneously.
    #[test]
    fn e2e_axis_accumulator_and_statement_binding_roundtrip() {
        // Two axis identity operations: axis(s, 1) = s, cost 1 each.
        let mut order = Reduction::<1024>::new();
        let s = order.atom(Goldilocks::new(7)).unwrap();
        let tag0 = order.atom(Goldilocks::new(0)).unwrap();
        let addr1 = order.atom(Goldilocks::new(1)).unwrap();
        let axis_f = order.pair(tag0, addr1).unwrap();

        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, axis_f, 100, &NullCalls, &mut trace);
        nox::reduce(&mut order, s, axis_f, 99, &NullCalls, &mut trace);
        // Two axis rows; consecutive pair satisfies pattern_axis budget-decrement constraint.
        assert_eq!(trace.0.len(), 2);

        // One Brakedown opening per axis row (both use the same polynomial for simplicity).
        let ao1 = make_axis_opening();
        let ao2 = make_axis_opening();

        // Statement binding: real hashes from first and last trace rows.
        let input_hash = super::hash_row(&trace.0[0]);
        let output_hash = super::hash_row(&trace.0[trace.0.len() - 1]);
        let stmt = Statement {
            program_hash: [0u8; 32],
            input_hash,
            output_hash,
            focus_bound: 10,
        bbg_root: [0u8; 32],
        };
        let params = ProofParams::default();

        let trace_proof = commit(&trace, &[], &[ao1, ao2], &[], &stmt, &params).unwrap();
        assert!(verify(&trace_proof, &stmt, &params).is_ok());
    }

    /// E2E: commit() rejects a statement whose input_hash does not match the
    /// hash of the first trace row.
    #[test]
    fn e2e_statement_binding_rejects_wrong_input_hash() {
        let mut order = Reduction::<1024>::new();
        let s = order.atom(Goldilocks::new(7)).unwrap();
        let tag0 = order.atom(Goldilocks::new(0)).unwrap();
        let addr = order.atom(Goldilocks::new(1)).unwrap();
        let axis_f = order.pair(tag0, addr).unwrap();

        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, axis_f, 100, &NullCalls, &mut trace);
        nox::reduce(&mut order, s, axis_f, 99, &NullCalls, &mut trace);

        let mut wrong_hash = [0u8; 32];
        wrong_hash[0] = 0xff;

        let stmt = Statement {
            program_hash: [0u8; 32],
            input_hash: wrong_hash,
            output_hash: [0u8; 32],
            focus_bound: 0,
        bbg_root: [0u8; 32],
        };
        let params = ProofParams::default();
        let err = commit(
            &trace,
            &[],
            &[make_axis_opening(), make_axis_opening()],
            &[],
            &stmt,
            &params,
        );
        assert!(matches!(err, Err(CommitError::StatementMismatch)));
    }

    /// E2E: commit() rejects when trace length exceeds statement focus_bound.
    #[test]
    fn e2e_statement_binding_rejects_focus_exceeded() {
        let trace = malformed_trace(); // 2 rows
        let stmt = Statement {
            program_hash: [0u8; 32],
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
            focus_bound: 1, // trace has 2 rows > 1
            bbg_root: [0u8; 32],
        };
        let params = ProofParams::default();
        let err = commit(&trace, &[], &[], &[], &stmt, &params);
        assert!(matches!(err, Err(CommitError::FocusExhausted)));
    }

    // ── prover-active axis: trace binding harness ────────────────────────────

    /// CallProvider that reports a fixed Lens commitment for every object.
    /// The executor writes its limbs into r[11]-r[14] (prover-active mode),
    /// arming the axis trace bindings in build_axis_steps_from_trace.
    struct AxisProver {
        commitment: [u8; 32],
    }

    impl nox::LookProvider for AxisProver {
        fn look(
            &self,
            _commitment: Goldilocks,
            _namespace: Goldilocks,
            _key: Goldilocks,
        ) -> Option<Goldilocks> {
            None
        }
    }

    impl<const N: usize> nox::CallProvider<N> for AxisProver {
        fn provide(
            &self,
            _reduction: &mut Reduction<N>,
            _tag: Goldilocks,
            _object: nox::Order,
        ) -> Option<nox::Order> {
            None
        }

        fn axis_commitment(&self, _object_id: u64) -> Option<[u8; 32]> {
            Some(self.commitment)
        }
    }

    /// Run `axis(s, 5)` twice over s = [[a b] [c d]] with a prover-active
    /// provider. The noun polynomial's evaluations are the particle ids at
    /// depth-2 addresses 4..8, so its value at axis_eval_point(5) is the
    /// result particle in r[7]. `tweak` perturbs the unopened leaves,
    /// deriving a distinct commitment with the same value at the opened
    /// point (used to build a second, different-but-valid proof).
    fn prover_active_axis_setup(tweak: u64) -> (VecTrace, Vec<AxisOpening>) {
        use lens::Transcript as LensTranscript;

        let g = Goldilocks::new;
        let mut order = Reduction::<1024>::new();
        let a = order.atom(g(11)).unwrap();
        let b = order.atom(g(22)).unwrap();
        let c = order.atom(g(33)).unwrap();
        let d = order.atom(g(44)).unwrap();
        let left = order.pair(a, b).unwrap();
        let right = order.pair(c, d).unwrap();
        let s = order.pair(left, right).unwrap();
        let tag0 = order.atom(g(0)).unwrap();
        let addr = order.atom(g(5)).unwrap();
        let axis_f = order.pair(tag0, addr).unwrap();

        // Noun polynomial: particle ids at addresses 4, 5, 6, 7 (LSB-first
        // index = low address bits). Address 5 → index 1.
        let ids = [a as u64, b as u64, c as u64, d as u64];
        let evals: Vec<Goldilocks> = ids
            .iter()
            .enumerate()
            .map(|(i, &v)| if i == 1 { g(v) } else { g(v + tweak) })
            .collect();
        let poly = MultilinearPoly::new(evals);
        let commitment = Brakedown::commit(&poly);
        let prover = AxisProver {
            commitment: commitment.as_bytes().try_into().unwrap(),
        };

        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, axis_f, 100, &prover, &mut trace);
        nox::reduce(&mut order, s, axis_f, 99, &prover, &mut trace);
        assert_eq!(trace.0.len(), 2);
        assert_eq!(trace.0[0].r()[7], b as u64, "axis 5 = tail(head(s)) = b");
        assert_ne!(trace.0[0].r()[11], 0, "prover-active row carries the commitment");

        let point = crate::ccs::axis_eval_point(5);
        let value = poly.evaluate(&point);
        assert_eq!(
            value,
            g(b as u64),
            "noun polynomial at the address point is the result particle"
        );

        let openings = (0..2)
            .map(|_| {
                let mut lt = LensTranscript::new(b"e2e-axis-prover");
                AxisOpening {
                    commitment,
                    point: point.clone(),
                    value,
                    opening: Brakedown::open(&poly, &point, &mut lt),
                    transcript_seed: b"e2e-axis-prover".to_vec(),
                }
            })
            .collect();
        (trace, openings)
    }

    /// E2E: prover-active axis — commitment (r11-r14), point (r5) and value
    /// (r7) bindings all hold and the proof round-trips.
    #[test]
    fn e2e_prover_active_axis_binding_roundtrip() {
        let (trace, openings) = prover_active_axis_setup(0);
        let stmt = zero_statement();
        let params = ProofParams::default();
        let trace_proof = commit(&trace, &[], &openings, &[], &stmt, &params).unwrap();
        assert!(verify(&trace_proof, &stmt, &params).is_ok());
    }

    /// Negative: a valid opening for a DIFFERENT commitment than the trace
    /// carries (r11-r14) must be rejected — the swapped-opening attack.
    #[test]
    fn commit_rejects_swapped_axis_commitment() {
        let (trace_p, _) = prover_active_axis_setup(0);
        let (_, openings_q) = prover_active_axis_setup(7);
        let stmt = zero_statement();
        let params = ProofParams::default();
        let err = commit(&trace_p, &[], &openings_q, &[], &stmt, &params);
        assert!(matches!(err, Err(CommitError::AxisBinding)));
    }

    /// Negative: an opening whose claimed value differs from the result
    /// particle nox produced (r7) must be rejected — the forged-result attack.
    #[test]
    fn commit_rejects_forged_axis_result() {
        let (trace, mut openings) = prover_active_axis_setup(0);
        openings[0].value += Goldilocks::ONE;
        let stmt = zero_statement();
        let params = ProofParams::default();
        let err = commit(&trace, &[], &openings, &[], &stmt, &params);
        assert!(matches!(err, Err(CommitError::AxisBinding)));
    }

    /// Negative: a corrupted opening proof (tampered final_poly byte) must be
    /// rejected — the tampered-opening attack.
    #[test]
    fn commit_rejects_tampered_axis_opening() {
        let (trace, mut openings) = prover_active_axis_setup(0);
        if let Opening::Tensor { final_poly, .. } = &mut openings[0].opening {
            final_poly[0] ^= 1;
        } else {
            panic!("Brakedown opening is Tensor");
        }
        let stmt = zero_statement();
        let params = ProofParams::default();
        let err = commit(&trace, &[], &openings, &[], &stmt, &params);
        assert!(matches!(err, Err(CommitError::AxisBinding)));
    }

    /// Negative: splicing the axis group of one valid proof into another
    /// valid proof must break verification. Both groups are self-consistent;
    /// only the option-A linkage digest ties them to their own proof.
    #[test]
    fn verify_rejects_spliced_axis_group() {
        let stmt = zero_statement();
        let params = ProofParams::default();

        let (t1, o1) = prover_active_axis_setup(0);
        let (t2, o2) = prover_active_axis_setup(7);
        let p1 = commit(&t1, &[], &o1, &[], &stmt, &params).unwrap();
        let p2 = commit(&t2, &[], &o2, &[], &stmt, &params).unwrap();
        assert!(verify(&p1, &stmt, &params).is_ok());
        assert!(verify(&p2, &stmt, &params).is_ok());

        // The single VZ_LEN=3 group holds the axis opening eq steps.
        let axis_group = |p: &TraceProof| {
            let idxs: Vec<usize> = p
                .groups
                .iter()
                .enumerate()
                .filter(|(_, (_, a))| a.committed_instance.num_cols == 3)
                .map(|(i, _)| i)
                .collect();
            assert_eq!(idxs.len(), 1, "exactly one axis eq-step group");
            idxs[0]
        };
        let i1 = axis_group(&p1);
        let i2 = axis_group(&p2);
        assert_ne!(
            p1.groups[i1].1.witness_commitment.as_bytes(),
            p2.groups[i2].1.witness_commitment.as_bytes(),
            "the two axis groups differ (different noun commitments)"
        );

        let mut spliced = p1.clone();
        spliced.groups[i1] = p2.groups[i2].clone();
        assert!(
            verify(&spliced, &stmt, &params).is_err(),
            "axis group spliced from another proof must not verify"
        );
    }

    /// Fold a hand-built axis step sequence, decide it, and wrap it as a
    /// one-group TraceProof — the route of a malicious prover who bypasses
    /// commit()'s strictness gate.
    fn prove_raw_linear_steps(steps: &[(CCSInstance, CCSWitness)]) -> TraceProof {
        let mut acc = blank_acc(&steps[0].0);
        let mut transcript = Transcript::new();
        for (instance, witness) in steps {
            crate::folding::fold_step(&mut acc, instance, witness, &mut transcript).unwrap();
        }
        let proof = decide(&acc, &zero_statement(), &ProofParams::default()).unwrap();
        TraceProof {
            groups: vec![(proof, acc)],
        }
    }

    /// Negative: a prover who folds a commitment-binding step for the WRONG
    /// commitment (valid opening of poly Q claimed against commitment P) and
    /// bypasses the commit gate is caught at verify time — linear groups must
    /// carry zero error.
    #[test]
    fn verify_rejects_folded_wrong_commitment_binding() {
        use crate::ccs::verifier_steps::read_limb;
        use crate::ccs::{eq_step, verifier_steps};
        use lens::Transcript as LensTranscript;

        let poly_q = MultilinearPoly::new(make_poly(&[9, 8, 7, 6]));
        let commitment_q = Brakedown::commit(&poly_q);
        let commitment_p = Brakedown::commit(&MultilinearPoly::new(make_poly(&[1, 2, 3, 4])));
        let point = vec![Goldilocks::ZERO, Goldilocks::ONE];
        let value = poly_q.evaluate(&point);
        let opening = {
            let mut lt = LensTranscript::new(b"raw-axis");
            Brakedown::open(&poly_q, &point, &mut lt)
        };

        // Internally-valid opening steps for Q…
        let mut steps = verifier_steps(&commitment_q, &point, value, &opening);
        // …plus the binding the trace would demand: Q's limbs against P's
        // registers. Unsatisfied — and folded in anyway.
        for k in 0..4 {
            steps.push(eq_step(
                read_limb(commitment_q.as_bytes(), k),
                read_limb(commitment_p.as_bytes(), k),
            ));
        }

        let trace_proof = prove_raw_linear_steps(&steps);
        let err = verify(&trace_proof, &zero_statement(), &ProofParams::default());
        assert!(matches!(err, Err(VerifyError::LinearErrorNonzero)));
    }

    /// Negative: a prover who folds a value-binding step claiming a forged
    /// result (opened value vs. a different r7) and bypasses the commit gate
    /// is caught at verify time.
    #[test]
    fn verify_rejects_folded_forged_result_binding() {
        use crate::ccs::{eq_step, verifier_steps};
        use lens::Transcript as LensTranscript;

        let poly = MultilinearPoly::new(make_poly(&[5, 15, 25, 35]));
        let commitment = Brakedown::commit(&poly);
        let point = vec![Goldilocks::ONE, Goldilocks::ZERO];
        let value = poly.evaluate(&point);
        let opening = {
            let mut lt = LensTranscript::new(b"raw-axis-forge");
            Brakedown::open(&poly, &point, &mut lt)
        };

        let mut steps = verifier_steps(&commitment, &point, value, &opening);
        // Value binding against a forged result particle.
        let forged_r7 = value + Goldilocks::ONE;
        steps.push(eq_step(value, forged_r7));

        let trace_proof = prove_raw_linear_steps(&steps);
        let err = verify(&trace_proof, &zero_statement(), &ProofParams::default());
        assert!(matches!(err, Err(VerifyError::LinearErrorNonzero)));
    }

    /// The zero-error rule accepts honest linear folds: the same raw route
    /// with all steps satisfied verifies.
    #[test]
    fn verify_accepts_raw_satisfied_axis_steps() {
        use crate::ccs::verifier_steps;
        use lens::Transcript as LensTranscript;

        let poly = MultilinearPoly::new(make_poly(&[5, 15, 25, 35]));
        let commitment = Brakedown::commit(&poly);
        let point = vec![Goldilocks::ONE, Goldilocks::ZERO];
        let value = poly.evaluate(&point);
        let opening = {
            let mut lt = LensTranscript::new(b"raw-axis-honest");
            Brakedown::open(&poly, &point, &mut lt)
        };

        let steps = verifier_steps(&commitment, &point, value, &opening);
        let trace_proof = prove_raw_linear_steps(&steps);
        assert!(verify(&trace_proof, &zero_statement(), &ProofParams::default()).is_ok());
    }

    // ── hash (pattern 15): trace binding tests ───────────────────────────────
    // Hash carries NO polynomial opening: the sponge is verified in-circuit,
    // and HashAux's rate is the only prover-supplied input. The bindings tie
    // every block row to the replay of that rate.

    /// Build the trace and honest HashAux for `[15 [1 s]]` hashing atom `val`.
    fn hash_setup(val: u64) -> (VecTrace, crate::ccs::HashAux) {
        let g = Goldilocks::new;
        let mut order = Reduction::<1024>::new();
        let s = order.atom(g(val)).unwrap();
        let tag1 = order.atom(g(1)).unwrap();
        let tag15 = order.atom(g(15)).unwrap();
        let quote_f = order.pair(tag1, s).unwrap();
        let hash_f = order.pair(tag15, quote_f).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, hash_f, 100, &NullCalls, &mut trace);
        assert_eq!(trace.0.len(), 26);
        let d = *order.digest(s).unwrap();
        let rate = [
            d[0], d[1], d[2], d[3],
            Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO,
        ];
        (trace, crate::ccs::HashAux { rate })
    }

    /// E2E: two hash blocks in one trace — bindings, round CCS and linkage
    /// all round-trip.
    #[test]
    fn e2e_two_hash_blocks_roundtrip() {
        let (mut trace, aux1) = hash_setup(42);
        let (trace2, aux2) = hash_setup(42);
        trace.0.extend(trace2.0);
        let stmt = zero_statement();
        let params = ProofParams::default();
        let tp = commit(&trace, &[aux1, aux2], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&tp, &stmt, &params).is_ok());
    }

    /// Negative: a tampered rate (not any digest) diverges from the trace at
    /// every row — the binding gate rejects at commit.
    #[test]
    fn commit_rejects_tampered_hash_rate() {
        let (trace, _) = hash_setup(42);
        let forged = crate::ccs::HashAux { rate: [Goldilocks::new(3); 8] };
        let err = commit(&trace, &[forged], &[], &[], &zero_statement(), &ProofParams::default());
        assert!(matches!(err, Err(CommitError::HashBinding)));
    }

    /// Negative: a VALID digest of a different particle (swapped input) still
    /// diverges from the recorded sponge states — rejected at commit.
    #[test]
    fn commit_rejects_swapped_hash_rate() {
        let (trace, _) = hash_setup(42);
        let (_, aux_other) = hash_setup(43);
        let err = commit(&trace, &[aux_other], &[], &[], &zero_statement(), &ProofParams::default());
        assert!(matches!(err, Err(CommitError::HashBinding)));
    }

    /// Negative: a prover who folds a forged output-digest binding directly
    /// (bypassing the commit gate) is caught by the degree-1 zero-error rule
    /// — the hash bindings inherit it from the axis machinery.
    #[test]
    fn verify_rejects_folded_forged_hash_digest() {
        use crate::ccs::eq_step;

        let (trace, aux) = hash_setup(42);
        let mut steps =
            crate::ccs::build_hash_binding_steps_from_trace(&trace.0, &[aux]).unwrap();
        // The squeeze row's recorded digest limb vs a forged replay value.
        let digest0 = Goldilocks::new(trace.0[25].r()[4]).canonicalize();
        steps.push(eq_step(digest0 + Goldilocks::ONE, digest0));

        let trace_proof = prove_raw_linear_steps(&steps);
        let err = verify(&trace_proof, &zero_statement(), &ProofParams::default());
        assert!(matches!(err, Err(VerifyError::LinearErrorNonzero)));
    }

    /// Negative: the hash binding group of one valid proof spliced into
    /// another valid proof breaks the option-A linkage digest — the hash
    /// bindings inherit the cross-group linkage.
    #[test]
    fn verify_rejects_spliced_hash_binding_group() {
        let stmt = zero_statement();
        let params = ProofParams::default();
        let (t1, a1) = hash_setup(42);
        let (t2, a2) = hash_setup(43);
        let p1 = commit(&t1, &[a1], &[], &[], &stmt, &params).unwrap();
        let p2 = commit(&t2, &[a2], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&p1, &stmt, &params).is_ok());
        assert!(verify(&p2, &stmt, &params).is_ok());

        let eq_group = |p: &TraceProof| {
            let idxs: Vec<usize> = p
                .groups
                .iter()
                .enumerate()
                .filter(|(_, (_, a))| a.committed_instance.num_cols == 3)
                .map(|(i, _)| i)
                .collect();
            assert_eq!(idxs.len(), 1, "exactly one eq-step binding group");
            idxs[0]
        };
        let i1 = eq_group(&p1);
        let i2 = eq_group(&p2);
        assert_ne!(
            p1.groups[i1].1.witness_commitment.as_bytes(),
            p2.groups[i2].1.witness_commitment.as_bytes(),
            "different hashed particles give different binding witnesses"
        );

        let mut spliced = p1.clone();
        spliced.groups[i1] = p2.groups[i2].clone();
        assert!(
            verify(&spliced, &stmt, &params).is_err(),
            "hash binding group spliced from another proof must not verify"
        );
    }

    // ── compose (2) and cons (3): real-trace e2e coverage ────────────────────
    // These catch the pattern_quote bug class: a constraint wired to
    // registers no real trace sets makes honest programs unprovable — the
    // degree-1 zero-error rule turns the stale constraint into a rejection.

    /// E2E: a real compose program, run twice so the compose row is followed
    /// by another row (engaging pattern_compose in the main fold), commits
    /// and verifies.
    #[test]
    fn e2e_compose_roundtrip() {
        // [2 [[1 5] [1 [1 9]]]] — quote-only sub-formulas keep the trace
        // free of axis rows (which would demand AxisOpenings):
        // evaluate(obj,[1 5]) = 5, evaluate(obj,[1 [1 9]]) = [1 9],
        // continuation reduce(5, [1 9]) = 9.
        let g = Goldilocks::new;
        let mut ar = Reduction::<1024>::new();
        let obj = ar.atom(g(5)).unwrap();
        let t1 = ar.atom(g(1)).unwrap();
        let five = ar.atom(g(5)).unwrap();
        let nine = ar.atom(g(9)).unwrap();
        let qx = ar.pair(t1, five).unwrap();
        let q9 = ar.pair(t1, nine).unwrap();
        let qq9 = ar.pair(t1, q9).unwrap();
        let body = ar.pair(qx, qq9).unwrap();
        let t2 = ar.atom(g(2)).unwrap();
        let formula = ar.pair(t2, body).unwrap();

        let mut trace = VecTrace::default();
        nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
        nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
        assert!(trace.0.iter().any(|r| r.r()[0] == 2), "trace has a compose row");

        let stmt = zero_statement();
        let params = ProofParams::default();
        let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&tp, &stmt, &params).is_ok());
    }

    /// E2E: a real cons program (`[3 [[1 7] [1 9]]]`), run twice, commits
    /// and verifies.
    #[test]
    fn e2e_cons_roundtrip() {
        let g = Goldilocks::new;
        let mut ar = Reduction::<1024>::new();
        let obj = ar.atom(g(5)).unwrap();
        let t1 = ar.atom(g(1)).unwrap();
        let seven = ar.atom(g(7)).unwrap();
        let nine = ar.atom(g(9)).unwrap();
        let qa = ar.pair(t1, seven).unwrap();
        let qb = ar.pair(t1, nine).unwrap();
        let body = ar.pair(qa, qb).unwrap();
        let t3 = ar.atom(g(3)).unwrap();
        let formula = ar.pair(t3, body).unwrap();

        let mut trace = VecTrace::default();
        nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
        nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
        assert!(trace.0.iter().any(|r| r.r()[0] == 3), "trace has a cons row");

        let stmt = zero_statement();
        let params = ProofParams::default();
        let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&tp, &stmt, &params).is_ok());
    }

    // ── look (pattern 17): public-root e2e and negatives ─────────────────────
    // The look chain (opening → value=r7 → point=r6 → leaf=dims[r5] → root =
    // r4/r11-r13) previously ended at the object's root limbs — witness data.
    // Statement.bbg_root makes the root a public input; these tests exercise
    // the full commit()/verify() pipeline for look for the first time.

    /// Run `[17 [[1 ns] [1 key]]]` against a provider over `evals`; the
    /// object carries the solo root limbs. Returns (trace, openings, root).
    fn look_setup(evals: &[u64], key: u64) -> (VecTrace, Vec<LookOpening>, [u8; 32]) {
        use nox::{BrakedownLookProvider, reduce};

        let g = Goldilocks::new;
        let poly = MultilinearPoly::new(evals.iter().map(|&v| g(v)).collect());
        let provider = BrakedownLookProvider::new(poly);
        let root = crate::ccs::standalone_root(&provider, 0);
        let root_bytes = root_to_bytes(&root);

        let mut ar = Reduction::<1024>::new();
        // object [[l0 | [l1 | [l2 | l3]]] | rest]
        let l: Vec<_> = root.iter().map(|&x| ar.atom(x).unwrap()).collect();
        let inner = ar.pair(l[2], l[3]).unwrap();
        let mid = ar.pair(l[1], inner).unwrap();
        let root_pair = ar.pair(l[0], mid).unwrap();
        let rest = ar.atom(g(0)).unwrap();
        let obj = ar.pair(root_pair, rest).unwrap();
        // formula [17 [[1 0] [1 key]]]
        let t17 = ar.atom(g(17)).unwrap();
        let t1 = ar.atom(g(1)).unwrap();
        let vns = ar.atom(g(0)).unwrap();
        let vkey = ar.atom(g(key)).unwrap();
        let nf = ar.pair(t1, vns).unwrap();
        let kf = ar.pair(t1, vkey).unwrap();
        let body = ar.pair(nf, kf).unwrap();
        let formula = ar.pair(t17, body).unwrap();

        let mut trace = VecTrace::default();
        let _ = reduce(&mut ar, obj, formula, 1000, &provider, &mut trace);
        assert!(trace.0.iter().any(|r| r.r()[0] == 17), "trace has a look row");
        let openings = crate::ccs::look_openings_from_provider(&provider);
        assert_eq!(openings.len(), 1);
        (trace, openings, root_bytes)
    }

    fn look_statement(root: [u8; 32]) -> Statement {
        Statement { bbg_root: root, ..zero_statement() }
    }

    /// E2E: a real look program against a committed state, its root public
    /// in the Statement, round-trips through commit and verify.
    #[test]
    fn e2e_look_roundtrip() {
        let (trace, openings, root) = look_setup(&[10, 20, 30, 40], 2);
        let stmt = look_statement(root);
        let params = ProofParams::default();
        let tp = commit(&trace, &[], &[], &openings, &stmt, &params).unwrap();
        assert!(verify(&tp, &stmt, &params).is_ok());
    }

    /// Negative: the public root names a different state — rejected at commit.
    #[test]
    fn commit_rejects_look_root_mismatch() {
        let (trace, openings, root) = look_setup(&[10, 20, 30, 40], 2);
        let mut wrong = root;
        wrong[0] ^= 1;
        let err = commit(&trace, &[], &[], &openings, &look_statement(wrong), &ProofParams::default());
        assert!(matches!(err, Err(CommitError::LookBinding)));
    }

    /// Negative: a VALID opening of a different state (its own consistent
    /// leaves and root) against this statement's root — rejected at commit.
    #[test]
    fn commit_rejects_swapped_look_opening() {
        let (trace, _, root) = look_setup(&[10, 20, 30, 40], 2);
        let (_, other_openings, _) = look_setup(&[11, 21, 31, 41], 2);
        let err = commit(&trace, &[], &[], &other_openings, &look_statement(root), &ProofParams::default());
        assert!(matches!(err, Err(CommitError::LookBinding)));
    }

    /// Negative: tampered leaves — the recomputed root diverges from both the
    /// trace registers and the public root — rejected at commit.
    #[test]
    fn commit_rejects_tampered_look_leaves() {
        let (trace, mut openings, root) = look_setup(&[10, 20, 30, 40], 2);
        openings[0].leaves.dims[3] = [Goldilocks::new(7); 4];
        let err = commit(&trace, &[], &[], &openings, &look_statement(root), &ProofParams::default());
        assert!(matches!(err, Err(CommitError::LookBinding)));
    }

    /// Negative: look rows against the zero-root sentinel — a program that
    /// reads state must declare its root — rejected at commit.
    #[test]
    fn commit_rejects_look_without_public_root() {
        let (trace, openings, _) = look_setup(&[10, 20, 30, 40], 2);
        let err = commit(&trace, &[], &[], &openings, &zero_statement(), &ProofParams::default());
        assert!(matches!(err, Err(CommitError::LookBinding)));
    }

    /// Negative: a prover who folds a root-vs-statement binding for the wrong
    /// public root directly (bypassing the commit gate) is caught by the
    /// degree-1 zero-error rule.
    #[test]
    fn verify_rejects_folded_wrong_statement_root() {
        use crate::ccs::eq_step;
        use crate::ccs::verifier_steps::read_limb;

        let (trace, openings, root) = look_setup(&[10, 20, 30, 40], 2);
        let mut steps =
            crate::ccs::build_look_steps_from_trace(&trace.0, &openings, &root).unwrap();
        // The forged binding: recomputed root limb vs a different public root.
        let limbs = crate::ccs::root_from_leaves(&openings[0].leaves);
        let mut wrong = root;
        wrong[0] ^= 1;
        steps.push(eq_step(limbs[0], read_limb(&wrong, 0)));

        // Keep only the linear eq steps for the raw fold (the root-chain
        // hemera pairs use a different CCS shape).
        let eq_only: Vec<_> = steps
            .into_iter()
            .filter(|(inst, _)| inst.num_cols == 3)
            .collect();
        let trace_proof = prove_raw_linear_steps(&eq_only);
        let err = verify(&trace_proof, &zero_statement(), &ProofParams::default());
        assert!(matches!(err, Err(VerifyError::LinearErrorNonzero)));
    }

    /// Negative: the look eq-step group of one valid proof spliced into
    /// another valid proof over the SAME state (same statement, different
    /// keys read) breaks the option-A linkage.
    #[test]
    fn verify_rejects_spliced_look_group() {
        let params = ProofParams::default();
        let (t1, o1, root) = look_setup(&[10, 20, 30, 40], 2);
        let (t2, o2, root2) = look_setup(&[10, 20, 30, 40], 0);
        assert_eq!(root, root2, "same state, same public root");
        let stmt = look_statement(root);
        let p1 = commit(&t1, &[], &[], &o1, &stmt, &params).unwrap();
        let p2 = commit(&t2, &[], &[], &o2, &stmt, &params).unwrap();
        assert!(verify(&p1, &stmt, &params).is_ok());
        assert!(verify(&p2, &stmt, &params).is_ok());

        // The root-chain hemera pairs split the look eq run into two VZ=3
        // groups: [opening + value/point/leaf eqs] and [root + statement eqs].
        // Splice the first — different keys read give different witnesses.
        let eq_group = |p: &TraceProof| {
            let idxs: Vec<usize> = p
                .groups
                .iter()
                .enumerate()
                .filter(|(_, (_, a))| a.committed_instance.num_cols == 3)
                .map(|(i, _)| i)
                .collect();
            assert_eq!(idxs.len(), 2, "two eq-step groups around the root chain");
            idxs[0]
        };
        let i1 = eq_group(&p1);
        let i2 = eq_group(&p2);
        assert_ne!(
            p1.groups[i1].1.witness_commitment.as_bytes(),
            p2.groups[i2].1.witness_commitment.as_bytes(),
            "different keys read give different binding witnesses"
        );

        let mut spliced = p1.clone();
        spliced.groups[i1] = p2.groups[i2].clone();
        assert!(
            verify(&spliced, &stmt, &params).is_err(),
            "look group spliced from another proof must not verify"
        );
    }

    /// T-2: tampered eval_value causes verify() to reject.
    #[test]
    fn verify_rejects_tampered_eval_value() {
        let trace = malformed_trace();
        let stmt = zero_statement();
        let params = ProofParams::default();
        let mut trace_proof = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();

        // Flip the eval_value in the first group's proof.
        let (proof, _acc) = &mut trace_proof.groups[0];
        proof.eval_value = Goldilocks::new(proof.eval_value.as_u64().wrapping_add(1));

        assert!(verify(&trace_proof, &stmt, &params).is_err());
    }
}


