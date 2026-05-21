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

pub mod transcript;
pub mod types;
pub mod multilinear;
pub mod sumcheck;
pub mod ccs;
pub mod spartan;
pub mod folding;

pub use transcript::Transcript;
pub use types::{
    Accumulator, CCSInstance, CCSWitness, CommitError, DecideError, FoldError,
    LensBackend, OpenError, Proof, ProofParams, SecurityLevel, SparseMatrix,
    Statement, SumcheckPoly, TraceProof, VerifyError,
};
pub use crate::ccs::{
    build_axis_transcript_steps, build_look_transcript_steps,
    look_openings_from_provider, AxisOpening, HashAux, LookOpening,
};

use nebu::Goldilocks;
use nox::VecTrace;

use lens::brakedown::Brakedown;
use lens::{Commitment, Lens, MultilinearPoly, Opening};

use crate::ccs::{
    build_axis_steps_from_trace, build_ccs_from_trace,
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
            && hash_row(first) != statement.input_hash {
                return Err(CommitError::StatementMismatch);
            }
    if statement.output_hash != [0u8; 32]
        && let Some(last) = trace.0.last()
            && hash_row(last) != statement.output_hash {
                return Err(CommitError::StatementMismatch);
            }

    // Build all step sequences and chain them.
    let main_steps          = build_ccs_from_trace(&trace.0);
    let hash_steps          = build_hash_steps_from_trace(&trace.0, hash_aux)?;
    let axis_steps          = build_axis_steps_from_trace(&trace.0, axis_openings)?;
    let axis_transcript     = build_axis_transcript_steps(&trace.0, axis_openings)?;
    let look_steps          = build_look_steps_from_trace(&trace.0, look_openings)?;
    let look_transcript     = build_look_transcript_steps(&trace.0, look_openings)?;

    let all_steps: Vec<(CCSInstance, CCSWitness)> = main_steps
        .into_iter()
        .chain(hash_steps)
        .chain(axis_steps)
        .chain(axis_transcript)
        .chain(look_steps)
        .chain(look_transcript)
        .collect();

    if all_steps.is_empty() {
        return Err(CommitError::TraceOverflow);
    }

    let mut groups: Vec<(Proof, Accumulator)> = Vec::new();

    // Sequential grouping: start a new group whenever the CCS instance changes.
    // Full equality is required because instances with the same structural shape
    // (matrix count, dimensions) but different matrix coefficients (e.g. distinct
    // Poseidon2 partial-round constants) must not fold together — their error_evals
    // are computed against the current instance's matrices while the verifier checks
    // against committed_instance, which only holds the first instance in the group.
    let mut cur_instance: Option<CCSInstance> = None;
    let mut cur_acc: Option<Accumulator> = None;
    let mut cur_transcript = Transcript::new();

    for (instance, witness) in &all_steps {
        let same = cur_instance.as_ref() == Some(instance);

        if !same {
            // Finalize previous group.
            if let Some(acc) = cur_acc.take() {
                let proof = run_decide(&acc, statement, params)
                    .map_err(CommitError::DecideFailed)?;
                groups.push((proof, acc));
            }
            cur_instance = Some(instance.clone());
            cur_acc = Some(blank_acc(instance));
            cur_transcript = Transcript::new();
        }

        fold_step(cur_acc.as_mut().unwrap(), instance, witness, &mut cur_transcript)
            .map_err(|_| CommitError::TraceOverflow)?;
    }

    // Finalize last group.
    if let Some(acc) = cur_acc.take() {
        let proof = run_decide(&acc, statement, params)
            .map_err(CommitError::DecideFailed)?;
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
    for (group_proof, acc) in &proof.groups {
        let mut transcript = Transcript::new_recursive();
        transcript.absorb_statement(statement);
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
/// bound to the given statement via Fiat-Shamir.
pub fn decide(
    acc: &Accumulator,
    statement: &Statement,
    params: &ProofParams,
) -> Result<Proof, DecideError> {
    run_decide(acc, statement, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox::{NullCalls, Order, Tag, VecTrace};
    use lens::brakedown::Brakedown;
    use lens::{Lens, MultilinearPoly, Transcript as LensTranscript};

    fn malformed_trace() -> VecTrace {
        // Two rows with tag=255 (unknown) → trivial_ccs (no constraints).
        // Used to test the full commit→verify pipeline without constraint logic.
        let mut order = Order::<1024>::new();
        let obj     = order.atom(Goldilocks::new(0), Tag::Field).unwrap();
        let tag_255 = order.atom(Goldilocks::new(255), Tag::Field).unwrap();
        let body    = order.atom(Goldilocks::new(0), Tag::Field).unwrap();
        let formula = order.cell(tag_255, body).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
        nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
        trace
    }

    fn zero_statement() -> Statement {
        Statement { program_hash: [0u8; 32], input_hash: [0u8; 32], output_hash: [0u8; 32], focus_bound: 0 }
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
        for &(idx, v) in vals { z[idx] = Goldilocks::new(v); }
        CCSWitness { z }
    }

    #[test]
    fn fold_add_multi_step_commit_verify() {
        use crate::ccs::{reg_t, reg_t1};
        use crate::ccs::patterns::build_step_ccs;
        use crate::folding::fold::fold_step;
        use crate::folding::decide::decide as run_decide;

        let instance = build_step_ccs(5); // add: r5_{t+1} - r3_t - r4_t = 0
        let witnesses = [
            make_z_33(&[(reg_t(3), 3), (reg_t(4), 4),  (reg_t1(5), 7)]),
            make_z_33(&[(reg_t(3), 10),(reg_t(4), 20), (reg_t1(5), 30)]),
            make_z_33(&[(reg_t(3), 1), (reg_t(4), 1),  (reg_t1(5), 2)]),
        ];
        for w in &witnesses { assert!(instance.is_satisfied_by(w)); }

        let mut acc = blank_acc(&instance);
        let mut transcript = Transcript::new();
        for w in &witnesses {
            fold_step(&mut acc, &instance, w, &mut transcript).unwrap();
        }
        assert_eq!(acc.step_count, 3);
        assert!(acc.error_evals.iter().all(|&e| e == Goldilocks::ZERO)); // degree-1: stays 0

        let stmt = zero_statement();
        let proof = run_decide(&acc, &stmt, &ProofParams::default()).unwrap();
        let trace_proof = TraceProof { groups: vec![(proof, acc)] };
        assert!(verify(&trace_proof, &stmt, &ProofParams::default()).is_ok());
    }

    #[test]
    fn fold_mul_multi_step_commit_verify() {
        use crate::ccs::{reg_t, reg_t1};
        use crate::ccs::patterns::build_step_ccs;
        use crate::folding::fold::fold_step;
        use crate::folding::decide::decide as run_decide;

        let instance = build_step_ccs(7); // mul: r5_{t+1} - r3_t * r4_t = 0
        let witnesses = [
            make_z_33(&[(reg_t(3), 6), (reg_t(4), 7),  (reg_t1(5), 42)]),
            make_z_33(&[(reg_t(3), 2), (reg_t(4), 5),  (reg_t1(5), 10)]),
            make_z_33(&[(reg_t(3), 3), (reg_t(4), 3),  (reg_t1(5), 9)]),
        ];
        for w in &witnesses { assert!(instance.is_satisfied_by(w)); }

        let mut acc = blank_acc(&instance);
        let mut transcript = Transcript::new();
        for w in &witnesses {
            fold_step(&mut acc, &instance, w, &mut transcript).unwrap();
        }
        assert_eq!(acc.step_count, 3);
        // degree-2 multi-fold: e_acc = error_evals(w_folded) ≠ 0 in general;
        // Spartan proves/verifies against this accumulated error.

        let stmt = zero_statement();
        let proof = run_decide(&acc, &stmt, &ProofParams::default()).unwrap();
        let trace_proof = TraceProof { groups: vec![(proof, acc)] };
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
        AxisOpening { commitment, point, value, opening, transcript_seed: b"e2e-axis-open".to_vec() }
    }

    /// E2E: trace with Poseidon2 hash operation → hash_aux drives particle CCS.
    ///
    /// formula = [15, [1, s]] hashes subject s, producing 25 rows (tag=15)
    /// plus 1 quote row (tag=1) — 26 total.  HashAux supplies the rate (the
    /// structural digest of s) so build_hash_steps_from_trace can replay the
    /// sponge and recover capacity elements.
    #[test]
    fn e2e_hash_accumulator_roundtrip() {
        let mut order = Order::<1024>::new();
        let s = order.atom(Goldilocks::new(42), Tag::Field).unwrap();
        let tag1  = order.atom(Goldilocks::new(1),  Tag::Field).unwrap();
        let tag15 = order.atom(Goldilocks::new(15), Tag::Field).unwrap();
        let quote_f = order.cell(tag1, s).unwrap();
        let hash_f  = order.cell(tag15, quote_f).unwrap();

        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, hash_f, 100, &NullCalls, &mut trace);
        // 1 quote row + 24 round rows + 1 squeeze row
        assert_eq!(trace.0.len(), 26);

        // Rate = structural digest of s (4 Goldilocks elements), zero-padded to 8.
        let in_digest = *order.digest(s).unwrap();
        let rate = [
            in_digest[0], in_digest[1], in_digest[2], in_digest[3],
            Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO,
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
        let mut order = Order::<1024>::new();
        let s = order.atom(Goldilocks::new(7), Tag::Field).unwrap();
        let tag0 = order.atom(Goldilocks::new(0), Tag::Field).unwrap();
        let addr1 = order.atom(Goldilocks::new(1), Tag::Field).unwrap();
        let axis_f = order.cell(tag0, addr1).unwrap();

        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, axis_f, 100, &NullCalls, &mut trace);
        nox::reduce(&mut order, s, axis_f,  99, &NullCalls, &mut trace);
        // Two axis rows; consecutive pair satisfies pattern_axis budget-decrement constraint.
        assert_eq!(trace.0.len(), 2);

        // One Brakedown opening per axis row (both use the same polynomial for simplicity).
        let ao1 = make_axis_opening();
        let ao2 = make_axis_opening();

        // Statement binding: real hashes from first and last trace rows.
        let input_hash  = super::hash_row(&trace.0[0]);
        let output_hash = super::hash_row(&trace.0[trace.0.len() - 1]);
        let stmt = Statement {
            program_hash: [0u8; 32],
            input_hash,
            output_hash,
            focus_bound: 10,
        };
        let params = ProofParams::default();

        let trace_proof = commit(&trace, &[], &[ao1, ao2], &[], &stmt, &params).unwrap();
        assert!(verify(&trace_proof, &stmt, &params).is_ok());
    }

    /// E2E: commit() rejects a statement whose input_hash does not match the
    /// hash of the first trace row.
    #[test]
    fn e2e_statement_binding_rejects_wrong_input_hash() {
        let mut order = Order::<1024>::new();
        let s    = order.atom(Goldilocks::new(7), Tag::Field).unwrap();
        let tag0 = order.atom(Goldilocks::new(0), Tag::Field).unwrap();
        let addr = order.atom(Goldilocks::new(1), Tag::Field).unwrap();
        let axis_f = order.cell(tag0, addr).unwrap();

        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, axis_f, 100, &NullCalls, &mut trace);
        nox::reduce(&mut order, s, axis_f,  99, &NullCalls, &mut trace);

        let mut wrong_hash = [0u8; 32];
        wrong_hash[0] = 0xff;

        let stmt = Statement {
            program_hash: [0u8; 32],
            input_hash: wrong_hash,
            output_hash: [0u8; 32],
            focus_bound: 0,
        };
        let params = ProofParams::default();
        let err = commit(&trace, &[], &[make_axis_opening(), make_axis_opening()], &[], &stmt, &params);
        assert!(matches!(err, Err(CommitError::StatementMismatch)));
    }

    /// E2E: commit() rejects when trace length exceeds statement focus_bound.
    #[test]
    fn e2e_statement_binding_rejects_focus_exceeded() {
        let trace = malformed_trace();   // 2 rows
        let stmt = Statement {
            program_hash: [0u8; 32],
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
            focus_bound: 1,              // trace has 2 rows > 1
        };
        let params = ProofParams::default();
        let err = commit(&trace, &[], &[], &[], &stmt, &params);
        assert!(matches!(err, Err(CommitError::FocusExhausted)));
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
