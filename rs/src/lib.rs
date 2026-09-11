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
pub mod wire;

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
    build_axis_steps_from_trace, build_hash_binding_steps_from_trace, build_look_steps_from_trace,
    build_universal_steps_from_trace, eq_instance, universal_ccs,
};
use crate::folding::{decide as run_decide, fold_step};
use crate::spartan::verifier::SpartanVerifier;
use crate::types::ProofGroup;

// ── five entry points ─────────────────────────────────────────────────────────

/// Compute the hemera hash of a trace row's 16 registers as a 32-byte digest.
///
/// This is the exact binding `commit()` enforces between
/// `Statement.input_hash`/`output_hash` and the first/last trace rows —
/// exported so provers (joy) can construct statements that bind.
pub fn row_hash(row: &nox::TraceRow) -> [u8; 32] {
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

/// Fold a sequence of witnesses of one instance into a fresh accumulator.
fn fold_all(instance: &CCSInstance, witnesses: &[CCSWitness]) -> Result<Accumulator, CommitError> {
    let mut acc = Accumulator::blank(instance);
    let mut transcript = Transcript::new();
    for w in witnesses {
        fold_step(&mut acc, instance, w, &mut transcript).map_err(|_| CommitError::TraceOverflow)?;
    }
    Ok(acc)
}

/// Prove a nox execution trace.
///
/// Every Layer-1 row — each consecutive trace pair, each replayed
/// Fiat-Shamir Poseidon2 round of an axis/look opening, each BBG root-chain
/// compression — is a witness of the ONE universal step instance and folds
/// into ONE HyperNova accumulator. The opening bindings (axis, hash, look eq
/// steps) fold into a second, degree-1 accumulator when present. Each is
/// closed by one decider under a shared linkage digest. The proof is two
/// groups at most and its size does not depend on the trace length.
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
        && row_hash(first) != statement.input_hash
    {
        return Err(CommitError::StatementMismatch);
    }
    if statement.output_hash != [0u8; 32]
        && let Some(last) = trace.0.last()
        && row_hash(last) != statement.output_hash
    {
        return Err(CommitError::StatementMismatch);
    }

    // The legacy recursive gadgets describe the retired Tensor protocol;
    // they cannot verify authenticated TensorMerkle columns and paths.
    // Explicit refusal prevents treating an empty gadget as a checked opening.
    if !axis_openings.is_empty() || !look_openings.is_empty() {
        return Err(CommitError::UnsupportedRecursiveOpening);
    }

    // Opening bindings (eq instance) first — their gates name the cause
    // (a wrong hash rate, a swapped axis commitment) more precisely than the
    // universal row gate, which would also reject the rows they feed.
    let mut bindings = build_hash_binding_steps_from_trace(&trace.0, hash_aux)?;
    bindings.extend(build_axis_steps_from_trace(&trace.0, axis_openings)?);
    // Layer-1 rows (universal instance).
    let mut rows = build_universal_steps_from_trace(&trace.0, hash_aux)?;
    rows.extend(build_axis_transcript_steps(&trace.0, axis_openings)?);
    let (look_eq, look_rows) =
        build_look_steps_from_trace(&trace.0, look_openings, &statement.bbg_root)?;
    bindings.extend(look_eq);
    rows.extend(look_rows);
    rows.extend(build_look_transcript_steps(&trace.0, look_openings)?);

    if rows.is_empty() {
        return Err(CommitError::TraceOverflow);
    }

    // Pass 1 — fold. One accumulator per instance; within each, trace order.
    let universal_acc = fold_all(universal_ccs(), &rows)?;
    let binding_acc = if bindings.is_empty() {
        None
    } else {
        let eq = eq_instance();
        let witnesses: Vec<CCSWitness> = bindings.into_iter().map(|(_, w)| w).collect();
        Some(fold_all(&eq, &witnesses)?)
    };

    // Pass 2 — cross-group linkage over every group's witness commitment.
    let mut commitments = vec![&universal_acc.witness_commitment];
    if let Some(acc) = &binding_acc {
        commitments.push(&acc.witness_commitment);
    }
    let linkage = linkage_digest(&commitments);

    // Pass 3 — decide each group under the shared linkage digest.
    let close = |acc: Accumulator| -> Result<ProofGroup, CommitError> {
        let proof =
            run_decide(&acc, statement, &linkage, params).map_err(CommitError::DecideFailed)?;
        Ok(ProofGroup { proof, accumulator: acc })
    };
    let universal = close(universal_acc)?;
    let binding = binding_acc.map(close).transpose()?;

    Ok(TraceProof { universal, binding })
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
/// The universal group is checked against `ccs::universal_ccs()`, the
/// binding group against `ccs::eq_instance()` — the instances come from
/// the verifier, never from the proof. Both groups must verify.
pub fn verify(
    proof: &TraceProof,
    statement: &Statement,
    _params: &ProofParams,
) -> Result<(), VerifyError> {
    // Recompute the cross-group linkage digest from the proof's own groups —
    // it must match what every group's decide transcript absorbed.
    let commitments: Vec<&Commitment> =
        proof.groups().map(|g| &g.accumulator.witness_commitment).collect();
    let linkage = linkage_digest(&commitments);

    let eq = eq_instance();
    let instances = core::iter::once(universal_ccs()).chain(core::iter::once(&eq));
    for (group, instance) in proof.groups().zip(instances) {
        let acc = &group.accumulator;
        if acc.error_evals.len() != instance.num_rows {
            return Err(VerifyError::GroupLayout);
        }

        // Degree-1 instances (the binding group) fold satisfied steps to
        // exactly zero error — error is linear in the witness. A non-zero
        // entry means an unsatisfied step (e.g. a forged axis binding) was
        // folded in; the relaxed Spartan check alone would accept it. The
        // universal instance is not linear: its rows are gated products, so
        // its error vector carries genuine cross terms and this rule cannot
        // apply — commit()'s per-row gate is what refuses a violated row.
        let linear = instance.multisets.iter().all(|multiset| multiset.len() <= 1);
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
        SpartanVerifier::verify(instance, &group.proof, &acc.error_evals, &mut transcript)?;
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
/// single-group linkage digest, so a `TraceProof` whose only group is this
/// one (a universal accumulator, no binding group) verifies with [`verify`].
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
    use lens::{Lens, MultilinearPoly};
    use nox::{NullCalls, Reduction, VecTrace};

    /// Two rows with tag=255 (unknown pattern). Under the universal step
    /// instance no selector can be set for such a row — it is unprovable.
    fn malformed_trace() -> VecTrace {
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

    /// `[1 5]` reduced twice: two quote rows, the smallest provable trace.
    fn quote_trace() -> VecTrace {
        let mut order = Reduction::<1024>::new();
        let obj = order.atom(Goldilocks::new(0)).unwrap();
        let t1 = order.atom(Goldilocks::new(1)).unwrap();
        let five = order.atom(Goldilocks::new(5)).unwrap();
        let formula = order.pair(t1, five).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
        nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
        assert_eq!(trace.0.len(), 2);
        trace
    }

    #[test]
    fn commit_verify_roundtrip() {
        let trace = quote_trace();
        let stmt = zero_statement();
        let params = ProofParams::default();
        let trace_proof = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
        assert_eq!(trace_proof.group_count(), 1, "no openings: universal group only");
        assert!(verify(&trace_proof, &stmt, &params).is_ok());
    }

    /// An unknown pattern tag has no selector column: the row is
    /// unprovable and commit names it.
    #[test]
    fn commit_rejects_unknown_pattern_tag() {
        let trace = malformed_trace();
        let err = commit(&trace, &[], &[], &[], &zero_statement(), &ProofParams::default());
        assert!(matches!(err, Err(CommitError::StepUnsatisfied(0))), "{err:?}");
    }

    // ── helpers for manual witness construction ──────────────────────────────

    /// A universal row of pattern `tag` with the given register values.
    fn row(tag: u64, vals: &[(usize, u64)]) -> CCSWitness {
        let mut v = vec![(crate::ccs::reg_t(0), tag)];
        v.extend_from_slice(vals);
        crate::ccs::universal::test_witness(&v)
    }

    /// Fold universal rows and close them as a one-group TraceProof.
    fn fold_universal(rows: &[CCSWitness]) -> ProofGroup {
        let instance = universal_ccs();
        let mut acc = Accumulator::blank(instance);
        let mut transcript = Transcript::new();
        for w in rows {
            assert!(instance.is_satisfied_by(w));
            crate::folding::fold_step(&mut acc, instance, w, &mut transcript).unwrap();
        }
        let proof = decide(&acc, &zero_statement(), &ProofParams::default()).unwrap();
        ProofGroup { proof, accumulator: acc }
    }

    #[test]
    fn fold_add_multi_step_commit_verify() {
        use crate::ccs::reg_t;
        let rows = [
            row(5, &[(reg_t(4), 3), (reg_t(5), 4), (reg_t(6), 7)]),
            row(5, &[(reg_t(4), 10), (reg_t(5), 20), (reg_t(6), 30)]),
            row(5, &[(reg_t(4), 1), (reg_t(5), 1), (reg_t(6), 2)]),
        ];
        let universal = fold_universal(&rows);
        assert_eq!(universal.accumulator.step_count, 3);
        let trace_proof = TraceProof { universal, binding: None };
        assert!(verify(&trace_proof, &zero_statement(), &ProofParams::default()).is_ok());
    }

    #[test]
    fn fold_mixed_patterns_commit_verify() {
        use crate::ccs::reg_t;
        // add, mul and quote rows in one accumulator — the point of the
        // universal instance. Degree-2+ terms leave genuine cross-term
        // error; Spartan proves/verifies against the accumulated error.
        let rows = [
            row(7, &[(reg_t(4), 6), (reg_t(5), 7), (reg_t(6), 42)]),
            row(5, &[(reg_t(4), 2), (reg_t(5), 5), (reg_t(6), 7)]),
            row(1, &[(reg_t(4), 9), (reg_t(7), 9)]),
        ];
        let universal = fold_universal(&rows);
        assert_eq!(universal.accumulator.step_count, 3);
        let trace_proof = TraceProof { universal, binding: None };
        assert!(verify(&trace_proof, &zero_statement(), &ProofParams::default()).is_ok());
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

        // Interpreter-mode axis rows (NullCalls) carry no commitment and
        // owe no openings.

        // Statement binding: real hashes from first and last trace rows.
        let input_hash = super::row_hash(&trace.0[0]);
        let output_hash = super::row_hash(&trace.0[trace.0.len() - 1]);
        let stmt = Statement {
            program_hash: [0u8; 32],
            input_hash,
            output_hash,
            focus_bound: 10,
        bbg_root: [0u8; 32],
        };
        let params = ProofParams::default();

        let trace_proof = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
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
        let err = commit(&trace, &[], &[], &[], &stmt, &params);
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

    #[test]
    fn authenticated_recursive_openings_are_refused_until_constrained() {
        let (trace, openings) = prover_active_axis_setup(0);
        assert!(matches!(
            commit(&trace, &[], &openings, &[], &zero_statement(), &ProofParams::default()),
            Err(CommitError::UnsupportedRecursiveOpening)
        ));
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

        // The binding group holds the axis opening eq steps.
        let b1 = p1.binding.as_ref().expect("axis proof has a binding group");
        let b2 = p2.binding.as_ref().expect("axis proof has a binding group");
        assert_ne!(
            b1.accumulator.witness_commitment.as_bytes(),
            b2.accumulator.witness_commitment.as_bytes(),
            "the two binding groups differ (different noun commitments)"
        );

        let mut spliced = p1.clone();
        spliced.binding = Some(b2.clone());
        assert!(
            verify(&spliced, &stmt, &params).is_err(),
            "axis group spliced from another proof must not verify"
        );
    }

    /// Fold a hand-built eq step sequence as the binding group next to a
    /// satisfied universal group — the route of a malicious prover who
    /// bypasses commit()'s strictness gates AND `fold_step`'s own
    /// per-witness satisfiability gate (`crate::folding::fold::fold_step_unchecked`,
    /// test-only). These tests exist to pin the verify()-time zero-error
    /// rule as a backstop independent of the fold-time gate — the fold-time
    /// gate alone (reachable via the public `fold_step`/`commit()`) already
    /// rejects an unsatisfied linear step before it can ever reach here; see
    /// `folding::fold::tests` for that regression.
    fn prove_raw_linear_steps(steps: &[(CCSInstance, CCSWitness)]) -> TraceProof {
        use crate::ccs::reg_t;
        use crate::folding::fold::fold_step_unchecked;

        let universal_acc = fold_all(
            universal_ccs(),
            &[row(1, &[(reg_t(4), 5), (reg_t(7), 5)])],
        )
        .unwrap();
        let eq = eq_instance();
        let mut binding_acc = Accumulator::blank(&eq);
        let mut transcript = Transcript::new();
        for (_, w) in steps {
            fold_step_unchecked(&mut binding_acc, &eq, w, &mut transcript).unwrap();
        }
        let linkage = linkage_digest(&[
            &universal_acc.witness_commitment,
            &binding_acc.witness_commitment,
        ]);
        let stmt = zero_statement();
        let params = ProofParams::default();
        let close = |acc: Accumulator| ProofGroup {
            proof: run_decide(&acc, &stmt, &linkage, &params).unwrap(),
            accumulator: acc,
        };
        TraceProof { universal: close(universal_acc), binding: Some(close(binding_acc)) }
    }

    /// Regression: the PUBLIC folding path (`fold_all`, which calls the
    /// gated `fold_step`) now refuses an unsatisfied binding step before it
    /// is folded in at all — a caller no longer needs `verify()`'s zero-error
    /// rule to catch this; `fold_step` itself does. This is the fold-time
    /// half of the fix; `verify_rejects_folded_wrong_commitment_binding` and
    /// its siblings below pin the verify-time backstop for the (now
    /// unreachable via the public API) case where the fold-time gate is
    /// ALSO bypassed (`fold_step_unchecked`, test-only).
    #[test]
    fn fold_all_rejects_unsatisfied_eq_step() {
        use crate::ccs::eq_step;

        let eq = eq_instance();
        let (_, bad_step) = eq_step(Goldilocks::new(1), Goldilocks::new(2));
        let err = fold_all(&eq, &[bad_step]);
        assert!(matches!(err, Err(CommitError::TraceOverflow)), "{err:?}");
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

    /// Group count is a function of which structures occur, never of trace
    /// length: two hash blocks and three hash blocks yield the same number of
    /// accumulator groups, and the step counts grow instead. (Two, not one:
    /// a block followed by another block adds the squeeze→quote boundary
    /// pair — a structure a single block never has.)
    #[test]
    fn group_count_independent_of_trace_length() {
        let stmt = zero_statement();
        let params = ProofParams::default();

        let (mut t1, a1) = hash_setup(42);
        let (t1b, a2) = hash_setup(43);
        t1.0.extend(t1b.0);
        let p1 = commit(&t1, &[a1, a2], &[], &[], &stmt, &params).unwrap();

        let (mut t3, b1) = hash_setup(42);
        let (t3b, b2) = hash_setup(43);
        let (t3c, b3) = hash_setup(44);
        t3.0.extend(t3b.0);
        t3.0.extend(t3c.0);
        let p3 = commit(&t3, &[b1, b2, b3], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&p3, &stmt, &params).is_ok());

        assert_eq!(p1.group_count(), 2, "universal + binding");
        assert_eq!(
            p1.group_count(),
            p3.group_count(),
            "groups are structures, not runs: 2 vs 3 hash blocks"
        );
        let steps = |p: &TraceProof| -> u64 { p.groups().map(|g| g.accumulator.step_count).sum() };
        assert!(steps(&p3) > steps(&p1), "the extra block folds into existing groups");
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

        let b1 = p1.binding.as_ref().expect("hash proof has a binding group");
        let b2 = p2.binding.as_ref().expect("hash proof has a binding group");
        assert_ne!(
            b1.accumulator.witness_commitment.as_bytes(),
            b2.accumulator.witness_commitment.as_bytes(),
            "different hashed particles give different binding witnesses"
        );

        let mut spliced = p1.clone();
        spliced.binding = Some(b2.clone());
        assert!(
            verify(&spliced, &stmt, &params).is_err(),
            "hash binding group spliced from another proof must not verify"
        );

        // The universal group is linked too: swapping it between two
        // proofs of different hashed particles breaks both digests.
        let mut spliced = p1.clone();
        spliced.universal = p2.universal.clone();
        assert!(
            verify(&spliced, &stmt, &params).is_err(),
            "universal group spliced from another proof must not verify"
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
        let (mut steps, _rows) =
            crate::ccs::build_look_steps_from_trace(&trace.0, &openings, &root).unwrap();
        // The forged binding: recomputed root limb vs a different public root.
        let limbs = crate::ccs::root_from_leaves(&openings[0].leaves);
        let mut wrong = root;
        wrong[0] ^= 1;
        steps.push(eq_step(limbs[0], read_limb(&wrong, 0)));

        let trace_proof = prove_raw_linear_steps(&steps);
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

        // Every eq step — opening, value/point/leaf and root/statement
        // bindings — is in the ONE binding group; the root-chain rows are
        // universal rows.
        let b1 = p1.binding.as_ref().expect("look proof has a binding group");
        let b2 = p2.binding.as_ref().expect("look proof has a binding group");
        assert_ne!(
            b1.accumulator.witness_commitment.as_bytes(),
            b2.accumulator.witness_commitment.as_bytes(),
            "different keys read give different binding witnesses"
        );

        let mut spliced = p1.clone();
        spliced.binding = Some(b2.clone());
        assert!(
            verify(&spliced, &stmt, &params).is_err(),
            "look group spliced from another proof must not verify"
        );
    }

    /// Real-trace guard for the pattern family: every universal row of a
    /// real nox trace must SATISFY the universal instance (the commit gate).
    /// This is the test that catches stale register wiring (the
    /// pattern_quote bug class) for any pattern it covers — the old
    /// add/sub/mul/eq/branch/inv encodings all fail it.
    #[test]
    fn real_traces_satisfy_pattern_family() {
        use crate::ccs::build_universal_steps_from_trace;

        let g = Goldilocks::new;
        // (tag, name): binary ops [tag [[1 a] [1 b]]] — field ops, eq, and
        // the multi-row bit patterns lt/xor/and/shl.
        for (tag, name) in [
            (5u64, "add"),
            (6, "sub"),
            (7, "mul"),
            (9, "eq"),
            (10, "lt"),
            (11, "xor"),
            (12, "and"),
            (14, "shl"),
        ] {
            for (a, b) in [(9u64, 4u64), (9, 9)] {
                let mut ar = Reduction::<1024>::new();
                let obj = ar.atom(g(1)).unwrap();
                let t = ar.atom(g(tag)).unwrap();
                let t1 = ar.atom(g(1)).unwrap();
                let va = ar.atom(g(a)).unwrap();
                let vb = ar.atom(g(b)).unwrap();
                let qa = ar.pair(t1, va).unwrap();
                let qb = ar.pair(t1, vb).unwrap();
                let body = ar.pair(qa, qb).unwrap();
                let formula = ar.pair(t, body).unwrap();
                let mut trace = VecTrace::default();
                nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
                nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
                assert!(trace.0.iter().any(|r| r.r()[0] == tag), "{name}: no tag row");
                let r = build_universal_steps_from_trace(&trace.0, &[]);
                assert!(r.is_ok(), "{name}({a},{b}): {r:?}");
            }
        }

        // unary ops [tag [1 a]]: inv (64-row Fermat chain), not (32-row).
        for (tag, name, a) in [(8u64, "inv", 7u64), (13, "not", 0xF0F0)] {
            let mut ar = Reduction::<1024>::new();
            let obj = ar.atom(g(1)).unwrap();
            let t = ar.atom(g(tag)).unwrap();
            let t1 = ar.atom(g(1)).unwrap();
            let va = ar.atom(g(a)).unwrap();
            let body = ar.pair(t1, va).unwrap();
            let formula = ar.pair(t, body).unwrap();
            let mut trace = VecTrace::default();
            nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
            nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
            assert!(trace.0.iter().any(|r| r.r()[0] == tag), "{name}: no tag row");
            let r = build_universal_steps_from_trace(&trace.0, &[]);
            assert!(r.is_ok(), "{name}({a}): {r:?}");
        }

        // branch [4 [[1 t] [[1 10] [1 20]]]] — both arms
        for test in [0u64, 7] {
            let mut ar = Reduction::<1024>::new();
            let obj = ar.atom(g(1)).unwrap();
            let t4 = ar.atom(g(4)).unwrap();
            let t1 = ar.atom(g(1)).unwrap();
            let vt = ar.atom(g(test)).unwrap();
            let vy = ar.atom(g(10)).unwrap();
            let vn = ar.atom(g(20)).unwrap();
            let qt = ar.pair(t1, vt).unwrap();
            let qy = ar.pair(t1, vy).unwrap();
            let qn = ar.pair(t1, vn).unwrap();
            let arms = ar.pair(qy, qn).unwrap();
            let body = ar.pair(qt, arms).unwrap();
            let formula = ar.pair(t4, body).unwrap();
            let mut trace = VecTrace::default();
            nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
            nox::reduce(&mut ar, obj, formula, 1000, &NullCalls, &mut trace);
            assert!(trace.0.iter().any(|r| r.r()[0] == 4), "no branch row");
            let r = build_universal_steps_from_trace(&trace.0, &[]);
            assert!(r.is_ok(), "branch(test={test}): {r:?}");
        }
    }

    /// Real-trace guard for call (16): a provider that answers, a check
    /// formula that accepts (quotes 0), rows satisfy the universal instance
    /// and the whole trace round-trips.
    #[test]
    fn real_call_trace_satisfies_and_roundtrips() {
        struct Answer;
        impl nox::LookProvider for Answer {
            fn look(&self, _c: Goldilocks, _n: Goldilocks, _k: Goldilocks) -> Option<Goldilocks> {
                None
            }
        }
        impl<const N: usize> nox::CallProvider<N> for Answer {
            fn provide(
                &self,
                reduction: &mut Reduction<N>,
                _tag: Goldilocks,
                _object: nox::Order,
            ) -> Option<nox::Order> {
                reduction.atom(Goldilocks::new(77))
            }
        }

        // [16 [[1 3] [1 0]]]: tag formula quotes 3, check formula quotes 0.
        let g = Goldilocks::new;
        let mut ar = Reduction::<1024>::new();
        let obj = ar.atom(g(1)).unwrap();
        let t16 = ar.atom(g(16)).unwrap();
        let t1 = ar.atom(g(1)).unwrap();
        let three = ar.atom(g(3)).unwrap();
        let zero = ar.atom(g(0)).unwrap();
        let tag_f = ar.pair(t1, three).unwrap();
        let check_f = ar.pair(t1, zero).unwrap();
        let body = ar.pair(tag_f, check_f).unwrap();
        let formula = ar.pair(t16, body).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut ar, obj, formula, 1000, &Answer, &mut trace);
        nox::reduce(&mut ar, obj, formula, 1000, &Answer, &mut trace);
        assert!(trace.0.iter().any(|r| r.r()[0] == 16), "no call row");

        let stmt = zero_statement();
        let params = ProofParams::default();
        let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&tp, &stmt, &params).is_ok());
    }

    /// T-2: tampered eval_value causes verify() to reject.
    #[test]
    fn verify_rejects_tampered_eval_value() {
        let trace = quote_trace();
        let stmt = zero_statement();
        let params = ProofParams::default();
        let mut trace_proof = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();

        // Flip the eval_value in the universal group's proof.
        let proof = &mut trace_proof.universal.proof;
        proof.eval_value = Goldilocks::new(proof.eval_value.as_u64().wrapping_add(1));

        assert!(verify(&trace_proof, &stmt, &params).is_err());
    }

    /// A proof cannot name its own instance: the error vector must have the
    /// verifier's row count for the group's position.
    #[test]
    fn verify_rejects_foreign_group_layout() {
        let trace = quote_trace();
        let stmt = zero_statement();
        let params = ProofParams::default();
        let mut tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
        tp.universal.accumulator.error_evals.truncate(1);
        assert!(matches!(verify(&tp, &stmt, &params), Err(VerifyError::GroupLayout)));
    }
}



#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;
    use nox::{NullCalls, Reduction, VecTrace};

    /// A proof artifact survives JSON round-trip and still verifies;
    /// a tampered byte in the wire form is rejected or fails verification.
    #[test]
    fn proof_json_roundtrip_verifies() {
        let g = Goldilocks::new;
        let mut order = Reduction::<1024>::new();
        let s = order.atom(g(7)).unwrap();
        let tag0 = order.atom(g(0)).unwrap();
        let addr = order.atom(g(1)).unwrap();
        let axis_f = order.pair(tag0, addr).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, axis_f, 100, &NullCalls, &mut trace);
        nox::reduce(&mut order, s, axis_f, 99, &NullCalls, &mut trace);

        let stmt = Statement {
            program_hash: [3u8; 32],
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
            focus_bound: 10,
            bbg_root: [0u8; 32],
        };
        let params = ProofParams::default();
        let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
        assert!(verify(&tp, &stmt, &params).is_ok());

        let proof_json = serde_json::to_string(&tp).unwrap();
        let stmt_json = serde_json::to_string(&stmt).unwrap();
        let tp2: TraceProof = serde_json::from_str(&proof_json).unwrap();
        let stmt2: Statement = serde_json::from_str(&stmt_json).unwrap();
        assert_eq!(stmt, stmt2);
        assert!(verify(&tp2, &stmt2, &params).is_ok());

        // Non-canonical field element rejected at deserialize.
        let bad = proof_json.replacen("[", "[18446744073709551615,", 1);
        let r: Result<TraceProof, _> = serde_json::from_str(&bad);
        assert!(r.is_err(), "non-canonical wire form must not deserialize");
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

    /// Every bit position of `bytes` flipped in turn must leave a proof
    /// that fails to deserialize or fails to verify. `bits` selects which
    /// bits of each byte to flip.
    fn assert_wire_tight(bytes: &[u8], stmt: &Statement, bits: &[u8]) {
        let params = ProofParams::default();
        let mut survivors = Vec::new();
        for i in 0..bytes.len() {
            for &b in bits {
                let mut t = bytes.to_vec();
                t[i] ^= 1 << b;
                if let Ok(p) = postcard::from_bytes::<TraceProof>(&t)
                    && verify(&p, stmt, &params).is_ok()
                {
                    survivors.push((i, b));
                }
            }
        }
        assert!(
            survivors.is_empty(),
            "{} single-bit flips still verify (byte, bit): {:?}",
            survivors.len(),
            &survivors[..survivors.len().min(16)]
        );
    }

    /// Wire tightness: every bit of a serialized proof is verifier-checked.
    /// A flip that still verifies would mean the verifier accepted a proof
    /// different from the one produced — or that the wire carries bytes
    /// the verifier never reads. Universal group only (no openings), every
    /// bit of every byte.
    #[test]
    fn every_bit_of_the_wire_is_checked() {
        let g = Goldilocks::new;
        let mut order = Reduction::<1024>::new();
        let obj = order.atom(g(0)).unwrap();
        let t1 = order.atom(g(1)).unwrap();
        let five = order.atom(g(5)).unwrap();
        let formula = order.pair(t1, five).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
        nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);

        let stmt = zero_statement();
        let params = ProofParams::default();
        let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
        let bytes = postcard::to_allocvec(&tp).unwrap();
        let back: TraceProof = postcard::from_bytes(&bytes).unwrap();
        assert!(verify(&back, &stmt, &params).is_ok(), "the untouched wire verifies");
        assert_wire_tight(&bytes, &stmt, &[0, 1, 2, 3, 4, 5, 6, 7]);
    }

    /// Wire tightness of a two-group proof (a hash block: universal +
    /// binding group, two lens openings). Bits 0 and 7 of every byte — the
    /// value bit and the varint continuation bit.
    #[test]
    fn every_byte_of_a_two_group_wire_is_checked() {
        let g = Goldilocks::new;
        let mut order = Reduction::<1024>::new();
        let s = order.atom(g(42)).unwrap();
        let tag1 = order.atom(g(1)).unwrap();
        let tag15 = order.atom(g(15)).unwrap();
        let quote_f = order.pair(tag1, s).unwrap();
        let hash_f = order.pair(tag15, quote_f).unwrap();
        let mut trace = VecTrace::default();
        nox::reduce(&mut order, s, hash_f, 100, &NullCalls, &mut trace);
        let d = *order.digest(s).unwrap();
        let rate = [d[0], d[1], d[2], d[3], g(0), g(0), g(0), g(0)];

        let stmt = zero_statement();
        let params = ProofParams::default();
        let tp = commit(&trace, &[HashAux { rate }], &[], &[], &stmt, &params).unwrap();
        assert_eq!(tp.group_count(), 2);
        let bytes = postcard::to_allocvec(&tp).unwrap();
        assert_wire_tight(&bytes, &stmt, &[0, 7]);
    }
}
