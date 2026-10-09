//! Retired folded trace API — UNSOUND, compiled only with the `legacy` feature.
//!
//! `commit`, `open`, `verify_eval`, `verify`, `fold` and `decide` implement the
//! 0.3.x "HyperNova over hemera + Brakedown" path. It must not be used for
//! production. Its holes are recorded in `specs/decider.md` §soundness:
//!
//! - the fold is never checked by the verifier: hemera is not homomorphic,
//!   so the error vector is prover data (`decider.md`, "current
//!   implementation residual");
//! - the statement is not bound: a satisfying witness of nothing verifies for
//!   any `Statement` (finding 3), and the constant wire is free, so the
//!   all-zero witness satisfies the universal instance (finding 2);
//! - the Brakedown code distance is unproven (lens#6).
//!
//! The tests `retired_path_hole_zeroed_constant_wire_satisfies_universal_instance`
//! and `retired_path_hole_meaningless_witness_passes_for_any_statement`
//! (`folding/fold.rs`) demonstrate the holes; they pass because the path is
//! broken. The sound production APIs are `crate::execution` (public profile v3,
//! state profile v3, native private MITH) and `crate::envelope`; see
//! `specs/soundness.md`. The feature exists so external consumers can migrate;
//! it is removed in phase 5 of the proof-system repair.

use nebu::Goldilocks;
use nox::VecTrace;

use lens::brakedown::Brakedown;
use lens::{Commitment, Lens, MultilinearPoly, Opening};

use crate::ccs::{
    AxisOpening, HashAux, LookOpening, build_axis_steps_from_trace,
    build_axis_transcript_steps, build_hash_binding_steps_from_trace,
    build_look_steps_from_trace, build_look_transcript_steps,
    build_universal_steps_from_trace, eq_instance, universal_ccs,
};
use crate::folding::{decide as run_decide, fold_step};
use crate::spartan::verifier::SpartanVerifier;
use crate::transcript::Transcript;
use crate::types::{
    Accumulator, CCSInstance, CCSWitness, CommitError, DecideError, FoldError, OpenError, Proof,
    ProofGroup, ProofParams, Statement, TraceProof, VerifyError,
};

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
pub(crate) fn fold_all(instance: &CCSInstance, witnesses: &[CCSWitness]) -> Result<Accumulator, CommitError> {
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
mod tests;

#[cfg(all(test, feature = "serde"))]
mod serde_tests;
