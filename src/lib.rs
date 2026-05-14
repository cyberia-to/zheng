// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! zheng — proof system: SuperSpartan IOP + sumcheck + Brakedown PCS.
//!
//! Five entry points: `commit`, `open`, `verify`, `fold`, `decide`.

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
    Statement, SumcheckPoly, VerifyError,
};

use nebu::Goldilocks;
use nox::VecTrace;

use lens::brakedown::Brakedown;
use lens::{Commitment, Lens, MultilinearPoly, Opening};

use crate::ccs::build_ccs_from_trace;
use crate::folding::{decide as run_decide, fold_step};
use crate::spartan::verifier::SpartanVerifier;

// ── five entry points ─────────────────────────────────────────────────────────

/// Prove a nox execution trace.
///
/// Folds all trace steps into a HyperNova accumulator, then runs the decider
/// to produce a proof. Returns the proof and the final accumulator state.
pub fn commit(
    trace: &VecTrace,
    params: &ProofParams,
) -> Result<(Proof, Accumulator), CommitError> {
    let steps = build_ccs_from_trace(&trace.0);
    if steps.is_empty() {
        return Err(CommitError::TraceOverflow);
    }

    // Use the first step's CCS structure to initialize the accumulator.
    let first_instance = steps[0].0.clone();
    let init_z = vec![Goldilocks::ZERO; 64];
    let mut acc = Accumulator {
        committed_instance: first_instance,
        folded_witness: CCSWitness { z: init_z.clone() },
        witness_commitment: Brakedown::commit_raw(&init_z),
        error_term: Goldilocks::ZERO,
        step_count: 0,
    };

    let mut transcript = Transcript::new();

    for (instance, witness) in &steps {
        fold_step(&mut acc, instance, witness, &mut transcript)
            .map_err(|_| CommitError::TraceOverflow)?;
    }

    let proof = run_decide(&acc, params)
        .map_err(|_| CommitError::TraceOverflow)?;

    Ok((proof, acc))
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
/// The proof must have been produced by `decide()` for the same CCS instance.
pub fn verify(
    proof: &Proof,
    instance: &CCSInstance,
    statement: &Statement,
    _params: &ProofParams,
) -> Result<(), VerifyError> {
    let mut transcript = Transcript::new_recursive();
    SpartanVerifier::verify(instance, statement, proof, &mut transcript)
}

/// Fold one trace step into an accumulator.
///
/// Call this repeatedly for each trace row pair to build up the accumulator,
/// then call `decide` to finalize the proof.
pub fn fold(
    acc: &mut Accumulator,
    instance: &CCSInstance,
    witness: &CCSWitness,
) -> Result<(), FoldError> {
    let mut transcript = Transcript::new();
    fold_step(acc, instance, witness, &mut transcript)
}

/// Run the SuperSpartan decider on an accumulated HyperNova state.
///
/// Produces the final proof from the accumulated CCS instance and witness.
pub fn decide(
    acc: &Accumulator,
    params: &ProofParams,
) -> Result<Proof, DecideError> {
    run_decide(acc, params)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
