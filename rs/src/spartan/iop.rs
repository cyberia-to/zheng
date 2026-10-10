//! The SuperSpartan IOP, generic over the challenge field: outer sumcheck
//! (log m rounds), batched inner sumcheck (log n rounds), ending in one claim
//! `z̃(r) = v` about the witness polynomial at a challenge-field point `r`.
//!
//! The commitment to `z` and the opening of that claim belong to the caller's
//! PCS. With `F = Goldilocks` this is the 0.4.0 Spartan transcript byte for
//! byte; with `F = Fp3` every challenge, round polynomial and evaluation is an
//! Fp3 element. Per-round soundness error is `degree / |F|`; see
//! `specs/soundness.md` for the ledger row.

use nebu::Goldilocks;

use crate::field::ChallengeField;
use crate::multilinear::{eq_evals, evaluate_multilinear};
use crate::sumcheck::prover::{OuterSumcheckProver, SumcheckProver};
use crate::sumcheck::verifier::SumcheckVerifier;
use crate::transcript::Transcript;
use crate::types::{CCSInstance, SumcheckPoly, VerifyError};

/// Everything the IOP sends; the PCS opening of `eval_value` is separate.
#[derive(Clone, Debug)]
pub struct IopProof<F: ChallengeField> {
    /// û_i(ρ_x) for every matrix.
    pub matrix_evals: Vec<F>,
    pub outer_sumcheck_polys: Vec<SumcheckPoly<F>>,
    pub sumcheck_polys: Vec<SumcheckPoly<F>>,
    /// The claimed z̃(r) at the inner sumcheck's final point.
    pub eval_value: F,
}

fn lift<F: ChallengeField>(values: &[Goldilocks]) -> Vec<F> {
    values.iter().map(|&v| F::from_base(v)).collect()
}

/// w_combined[col] = Σ_i γ^i · Σ_r eq(ρ_x, r) · M_i[r][col].
///
/// Row weights use the reversed challenge order: the outer fold pins the
/// MSB row bit with the round-0 challenge, while eq_evals is LSB-first.
pub(crate) fn combined_weights<F: ChallengeField>(
    instance: &CCSInstance,
    rho_x: &[F],
    gamma: F,
    size: usize,
) -> Vec<F> {
    let rho_rev: Vec<F> = rho_x.iter().rev().copied().collect();
    let eq_rox = eq_evals(&rho_rev);
    let mut w = vec![F::ZERO; size];
    let mut gamma_pow = F::ONE;
    for matrix in &instance.matrices {
        for (r, row) in matrix.entries.iter().enumerate() {
            let weight = gamma_pow * eq_rox.get(r).copied().unwrap_or(F::ZERO);
            for &(col, coeff) in row {
                if col < size {
                    w[col] = w[col] + weight * F::from_base(coeff);
                }
            }
        }
        gamma_pow = gamma_pow * gamma;
    }
    w
}

/// Prove that `z` (power-of-two length, already committed and absorbed by
/// the caller) satisfies `instance`. Returns the proof and the evaluation
/// point (MSB-first: `point[0]` pairs with the top index bit).
pub fn prove<F: ChallengeField>(
    instance: &CCSInstance,
    z: &[Goldilocks],
    transcript: &mut Transcript,
) -> (IopProof<F>, Vec<F>) {
    let m = instance.num_rows;
    let log_m = m.trailing_zeros() as usize;
    let row_mv: Vec<Vec<F>> = instance
        .matrices
        .iter()
        .map(|matrix| {
            (0..m)
                .map(|r| {
                    let dot = matrix.entries.get(r).map_or(Goldilocks::ZERO, |row| {
                        row.iter().fold(Goldilocks::ZERO, |acc, &(col, coeff)| {
                            acc + coeff * z.get(col).copied().unwrap_or(Goldilocks::ZERO)
                        })
                    });
                    F::from_base(dot)
                })
                .collect()
        })
        .collect();

    let tau: Vec<F> = (0..log_m).map(|_| F::squeeze(transcript)).collect();
    let mut outer = OuterSumcheckProver::new(
        eq_evals(&tau),
        row_mv,
        instance.multisets.clone(),
        lift(&instance.coeffs),
    );
    let mut rho_x: Vec<F> = Vec::with_capacity(log_m);
    let outer_sumcheck_polys = outer.prove_all(|poly| {
        transcript.absorb_sumcheck_poly(rho_x.len(), poly);
        let r = F::squeeze(transcript);
        rho_x.push(r);
        r
    });
    let matrix_evals = outer.matrix_evals();
    for &e in &matrix_evals {
        transcript.absorb_eval(e);
    }

    let gamma = F::squeeze(transcript);
    let w = combined_weights(instance, &rho_x, gamma, z.len());
    let mut inner = SumcheckProver::new(w, lift(z));
    let mut point: Vec<F> = Vec::with_capacity(z.len().trailing_zeros() as usize);
    let sumcheck_polys = inner.prove_all(|poly| {
        transcript.absorb_sumcheck_poly(point.len(), poly);
        let r = F::squeeze(transcript);
        point.push(r);
        r
    });
    let (_, eval_value) = inner.final_claim();
    let proof = IopProof {
        matrix_evals,
        outer_sumcheck_polys,
        sumcheck_polys,
        eval_value,
    };
    (proof, point)
}

/// Verify the IOP against `error_evals` (all zero for a strict instance).
/// `num_vars` is fixed by the caller, never by the proof. On success returns
/// the point at which the caller's PCS must open `eval_value`; the caller
/// absorbs `eval_value` before deriving the opening's randomness.
pub fn verify<F: ChallengeField>(
    instance: &CCSInstance,
    proof: &IopProof<F>,
    error_evals: &[Goldilocks],
    num_vars: usize,
    transcript: &mut Transcript,
) -> Result<Vec<F>, VerifyError> {
    if proof.matrix_evals.len() != instance.matrices.len() {
        return Err(VerifyError::EvaluationMismatch);
    }
    let log_m = instance.num_rows.trailing_zeros() as usize;
    let tau: Vec<F> = (0..log_m).map(|_| F::squeeze(transcript)).collect();
    // eq_evals is LSB-first (tau_j <-> bit j), matching the prover's weighting.
    let e_claim = eq_evals(&tau)
        .iter()
        .zip(error_evals.iter())
        .fold(F::ZERO, |acc, (&w, &e)| acc + w * F::from_base(e));
    let (outer_final, rho_x) =
        SumcheckVerifier::new(e_claim, log_m).verify_all(&proof.outer_sumcheck_polys, transcript)?;
    for &e in &proof.matrix_evals {
        transcript.absorb_eval(e);
    }

    // eq(τ, ρ_x) · G(ρ_x) must equal the outer sumcheck's final claim.
    let mut constraint = F::ZERO;
    for (multiset, &coeff) in instance.multisets.iter().zip(instance.coeffs.iter()) {
        let mut product = F::ONE;
        for &idx in multiset {
            product = product
                * proof
                    .matrix_evals
                    .get(idx)
                    .copied()
                    .ok_or(VerifyError::EvaluationMismatch)?;
        }
        constraint = constraint + F::from_base(coeff) * product;
    }
    if evaluate_multilinear(&eq_evals(&tau), &rho_x) * constraint != outer_final {
        return Err(VerifyError::EvaluationMismatch);
    }

    let gamma = F::squeeze(transcript);
    let mut batched = F::ZERO;
    let mut gamma_pow = F::ONE;
    for &e in &proof.matrix_evals {
        batched = batched + gamma_pow * e;
        gamma_pow = gamma_pow * gamma;
    }
    let (final_claim, point) =
        SumcheckVerifier::new(batched, num_vars).verify_all(&proof.sumcheck_polys, transcript)?;
    let w = combined_weights(instance, &rho_x, gamma, 1usize << num_vars);
    if final_claim != evaluate_multilinear(&w, &point) * proof.eval_value {
        return Err(VerifyError::SumcheckFailed { round: num_vars });
    }
    Ok(point)
}

#[cfg(test)]
#[path = "iop_tests.rs"]
mod tests;
