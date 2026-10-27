//! The verifier half of the Spartan IOP over compressed round polynomials.
//!
//! A sumcheck round polynomial `g(X) = c_0 + c_1 X + … + c_d X^d` must
//! satisfy `g(0) + g(1) = claim`, i.e. `c_1 = claim − 2 c_0 − Σ_{i≥2} c_i`.
//! The prover therefore sends every coefficient except `c_1`; the verifier
//! restores `c_1` from its running claim and continues exactly as
//! [`super::iop::verify`] does (the restored polynomial is the one absorbed
//! into the transcript). Soundness is unchanged: a prover who sends a full
//! polynomial that fails the round check cannot do better than one whose
//! `c_1` is forced — the verifier accepts the same set of transcripts.
//!
//! Unlike `iop::verify`, [`reduce`] does not check the final witness claim:
//! it returns the inner sumcheck's point, its final claim and the combined
//! matrix weight at that point, and the caller checks
//! `claim = weight · z̃(point)` with a `z̃(point)` it assembles itself (the
//! succinct profile combines a committed half and a public half).

use crate::field::ChallengeField;
use crate::multilinear::evaluate_multilinear;
use crate::spartan::iop::{IopProof, combined_weights};

use crate::sumcheck::verifier::SumcheckVerifier;
use crate::transcript::Transcript;
use crate::types::{CCSInstance, SumcheckPoly, VerifyError};

/// Round polynomials without their linear coefficient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedRounds<F: ChallengeField> {
    /// Per round: `[c_0, c_2, c_3, …, c_d]`.
    pub rounds: Vec<Vec<F>>,
}

/// Drop `c_1` from every round polynomial.
pub fn compress<F: ChallengeField>(polys: &[SumcheckPoly<F>]) -> CompressedRounds<F> {
    CompressedRounds {
        rounds: polys
            .iter()
            .map(|p| {
                let mut c = p.coeffs.clone();
                if c.len() > 1 {
                    c.remove(1);
                }
                c
            })
            .collect(),
    }
}

/// Restore `c_1 = claim − 2 c_0 − Σ_{i≥2} c_i` for a polynomial of `degree`.
/// `None` if the compressed form does not have `degree` coefficients.
pub fn decompress<F: ChallengeField>(claim: F, degree: u8, rest: &[F]) -> Option<SumcheckPoly<F>> {
    if degree == 0 || rest.len() != usize::from(degree) {
        return None;
    }
    let c0 = rest[0];
    let tail = rest[1..].iter().fold(F::ZERO, |acc, &c| acc + c);
    let c1 = claim - c0 - c0 - tail;
    let mut coeffs = Vec::with_capacity(rest.len() + 1);
    coeffs.push(c0);
    coeffs.push(c1);
    coeffs.extend_from_slice(&rest[1..]);
    Some(SumcheckPoly { degree, coeffs })
}

/// Degree of the outer round polynomials: the CCS degree plus one (eq).
pub fn outer_degree(instance: &CCSInstance) -> u8 {
    let d = instance.multisets.iter().map(Vec::len).max().unwrap_or(1);
    u8::try_from(d + 1).expect("CCS degree below 255")
}

/// What the IOP reduces satisfiability to: the caller checks
/// `claim = (Σ_i γ^i M̃_i(ρ_x, point)) · z̃(point)`.
#[derive(Clone, Debug)]
pub struct Reduction<F: ChallengeField> {
    /// The inner sumcheck point, MSB-first (`point[0]` ↔ top index bit).
    pub point: Vec<F>,
    /// The inner sumcheck's final claim.
    pub claim: F,
    /// The outer sumcheck point, in round order.
    pub rho_x: Vec<F>,
    /// The batching challenge of the matrix evaluations.
    pub gamma: F,
}

impl<F: ChallengeField> Reduction<F> {
    /// `Σ_i γ^i M̃_i(ρ_x, point)` from the instance the IOP ran on.
    pub fn weight(&self, instance: &CCSInstance) -> F {
        let w = combined_weights(instance, &self.rho_x, self.gamma, 1usize << self.point.len());
        evaluate_multilinear(&w, &self.point)
    }
}

fn run_rounds<F: ChallengeField>(
    claim: F,
    degree: u8,
    rounds: &[Vec<F>],
    expected: usize,
    transcript: &mut Transcript,
) -> Result<(F, Vec<F>), VerifyError> {
    if rounds.len() != expected {
        return Err(VerifyError::SumcheckFailed { round: 0 });
    }
    let mut v = SumcheckVerifier::new(claim, expected);
    for (i, rest) in rounds.iter().enumerate() {
        let poly = decompress(v.current_claim(), degree, rest)
            .ok_or(VerifyError::SumcheckFailed { round: i })?;
        v.verify_round(&poly, transcript)?;
    }
    Ok((v.current_claim(), v.challenges().to_vec()))
}

/// Verify the strict-instance IOP (`Σ eq(τ, x)·G(x) = 0`) from compressed
/// rounds. `num_vars` (the witness variables) is the caller's, never the
/// proof's. Transcript order is identical to [`super::iop::prove`]. Only the
/// shape of `instance` is read (row count, matrix count, multisets,
/// coefficients); the matrix entries enter through [`Reduction::weight`] or
/// the caller's own evaluation of the same quantity.
pub fn reduce<F: ChallengeField>(
    instance: &CCSInstance,
    matrix_evals: &[F],
    outer: &CompressedRounds<F>,
    inner: &CompressedRounds<F>,
    num_vars: usize,
    transcript: &mut Transcript,
) -> Result<Reduction<F>, VerifyError> {
    if matrix_evals.len() != instance.matrices.len() || !instance.num_rows.is_power_of_two() {
        return Err(VerifyError::EvaluationMismatch);
    }
    let log_m = instance.num_rows.trailing_zeros() as usize;
    let tau: Vec<F> = (0..log_m).map(|_| F::squeeze(transcript)).collect();
    let (outer_final, rho_x) = run_rounds(
        F::ZERO,
        outer_degree(instance),
        &outer.rounds,
        log_m,
        transcript,
    )?;
    for &e in matrix_evals {
        transcript.absorb_eval(e);
    }
    let mut constraint = F::ZERO;
    for (multiset, &coeff) in instance.multisets.iter().zip(&instance.coeffs) {
        let product = multiset
            .iter()
            .fold(F::ONE, |acc, &i| acc * matrix_evals[i]);
        constraint = constraint + F::from_base(coeff) * product;
    }
    // eq(τ, ρ_x): the outer fold pins the top row bit first, eq_evals(τ) is
    // LSB-first, so τ_j pairs with ρ_x[log m − 1 − j]
    let eq_tau_rho = tau
        .iter()
        .zip(rho_x.iter().rev())
        .fold(F::ONE, |acc, (&t, &r)| acc * (t * r + (F::ONE - t) * (F::ONE - r)));
    if eq_tau_rho * constraint != outer_final {
        return Err(VerifyError::EvaluationMismatch);
    }
    let gamma = F::squeeze(transcript);
    let mut batched = F::ZERO;
    let mut gamma_pow = F::ONE;
    for &e in matrix_evals {
        batched = batched + gamma_pow * e;
        gamma_pow = gamma_pow * gamma;
    }
    let (claim, point) = run_rounds(batched, 2, &inner.rounds, num_vars, transcript)?;
    Ok(Reduction {
        point,
        claim,
        rho_x,
        gamma,
    })
}

/// The compressed rounds of an honest IOP proof: `(outer, inner)`.
pub fn compress_proof<F: ChallengeField>(
    proof: &IopProof<F>,
) -> (CompressedRounds<F>, CompressedRounds<F>) {
    (
        compress(&proof.outer_sumcheck_polys),
        compress(&proof.sumcheck_polys),
    )
}

#[cfg(test)]
#[path = "reduce_tests.rs"]
mod tests;
