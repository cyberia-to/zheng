// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! SuperSpartan verifier: check sumcheck transcript and PCS opening.

use nebu::Goldilocks;

use lens::brakedown::Brakedown;
use lens::{Lens, Transcript as LensTranscript};

use crate::multilinear::{eq_evals, evaluate_multilinear};
use crate::sumcheck::verifier::SumcheckVerifier;
use crate::transcript::Transcript;
use crate::types::{CCSInstance, Proof, VerifyError};

/// SuperSpartan verifier for CCS instances (any number of constraint rows).
pub struct SpartanVerifier;

impl SpartanVerifier {
    /// Verify that `proof` attests to a satisfying witness for `instance`.
    ///
    /// The transcript must already have the statement and accumulator public
    /// data absorbed before this call (done by `lib.rs::verify()`).
    pub fn verify(
        instance: &CCSInstance,
        proof: &Proof,
        error_evals: &[Goldilocks],
        transcript: &mut Transcript,
    ) -> Result<(), VerifyError> {
        // ── 1. Absorb commitment ─────────────────────────────────────────────
        transcript.absorb_commitment(&proof.commitment);

        // ── 2. Check matrix eval count ───────────────────────────────────────
        if proof.matrix_evals.len() != instance.matrices.len() {
            return Err(VerifyError::EvaluationMismatch);
        }

        // ── 3. Outer sumcheck (log m rounds) ─────────────────────────────────
        // For m=1: log_m=0, tau=[], e_claim=error_evals[0], 0 rounds, rho_x=[].
        let m = instance.num_rows;
        let log_m = m.trailing_zeros() as usize;
        let tau: Vec<Goldilocks> = transcript.squeeze_challenges(log_m);
        let e_claim = evaluate_multilinear(error_evals, &tau);

        let mut outer_verifier = SumcheckVerifier::new(e_claim, log_m);
        let (outer_final_claim, rho_x) =
            outer_verifier.verify_all(&proof.outer_sumcheck_polys, transcript)?;

        // ── 4. Absorb claimed û_i(ρ_x) ──────────────────────────────────────
        for &e in &proof.matrix_evals {
            transcript.absorb_eval(e);
        }

        // ── 5. Check outer final claim: eq(τ,ρ_x) · G(ρ_x) = outer_final_claim
        // G(ρ_x) = Σ_j c_j · ∏_{i ∈ S_j} û_i(ρ_x)
        let mut constraint_val = Goldilocks::ZERO;
        for (multiset, &coeff) in instance.multisets.iter().zip(instance.coeffs.iter()) {
            let mut product = Goldilocks::ONE;
            for &idx in multiset {
                let e = proof.matrix_evals
                    .get(idx)
                    .copied()
                    .ok_or(VerifyError::EvaluationMismatch)?;
                product *= e;
            }
            constraint_val += coeff * product;
        }
        // eq(τ, ρ_x) — the verifier computes this directly.
        // For m=1: tau=[], rho_x=[], eq_evals([])=[ONE], evaluate_multilinear([ONE],[])=ONE.
        let eq_val = evaluate_multilinear(&eq_evals(&tau), &rho_x);
        if eq_val * constraint_val != outer_final_claim {
            return Err(VerifyError::EvaluationMismatch);
        }

        // ── 6. Squeeze γ for batched inner sumcheck ──────────────────────────
        let gamma = transcript.squeeze_challenge();

        // ── 7. Compute batched claim: Σ_i γ^i · û_i(ρ_x) ────────────────────
        let batched_claim = {
            let mut c = Goldilocks::ZERO;
            let mut gp = Goldilocks::ONE;
            for &e in &proof.matrix_evals {
                c += gp * e;
                gp *= gamma;
            }
            c
        };

        // ── 8. Inner sumcheck verification ───────────────────────────────────
        let num_vars = proof.sumcheck_polys.len();
        let mut verifier = SumcheckVerifier::new(batched_claim, num_vars);
        let (final_claim, eval_point) =
            verifier.verify_all(&proof.sumcheck_polys, transcript)?;

        // ── 9. Build w_combined using eq(ρ_x, r) weights ────────────────────
        // w_combined[col] = Σ_i γ^i · Σ_r eq(ρ_x,r) · M_i[r][col]
        // For m=1: eq_rox=[ONE], reduces to Σ_i γ^i · M_i[0][col] (same as before).
        let eq_rox = eq_evals(&rho_x);
        let z_size = 1usize << num_vars;
        let mut w_combined = vec![Goldilocks::ZERO; z_size];
        let mut gp = Goldilocks::ONE;
        for matrix in &instance.matrices {
            for (r, row) in matrix.entries.iter().enumerate() {
                let weight = gp * eq_rox.get(r).copied().unwrap_or(Goldilocks::ZERO);
                for &(col, coeff) in row {
                    if col < z_size {
                        w_combined[col] += weight * coeff;
                    }
                }
            }
            gp *= gamma;
        }
        let w_at_point = evaluate_multilinear(&w_combined, &eval_point);

        let expected_final = w_at_point * proof.eval_value;
        if final_claim != expected_final {
            return Err(VerifyError::SumcheckFailed { round: num_vars });
        }

        // ── 10. Absorb eval_value, then PCS verify ───────────────────────────
        let pcs_point: Vec<Goldilocks> = eval_point.iter().copied().rev().collect();
        transcript.absorb_eval(proof.eval_value);
        let seed = transcript.squeeze_hash();
        let mut lt = LensTranscript::new(&seed);
        if !Brakedown::verify(
            &proof.commitment,
            &pcs_point,
            proof.eval_value,
            &proof.pcs_opening,
            &mut lt,
        ) {
            return Err(VerifyError::LensFailed);
        }

        Ok(())
    }
}
