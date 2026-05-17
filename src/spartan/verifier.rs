// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! SuperSpartan verifier: check sumcheck transcript and PCS opening.

use nebu::Goldilocks;

use lens::brakedown::Brakedown;
use lens::{Lens, Transcript as LensTranscript};

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
        expected_error: Goldilocks,
        transcript: &mut Transcript,
    ) -> Result<(), VerifyError> {
        // ── 1. Absorb commitment ─────────────────────────────────────────────
        transcript.absorb_commitment(&proof.commitment);

        // ── 2. Absorb claimed matrix evaluations û_i ─────────────────────────
        if proof.matrix_evals.len() != instance.matrices.len() {
            return Err(VerifyError::EvaluationMismatch);
        }
        for &e in &proof.matrix_evals {
            transcript.absorb_eval(e);
        }

        // ── 3. Check CCS constraint: Σ_j c_j · Π_{i ∈ S_j} û_i = expected_error ─
        let constraint_val = instance
            .multisets
            .iter()
            .zip(instance.coeffs.iter())
            .fold(Goldilocks::ZERO, |acc, (multiset, &coeff)| {
                let product = multiset.iter().fold(Goldilocks::ONE, |p, &idx| {
                    p * proof.matrix_evals.get(idx).copied().unwrap_or(Goldilocks::ZERO)
                });
                acc + coeff * product
            });
        if constraint_val != expected_error {
            return Err(VerifyError::EvaluationMismatch);
        }

        // ── 4. Squeeze γ for batched inner sumcheck ──────────────────────────
        let gamma = transcript.squeeze_challenge();

        // ── 5. Compute batched claim: Σ_i γ^i · û_i ─────────────────────────
        let batched_claim = {
            let mut c = Goldilocks::ZERO;
            let mut gp = Goldilocks::ONE;
            for &e in &proof.matrix_evals {
                c = c + gp * e;
                gp = gp * gamma;
            }
            c
        };

        // ── 6. Inner sumcheck verification ───────────────────────────────────
        let num_vars = proof.sumcheck_polys.len();
        let mut verifier = SumcheckVerifier::new(batched_claim, num_vars);
        let (final_claim, eval_point) =
            verifier.verify_all(&proof.sumcheck_polys, transcript)?;

        // ── 7. Final claim check: final_claim = w_combined(eval_point) · ẑ(eval_point)
        // w_combined(eval_point) = Σ_i γ^i · M_i[0, eval_point] evaluated at the
        // specific evaluation point. The prover provides eval_value = ẑ(eval_point).
        // We evaluate w_combined at that point.
        let w_at_point = {
            // For a sparse matrix with one row, M_i[0, x] selects specific columns.
            // The MLE of M_i evaluated at eval_point is M_i[0, ·] extended to F^n.
            // Since M_i is a selection matrix, M̃_i(eval_point) =
            //   Σ_col M_i[0, col] · eq_bit(col, eval_point)
            // where eq_bit is the multilinear basis function.
            // We compute this directly.
            use crate::multilinear::evaluate_multilinear;
            let z_size = 1usize << num_vars;
            let mut w_combined = vec![Goldilocks::ZERO; z_size];
            let mut gp = Goldilocks::ONE;
            for matrix in &instance.matrices {
                for row in &matrix.entries {
                    for &(col, coeff) in row {
                        if col < z_size {
                            w_combined[col] = w_combined[col] + gp * coeff;
                        }
                    }
                }
                gp = gp * gamma;
            }
            evaluate_multilinear(&w_combined, &eval_point)
        };

        let expected_final = w_at_point * proof.eval_value;
        if final_claim != expected_final {
            return Err(VerifyError::SumcheckFailed { round: num_vars });
        }

        // ── 8. Absorb eval_value, then PCS verify ────────────────────────────
        // Reverse the point: Brakedown uses tensor_reduce (LSB-first), sumcheck uses
        // fold_inplace (MSB-first). See prover.rs for the reconciliation rationale.
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
