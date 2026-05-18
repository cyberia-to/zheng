// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! SuperSpartan prover: commit witness, outer sumcheck (log m rounds),
//! inner sumcheck (log n rounds), PCS open.
//!
//! For m=1 (all current single-row patterns), log m = 0 and the outer
//! sumcheck runs 0 rounds — identical to the previous single-row behavior.

use nebu::Goldilocks;

use lens::brakedown::Brakedown;
use lens::{Lens, MultilinearPoly, Transcript as LensTranscript};

use crate::multilinear::{eq_evals, pad_to_power_of_two};
use crate::sumcheck::prover::{OuterSumcheckProver, SumcheckProver};
use crate::transcript::Transcript;
use crate::types::{CCSInstance, CCSWitness, Proof};

/// SuperSpartan prover for CCS instances (any number of constraint rows).
pub struct SpartanProver;

impl SpartanProver {
    /// Prove that `witness` satisfies `instance`.
    ///
    /// The proof is non-interactive via the Fiat-Shamir `transcript`.
    pub fn prove(
        instance: &CCSInstance,
        witness: &CCSWitness,
        transcript: &mut Transcript,
    ) -> Proof {
        // ── 1. Pad z to power-of-2 size for PCS ─────────────────────────────────
        let mut z_padded = witness.z.clone();
        pad_to_power_of_two(&mut z_padded, 64);
        let num_vars = z_padded.len().trailing_zeros() as usize; // log n

        // ── 2. Commit to z ───────────────────────────────────────────────────────
        let z_poly = MultilinearPoly::new(z_padded.clone());
        let commitment = Brakedown::commit(&z_poly);
        transcript.absorb_commitment(&commitment);

        // ── 3. Per-row matrix-vector products ────────────────────────────────────
        // row_mv[i][r] = M_i[row r] · z  for all matrices i and rows r
        let m = instance.num_rows;
        let log_m = m.trailing_zeros() as usize; // 0 for m=1, 4 for m=16

        let row_mv: Vec<Vec<Goldilocks>> = instance.matrices.iter().map(|matrix| {
            (0..m).map(|r| {
                matrix.entries.get(r).map_or(Goldilocks::ZERO, |row| {
                    row.iter().fold(Goldilocks::ZERO, |acc, &(col, coeff)| {
                        acc + coeff * z_padded.get(col).copied().unwrap_or(Goldilocks::ZERO)
                    })
                })
            }).collect::<Vec<Goldilocks>>()
        }).collect();

        // ── 4. Outer sumcheck: Σ_x eq(τ,x)·G(x) ────────────────────────────────
        // τ has log m components; empty for m=1 → 0 rounds, trivial output.
        // OuterSumcheckProver tracks each f_i table separately and evaluates
        // G at degree+2 points per round for correct polynomial interpolation.
        let tau: Vec<Goldilocks> = transcript.squeeze_challenges(log_m);
        let eq_tau = eq_evals(&tau);

        let mut outer_prover = OuterSumcheckProver::new(
            eq_tau,
            row_mv,
            instance.multisets.clone(),
            instance.coeffs.clone(),
        );
        let mut rho_x: Vec<Goldilocks> = Vec::with_capacity(log_m);
        let outer_sumcheck_polys = outer_prover.prove_all(|poly| {
            transcript.absorb_sumcheck_poly(rho_x.len(), poly);
            let r = transcript.squeeze_challenge();
            rho_x.push(r);
            r
        });

        // ── 5. û_i(ρ_x) from folded f_tables — exact MLE via bookkeeping ────────
        // After log_m folds, f_tables[i][0] = û_i(ρ_x). No separate evaluation needed.
        let matrix_evals = outer_prover.matrix_evals();

        for &e in &matrix_evals {
            transcript.absorb_eval(e);
        }

        // ── 6. Squeeze γ for batched inner sumcheck ──────────────────────────────
        let gamma = transcript.squeeze_challenge();

        // ── 7. Build w_combined: Σ_i γ^i · M̃_i(ρ_x, ·) ─────────────────────────
        // w_combined[col] = Σ_i γ^i · Σ_r eq(ρ_x,r) · M_i[r][col]
        // For m=1: eq_rox=[1], reduces to Σ_i γ^i · M_i[0][col].
        let eq_rox = eq_evals(&rho_x);
        let mut w_combined = vec![Goldilocks::ZERO; z_padded.len()];
        let mut gamma_pow = Goldilocks::ONE;
        for matrix in &instance.matrices {
            for (r, row) in matrix.entries.iter().enumerate() {
                let weight = gamma_pow * eq_rox.get(r).copied().unwrap_or(Goldilocks::ZERO);
                for &(col, coeff) in row {
                    if col < w_combined.len() {
                        w_combined[col] += weight * coeff;
                    }
                }
            }
            gamma_pow *= gamma;
        }

        // ── 8. Inner sumcheck (log n rounds) ─────────────────────────────────────
        let mut prover = SumcheckProver::new(w_combined, z_padded.clone());
        let mut eval_point: Vec<Goldilocks> = Vec::with_capacity(num_vars);
        let sumcheck_polys = prover.prove_all(|poly| {
            transcript.absorb_sumcheck_poly(eval_point.len(), poly);
            let r = transcript.squeeze_challenge();
            eval_point.push(r);
            r
        });

        // ── 9. PCS evaluation value ───────────────────────────────────────────────
        let (_w_fin, f_fin) = prover.final_claim();
        let eval_value = f_fin;
        transcript.absorb_eval(eval_value);

        // ── 10. PCS open via Brakedown ────────────────────────────────────────────
        // Brakedown uses LSB-first; sumcheck MSB-first. Reverse to reconcile.
        let pcs_point: Vec<Goldilocks> = eval_point.iter().copied().rev().collect();
        let seed = transcript.squeeze_hash();
        let mut lt = LensTranscript::new(&seed);
        let pcs_opening = Brakedown::open(&z_poly, &pcs_point, &mut lt);

        Proof {
            commitment,
            matrix_evals,
            outer_sumcheck_polys,
            sumcheck_polys,
            eval_value,
            pcs_opening,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::patterns::build_step_ccs;
    use crate::ccs::{reg_t, reg_t1, CONST_IDX, Z_LEN};
    use crate::spartan::verifier::SpartanVerifier;
    use crate::transcript::Transcript;
    fn make_z(vals: &[(usize, u64)]) -> Vec<Goldilocks> {
        let mut z = vec![Goldilocks::ZERO; Z_LEN];
        z[CONST_IDX] = Goldilocks::ONE;
        for &(idx, v) in vals {
            z[idx] = Goldilocks::new(v);
        }
        z
    }

    #[test]
    fn prove_verify_add_pattern() {
        // r3=5, r4=3, r5_{t+1}=8
        let z = make_z(&[(reg_t(3), 5), (reg_t(4), 3), (reg_t1(5), 8)]);
        let instance = build_step_ccs(5);
        let witness = CCSWitness { z };

        let mut pt = Transcript::new();
        let proof = SpartanProver::prove(&instance, &witness, &mut pt);

        let mut vt = Transcript::new();
        let result = SpartanVerifier::verify(&instance, &proof, &[Goldilocks::ZERO], &mut vt);
        assert!(result.is_ok(), "verify failed: {result:?}");
    }

    #[test]
    fn prove_verify_mul_pattern() {
        // r3=6, r4=7, r5_{t+1}=42
        let z = make_z(&[(reg_t(3), 6), (reg_t(4), 7), (reg_t1(5), 42)]);
        let instance = build_step_ccs(7);
        let witness = CCSWitness { z };

        let mut pt = Transcript::new();
        let proof = SpartanProver::prove(&instance, &witness, &mut pt);

        let mut vt = Transcript::new();
        assert!(SpartanVerifier::verify(&instance, &proof, &[Goldilocks::ZERO], &mut vt).is_ok());
    }
}
