// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! SuperSpartan prover: commit witness, inner sumcheck, PCS open.
//!
//! For m=1 CCS instances (single constraint row), the outer sumcheck is
//! trivial. The inner sumcheck (6 rounds over the 64-element witness) reduces
//! û_i claims to a single PCS evaluation.

use nebu::Goldilocks;

use lens::brakedown::Brakedown;
use lens::{Lens, MultilinearPoly, Transcript as LensTranscript};

use crate::multilinear::pad_to_power_of_two;
use crate::sumcheck::prover::SumcheckProver;
use crate::transcript::Transcript;
use crate::types::{CCSInstance, CCSWitness, Proof, SparseMatrix};

/// Compute M_i · z for a 1-row matrix and z vector.
fn matrix_dot(m: &SparseMatrix, z: &[Goldilocks]) -> Goldilocks {
    m.entries
        .first()
        .map(|row| {
            row.iter().fold(Goldilocks::ZERO, |acc, &(col, coeff)| {
                acc + coeff * z.get(col).copied().unwrap_or(Goldilocks::ZERO)
            })
        })
        .unwrap_or(Goldilocks::ZERO)
}

/// SuperSpartan prover for m=1 CCS instances.
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
        // ── 1. Pad z to power-of-2 size for PCS ─────────────────────────────
        let mut z_padded = witness.z.clone();
        pad_to_power_of_two(&mut z_padded, 64);
        let num_vars = z_padded.len().trailing_zeros() as usize;

        // ── 2. Commit to z ───────────────────────────────────────────────────
        let z_poly = MultilinearPoly::new(z_padded.clone());
        let commitment = Brakedown::commit(&z_poly);
        transcript.absorb_commitment(&commitment);

        // ── 3. Compute û_i = M_i · z for each matrix (m=1 case) ─────────────
        let matrix_evals: Vec<Goldilocks> = instance
            .matrices
            .iter()
            .map(|m| matrix_dot(m, &witness.z))
            .collect();

        // Absorb all claimed evaluations into transcript.
        for &e in &matrix_evals {
            transcript.absorb_eval(e);
        }

        // ── 4. Squeeze γ for batched inner sumcheck ──────────────────────────
        let gamma = transcript.squeeze_challenge();

        // ── 5. Build batched weight vector: w[x] = Σ_i γ^i · M_i[0, x] ─────
        let mut w_combined = vec![Goldilocks::ZERO; z_padded.len()];
        let mut gamma_pow = Goldilocks::ONE;
        for matrix in &instance.matrices {
            if let Some(row) = matrix.entries.first() {
                for &(col, coeff) in row {
                    if col < w_combined.len() {
                        w_combined[col] = w_combined[col] + gamma_pow * coeff;
                    }
                }
            }
            gamma_pow = gamma_pow * gamma;
        }

        // ── 6. Batched claim: Σ_i γ^i · û_i ─────────────────────────────────
        // (computed for consistency; the prover's SumcheckProver derives it from
        // w_combined dot z_padded, which equals the batched claim by construction)
        let _batched_claim = {
            let mut c = Goldilocks::ZERO;
            let mut gp = Goldilocks::ONE;
            for &e in &matrix_evals {
                c = c + gp * e;
                gp = gp * gamma;
            }
            c
        };

        // ── 7. Inner sumcheck (6 rounds) ─────────────────────────────────────
        let mut prover = SumcheckProver::new(w_combined, z_padded.clone());
        let mut eval_point = Vec::with_capacity(num_vars);

        let sumcheck_polys = prover.prove_all(|poly| {
            transcript.absorb_sumcheck_poly(eval_point.len(), poly);
            let r = transcript.squeeze_challenge();
            eval_point.push(r);
            r
        });

        // ── 8. Collect PCS evaluation value ──────────────────────────────────
        let (_w_fin, f_fin) = prover.final_claim();
        let eval_value = f_fin;
        transcript.absorb_eval(eval_value);

        // ── 9. PCS open via Brakedown ─────────────────────────────────────────
        // Brakedown uses tensor_reduce (LSB-first convention), while the sumcheck
        // fold_inplace uses MSB-first. Reverse the eval_point to reconcile.
        let pcs_point: Vec<Goldilocks> = eval_point.iter().copied().rev().collect();
        let seed = transcript.squeeze_hash();
        let mut lt = LensTranscript::new(&seed);
        let pcs_opening = Brakedown::open(&z_poly, &pcs_point, &mut lt);

        Proof {
            commitment,
            matrix_evals,
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
    use crate::types::Statement;

    fn make_z(vals: &[(usize, u64)]) -> Vec<Goldilocks> {
        let mut z = vec![Goldilocks::ZERO; Z_LEN];
        z[CONST_IDX] = Goldilocks::ONE;
        for &(idx, v) in vals {
            z[idx] = Goldilocks::new(v);
        }
        z
    }

    fn dummy_statement() -> Statement {
        Statement {
            program_hash: [0u8; 32],
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
            focus_bound: 0,
        }
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
        let result = SpartanVerifier::verify(&instance, &dummy_statement(), &proof, &mut vt);
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
        assert!(SpartanVerifier::verify(&instance, &dummy_statement(), &proof, &mut vt).is_ok());
    }
}
