// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Brakedown verifier encoded as a sequence of m=1 CCS instances.
//!
//! Each step uses Z = [a, b, 1] (VZ_LEN = 3) so all steps are structurally
//! uniform and fold into a single verifier accumulator via zheng's fold().
//!
//! Pattern 0 (axis) uses these steps as the sub-proof that a Brakedown
//! opening is sound.
//!
//! Steps for a `num_vars`-variable opening:
//!   (a) 4 commitment-binding eq steps: round_commitments[0][k] == commitment[k]
//!   (b) 1 final-value eq step: final_poly[0] == value
//!
//! Fiat-Shamir transcript steps (num_vars × 20 × 24 Poseidon2 CCS pairs) are
//! produced separately by `ccs::transcript::build_transcript_steps` and folded
//! into the hash accumulator.

use nebu::Goldilocks;

use lens::{Commitment, Opening};

use crate::types::{CCSInstance, CCSWitness, SparseMatrix};

/// Z-vector for verifier steps: [a, b, 1].
const VZ_LEN: usize = 3;

fn neg_one() -> Goldilocks {
    Goldilocks::ZERO - Goldilocks::ONE
}

fn sel(col: usize) -> SparseMatrix {
    let mut m = SparseMatrix::new(1, VZ_LEN);
    m.set(0, col, Goldilocks::ONE);
    m
}

/// Encode `a == b` as a single m=1 CCS step.
///
/// Constraint: z[0] - z[1] = 0.  Z = [a, b, 1].
pub fn eq_step(a: Goldilocks, b: Goldilocks) -> (CCSInstance, CCSWitness) {
    let instance = CCSInstance {
        matrices: vec![sel(0), sel(1)],
        multisets: vec![vec![0], vec![1]],
        coeffs: vec![Goldilocks::ONE, neg_one()],
        num_rows: 1,
        num_cols: VZ_LEN,
    };
    (instance, CCSWitness { z: vec![a, b, Goldilocks::ONE] })
}

/// Encode the Brakedown verifier as a flat sequence of m=1 CCS steps.
///
/// All steps share the same CCS structure (2 matrices, VZ_LEN = 3) so they
/// can be folded together into a single verifier accumulator.
///
/// Returns empty vec if `opening` is not `Opening::Tensor`.
pub fn verifier_steps(
    commitment: &Commitment,
    _point: &[Goldilocks],
    value: Goldilocks,
    opening: &Opening,
) -> Vec<(CCSInstance, CCSWitness)> {
    let Opening::Tensor { round_commitments, final_poly, .. } = opening else {
        return vec![];
    };

    let mut steps: Vec<(CCSInstance, CCSWitness)> = Vec::with_capacity(5);

    // ── (a) Commitment binding ────────────────────────────────────────────────
    // Verify round_commitments[0] == commitment across all 4 × 8-byte limbs.
    if let Some(rc0) = round_commitments.first() {
        let cb = commitment.as_bytes();
        let rb = rc0.as_bytes();
        for k in 0..4 {
            steps.push(eq_step(read_limb(cb, k), read_limb(rb, k)));
        }
    }

    // ── (b) Final value check ─────────────────────────────────────────────────
    // Verify the last round's residual polynomial evaluates to `value`.
    let finals = de_goldilocks(final_poly);
    if let Some(&fp) = finals.first() {
        steps.push(eq_step(fp, value));
    }

    steps
}

pub(crate) fn read_limb(bytes: &[u8], k: usize) -> Goldilocks {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[k * 8..k * 8 + 8]);
    Goldilocks::new(u64::from_le_bytes(buf))
}

fn de_goldilocks(bytes: &[u8]) -> Vec<Goldilocks> {
    bytes.chunks_exact(8).map(|c| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(c);
        Goldilocks::new(u64::from_le_bytes(buf))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::selector::is_satisfied;
    use lens::brakedown::{Brakedown, MultilinearPoly};
    use lens::{Lens, Transcript as LensTranscript};

    fn gold_poly(vals: &[u64]) -> MultilinearPoly<Goldilocks> {
        MultilinearPoly::new(vals.iter().map(|&v| Goldilocks::new(v)).collect())
    }

    fn open_poly(
        poly: &MultilinearPoly<Goldilocks>,
        point: &[Goldilocks],
    ) -> Opening {
        let mut lt = LensTranscript::new(b"verifier-steps-test");
        Brakedown::open(poly, point, &mut lt)
    }

    // ── eq_step unit tests ────────────────────────────────────────────────────

    #[test]
    fn eq_step_satisfied_when_equal() {
        let v = Goldilocks::new(9999);
        let (inst, wit) = eq_step(v, v);
        assert!(is_satisfied(&inst, &wit));
    }

    #[test]
    fn eq_step_unsatisfied_when_different() {
        let (inst, wit) = eq_step(Goldilocks::new(1), Goldilocks::new(2));
        assert!(!is_satisfied(&inst, &wit));
    }

    #[test]
    fn eq_step_trivial_zero_satisfied() {
        let (inst, wit) = eq_step(Goldilocks::ZERO, Goldilocks::ZERO);
        assert!(is_satisfied(&inst, &wit));
    }

    // ── verifier_steps correctness ────────────────────────────────────────────

    #[test]
    fn all_steps_satisfied_on_valid_opening() {
        let poly = gold_poly(&[1, 2, 3, 4]);
        let commitment = Brakedown::commit(&poly);
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let value = poly.evaluate(&point);
        let opening = open_poly(&poly, &point);

        let steps = verifier_steps(&commitment, &point, value, &opening);
        assert!(!steps.is_empty());
        for (i, (inst, wit)) in steps.iter().enumerate() {
            assert!(is_satisfied(inst, wit), "step {i} not satisfied");
        }
    }

    #[test]
    fn step_count_two_vars() {
        // 4 binding + 1 final = 5
        let poly = gold_poly(&[1, 2, 3, 4]);
        let commitment = Brakedown::commit(&poly);
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let value = poly.evaluate(&point);
        let opening = open_poly(&poly, &point);

        let steps = verifier_steps(&commitment, &point, value, &opening);
        assert_eq!(steps.len(), 5);
    }

    #[test]
    fn step_count_four_vars() {
        // 4 binding + 1 final = 5, regardless of num_vars
        let poly = gold_poly(&(0u64..16).collect::<Vec<_>>());
        let commitment = Brakedown::commit(&poly);
        let point = vec![
            Goldilocks::new(2), Goldilocks::new(3),
            Goldilocks::new(5), Goldilocks::new(7),
        ];
        let value = poly.evaluate(&point);
        let opening = open_poly(&poly, &point);

        let steps = verifier_steps(&commitment, &point, value, &opening);
        assert_eq!(steps.len(), 5);
    }

    #[test]
    fn uniform_matrix_structure_for_folding() {
        // All steps must have identical matrix count so they fold together.
        let poly = gold_poly(&[10, 20, 30, 40]);
        let commitment = Brakedown::commit(&poly);
        let point = vec![Goldilocks::ONE, Goldilocks::ZERO];
        let value = poly.evaluate(&point);
        let opening = open_poly(&poly, &point);

        let steps = verifier_steps(&commitment, &point, value, &opening);
        let n_matrices = steps[0].0.matrices.len();
        for (inst, _) in &steps {
            assert_eq!(
                inst.matrices.len(), n_matrices,
                "non-uniform matrix count breaks fold compatibility"
            );
        }
    }

    #[test]
    fn binding_steps_fail_on_wrong_commitment() {
        let poly = gold_poly(&[5, 6, 7, 8]);
        let commitment = Brakedown::commit(&poly);
        // A commitment to a different polynomial serves as the "wrong" one.
        let wrong = Brakedown::commit(&gold_poly(&[0, 0, 0, 0]));
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let value = poly.evaluate(&point);
        let opening = open_poly(&poly, &point);

        let good = verifier_steps(&commitment, &point, value, &opening);
        let bad = verifier_steps(&wrong, &point, value, &opening);

        let good_binding = good[..4].iter().all(|(i, w)| is_satisfied(i, w));
        let bad_binding = bad[..4].iter().all(|(i, w)| is_satisfied(i, w));
        assert!(good_binding, "correct commitment: all binding steps satisfied");
        assert!(!bad_binding, "wrong commitment: at least one binding step fails");
    }

    #[test]
    fn final_step_fails_on_wrong_value() {
        let poly = gold_poly(&[1, 2, 3, 4]);
        let commitment = Brakedown::commit(&poly);
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let value = poly.evaluate(&point);
        let opening = open_poly(&poly, &point);

        let good_steps = verifier_steps(&commitment, &point, value, &opening);
        let bad_steps = verifier_steps(
            &commitment, &point, value + Goldilocks::ONE, &opening
        );

        let last_good = good_steps.last().unwrap();
        let last_bad = bad_steps.last().unwrap();
        assert!(is_satisfied(&last_good.0, &last_good.1));
        assert!(!is_satisfied(&last_bad.0, &last_bad.1));
    }

    #[test]
    fn non_tensor_opening_returns_empty() {
        let commitment = Brakedown::commit(&gold_poly(&[1, 2]));
        let point = vec![Goldilocks::ZERO];
        let opening = Opening::Folding {
            round_commitments: vec![],
            merkle_paths: vec![],
            final_value: vec![],
        };
        let steps = verifier_steps(&commitment, &point, Goldilocks::ZERO, &opening);
        assert!(steps.is_empty());
    }
}
