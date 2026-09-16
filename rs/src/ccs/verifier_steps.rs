// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Legacy Tensor-format equality rows, not a polynomial-opening verifier.
//!
//! These rows compare commitment limbs and a residual value only. They do not
//! establish proximity, Merkle authentication, or polynomial evaluation.
//! Current Lens `TensorMerkle` openings are unsupported here, and the public
//! trace commit API rejects recursive openings with `UnsupportedRecursiveOpening`.
//! `eq_instance` and `eq_step` remain general linear binding primitives.

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

/// The binding instance: z[0] − z[1] = 0 over Z = [a, b, 1]. Degree 1, so
/// satisfied steps fold to exactly zero error (the verifier's zero-error
/// rule). Every eq step shares it; the verifier derives it from the
/// binding group's position, never from the wire.
pub fn eq_instance() -> CCSInstance {
    CCSInstance {
        matrices: vec![sel(0), sel(1)],
        multisets: vec![vec![0], vec![1]],
        coeffs: vec![Goldilocks::ONE, neg_one()],
        num_rows: 1,
        num_cols: VZ_LEN,
    }
}

/// Encode `a == b` as a single m=1 CCS step.
///
/// Constraint: z[0] - z[1] = 0.  Z = [a, b, 1].
pub fn eq_step(a: Goldilocks, b: Goldilocks) -> (CCSInstance, CCSWitness) {
    (eq_instance(), CCSWitness { z: vec![a, b, Goldilocks::ONE] })
}

/// Extract legacy Tensor equality rows; this is not opening verification.
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

    // The useful security property of these primitives is equality, not
    // acceptance of a current Lens opening by five unconstrained comparisons.
    #[test]
    fn commitment_limb_bindings_reject_each_changed_limb() {
        let commitment = Brakedown::commit(&gold_poly(&[5, 6, 7, 8]));
        for k in 0..4 {
            let value = read_limb(commitment.as_bytes(), k);
            let (instance, honest) = eq_step(value, value);
            assert!(is_satisfied(&instance, &honest));
            let (_, forged) = eq_step(value, value + Goldilocks::ONE);
            assert!(!is_satisfied(&instance, &forged));
        }
    }

    #[test]
    fn equality_rows_have_one_uniform_folding_shape() {
        let steps: Vec<_> = [0, 1, 42, 9999].into_iter()
            .map(|v| eq_step(Goldilocks::new(v), Goldilocks::new(v))).collect();
        for (instance, witness) in &steps {
            assert_eq!((instance.num_rows, instance.num_cols), (1, 3));
            assert_eq!(instance.matrices.len(), 2);
            assert!(is_satisfied(instance, witness));
        }
        // Exercise the real folding entry point, not just matrix counts.
        let witnesses: Vec<_> = steps.into_iter().map(|(_, w)| w).collect();
        let accumulator = crate::fold_all(&eq_instance(), &witnesses).unwrap();
        assert_eq!(accumulator.step_count, 4);
    }

    #[test]
    fn current_authenticated_opening_is_not_a_legacy_equality_proof() {
        for vals in [vec![1, 2, 3, 4], (0..16).collect()] {
            let poly = gold_poly(&vals);
            let commitment = Brakedown::commit(&poly);
            let point = vec![Goldilocks::ZERO; vals.len().ilog2() as usize];
            let opening = open_poly(&poly, &point);
            assert!(matches!(opening, Opening::TensorMerkle { .. }));
            assert!(verifier_steps(&commitment, &point, poly.evaluate(&point), &opening).is_empty());
        }
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
