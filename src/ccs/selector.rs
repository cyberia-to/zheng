// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! CCS constraint evaluation helpers.

use nebu::Goldilocks;

use crate::types::{CCSInstance, CCSWitness};

/// Evaluate the CCS constraint at the given witness.
///
/// Returns one scalar per constraint row. All entries are zero for a satisfying
/// witness. Non-zero entries indicate which row of the constraint is violated.
pub fn constraint_eval(instance: &CCSInstance, witness: &CCSWitness) -> Vec<Goldilocks> {
    if instance.matrices.is_empty() {
        return vec![Goldilocks::ZERO; instance.num_rows];
    }
    let z = &witness.z;
    let mut sum = vec![Goldilocks::ZERO; instance.num_rows];
    for (multiset, &coeff) in instance.multisets.iter().zip(instance.coeffs.iter()) {
        // Hadamard product of selected matrix-vector products over the row index.
        let mut product = vec![Goldilocks::ONE; instance.num_rows];
        for &idx in multiset {
            let mv = instance.matrices[idx].mul_vec(z);
            for (p, m) in product.iter_mut().zip(mv.iter()) {
                *p = *p * *m;
            }
        }
        for (s, p) in sum.iter_mut().zip(product.iter()) {
            *s = *s + coeff * *p;
        }
    }
    sum
}

/// Returns true iff the witness satisfies all rows of the CCS.
pub fn is_satisfied(instance: &CCSInstance, witness: &CCSWitness) -> bool {
    constraint_eval(instance, witness)
        .iter()
        .all(|&v| v == Goldilocks::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::patterns::{build_step_ccs, trivial_ccs};
    use crate::ccs::{reg_t, reg_t1, CONST_IDX, Z_LEN};

    fn make_z(vals: &[(usize, u64)]) -> Vec<Goldilocks> {
        let mut z = vec![Goldilocks::ZERO; Z_LEN];
        z[CONST_IDX] = Goldilocks::ONE;
        for &(idx, v) in vals {
            z[idx] = Goldilocks::new(v);
        }
        z
    }

    #[test]
    fn trivial_ccs_always_zero() {
        let ccs = trivial_ccs();
        let w = CCSWitness { z: vec![Goldilocks::ZERO; Z_LEN] };
        let v = constraint_eval(&ccs, &w);
        assert!(v.iter().all(|&x| x == Goldilocks::ZERO));
    }

    #[test]
    fn add_constraint_evaluates_to_zero() {
        let ccs = build_step_ccs(5);
        let z = make_z(&[(reg_t(3), 5), (reg_t(4), 3), (reg_t1(5), 8)]);
        let v = constraint_eval(&ccs, &CCSWitness { z });
        assert_eq!(v, vec![Goldilocks::ZERO]);
    }

    #[test]
    fn add_constraint_nonzero_on_wrong_witness() {
        let ccs = build_step_ccs(5);
        let z = make_z(&[(reg_t(3), 5), (reg_t(4), 3), (reg_t1(5), 9)]);
        let v = constraint_eval(&ccs, &CCSWitness { z });
        assert_ne!(v, vec![Goldilocks::ZERO]);
    }
}
