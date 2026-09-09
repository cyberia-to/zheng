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
                *p *= *m;
            }
        }
        for (s, p) in sum.iter_mut().zip(product.iter()) {
            *s += coeff * *p;
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
    use crate::ccs::reg_t;
    use crate::ccs::universal::{test_witness, universal_ccs, NUM_ROWS};

    #[test]
    fn empty_instance_evaluates_to_zero_rows() {
        let ccs = CCSInstance { num_rows: 3, ..CCSInstance::default() };
        let w = CCSWitness { z: vec![Goldilocks::ZERO; 4] };
        assert_eq!(constraint_eval(&ccs, &w), vec![Goldilocks::ZERO; 3]);
    }

    #[test]
    fn add_constraint_evaluates_to_zero() {
        let w = test_witness(&[(reg_t(0), 5), (reg_t(4), 5), (reg_t(5), 3), (reg_t(6), 8)]);
        let v = constraint_eval(universal_ccs(), &w);
        assert_eq!(v, vec![Goldilocks::ZERO; NUM_ROWS]);
    }

    #[test]
    fn add_constraint_nonzero_on_wrong_witness() {
        let w = test_witness(&[(reg_t(0), 5), (reg_t(4), 5), (reg_t(5), 3), (reg_t(6), 9)]);
        let v = constraint_eval(universal_ccs(), &w);
        assert_ne!(v, vec![Goldilocks::ZERO; NUM_ROWS]);
        assert!(!is_satisfied(universal_ccs(), &w));
    }
}
