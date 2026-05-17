// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! HyperNova fold: cross-term computation, beta challenge, witness folding.
//!
//! For a sequence of CCS instances all sharing the same structure,
//! fold() accumulates them into a single accumulator. The decider then
//! proves the accumulated instance is satisfiable.

use nebu::Goldilocks;

use lens::brakedown::Brakedown;

use crate::multilinear::pad_to_power_of_two;
use crate::transcript::Transcript;
use crate::types::{Accumulator, CCSInstance, CCSWitness, FoldError};

/// Compute M_idx · z by summing dot products over all matrix rows.
fn eval_matrix(instance: &CCSInstance, m_idx: usize, z: &[Goldilocks]) -> Goldilocks {
    instance.matrices[m_idx].entries.iter().fold(Goldilocks::ZERO, |sum, row| {
        sum + row.iter().fold(Goldilocks::ZERO, |acc, &(col, c)| {
            acc + c * z.get(col).copied().unwrap_or(Goldilocks::ZERO)
        })
    })
}

/// Compute the HyperNova cross-term T.
///
/// For each degree-2 CCS term (S_j with |S_j| = 2), T accumulates the
/// bilinear cross contribution between acc and new witness, summed over all
/// matrix rows:
///   T_j = c_j · ((M_i · w_acc) · (M_k · w_new) + (M_i · w_new) · (M_k · w_acc))
///
/// Degree-1 terms have no cross term.
fn cross_term(instance: &CCSInstance, w_acc: &[Goldilocks], w_new: &[Goldilocks]) -> Goldilocks {
    instance
        .multisets
        .iter()
        .zip(instance.coeffs.iter())
        .fold(Goldilocks::ZERO, |t, (multiset, &coeff)| {
            if multiset.len() < 2 {
                return t;
            }
            let i = multiset[0];
            let k = multiset[1];
            let mi_acc = eval_matrix(instance, i, w_acc);
            let mk_acc = eval_matrix(instance, k, w_acc);
            let mi_new = eval_matrix(instance, i, w_new);
            let mk_new = eval_matrix(instance, k, w_new);
            let cross = mi_acc * mk_new + mi_new * mk_acc;
            t + coeff * cross
        })
}

/// Compute the CCS error term for a given witness, summing over all matrix rows.
///
/// e = Σ_j c_j · Π_{i ∈ S_j} (Σ_row M_i[row] · z)
/// For a satisfying witness, e = 0.
fn error_term(instance: &CCSInstance, z: &[Goldilocks]) -> Goldilocks {
    instance
        .multisets
        .iter()
        .zip(instance.coeffs.iter())
        .fold(Goldilocks::ZERO, |acc, (multiset, &coeff)| {
            let product = multiset.iter().fold(Goldilocks::ONE, |p, &idx| {
                p * eval_matrix(instance, idx, z)
            });
            acc + coeff * product
        })
}

/// Fold one CCS step into the accumulator.
///
/// On the first fold (step_count == 0): adopt the instance and witness directly.
/// On subsequent folds: apply the HyperNova fold protocol.
pub fn fold_step(
    acc: &mut Accumulator,
    instance: &CCSInstance,
    witness: &CCSWitness,
    transcript: &mut Transcript,
) -> Result<(), FoldError> {
    // Pad new witness to 64 elements (2^6) for PCS compatibility.
    let mut z_new = witness.z.clone();
    pad_to_power_of_two(&mut z_new, 64);

    if acc.step_count == 0 {
        // First fold: adopt the CCS structure and witness directly.
        acc.committed_instance = instance.clone();
        acc.folded_witness = CCSWitness { z: z_new.clone() };
        acc.witness_commitment = Brakedown::commit_raw(&z_new);
        acc.error_term = error_term(instance, &z_new);
        acc.step_count = 1;
        return Ok(());
    }

    // Verify the instance structure matches the accumulator.
    if acc.committed_instance.matrices.len() != instance.matrices.len() {
        return Err(FoldError::InstanceMismatch);
    }

    let w_acc = &acc.folded_witness.z;
    if w_acc.len() != z_new.len() {
        return Err(FoldError::WitnessMismatch);
    }

    // ── HyperNova fold ───────────────────────────────────────────────────────

    // 1. Compute cross-term T for Fiat-Shamir binding.
    let t = cross_term(instance, w_acc, &z_new);

    // 2. Derive beta from transcript.
    transcript.absorb(acc.witness_commitment.as_bytes());
    let new_commitment = Brakedown::commit_raw(&z_new);
    transcript.absorb(new_commitment.as_bytes());
    transcript.absorb(&t.as_u64().to_le_bytes());
    let beta = transcript.squeeze_challenge();

    // 3. Fold witnesses: w_folded = w_acc + beta · w_new
    let mut w_folded = w_acc.clone();
    for (wf, &wn) in w_folded.iter_mut().zip(z_new.iter()) {
        *wf = *wf + beta * wn;
    }

    // 4. Fold error: evaluate constraint on the folded witness directly.
    //    For degree-1 constraints: error_term(w_acc + β·w_new) = e_acc + β·e_new.
    //    For degree-2: the bilinear cross-term makes the formula non-trivial;
    //    computing directly is always correct.
    let e_folded = error_term(instance, &w_folded);

    // 5. Update commitment.
    let c_folded = Brakedown::commit_raw(&w_folded);

    acc.folded_witness = CCSWitness { z: w_folded };
    acc.witness_commitment = c_folded;
    acc.error_term = e_folded;
    acc.step_count += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::patterns::build_step_ccs;
    use crate::ccs::{reg_t, reg_t1, CONST_IDX, Z_LEN};

    fn zero_accumulator(instance: &CCSInstance) -> Accumulator {
        let z = vec![Goldilocks::ZERO; 64];
        Accumulator {
            committed_instance: instance.clone(),
            folded_witness: CCSWitness { z: z.clone() },
            witness_commitment: Brakedown::commit_raw(&z),
            error_term: Goldilocks::ZERO,
            step_count: 0,
        }
    }

    fn make_witness(r3: u64, r4: u64, r5_t1: u64) -> CCSWitness {
        let mut z = vec![Goldilocks::ZERO; Z_LEN];
        z[CONST_IDX] = Goldilocks::ONE;
        z[reg_t(3)] = Goldilocks::new(r3);
        z[reg_t(4)] = Goldilocks::new(r4);
        z[reg_t1(5)] = Goldilocks::new(r5_t1);
        CCSWitness { z }
    }

    #[test]
    fn first_fold_adopts_witness() {
        let instance = build_step_ccs(5);
        let witness = make_witness(5, 3, 8);
        let mut acc = zero_accumulator(&instance);
        let mut transcript = Transcript::new();
        fold_step(&mut acc, &instance, &witness, &mut transcript).unwrap();
        assert_eq!(acc.step_count, 1);
        // Error should be 0 for satisfying witness.
        assert_eq!(acc.error_term, Goldilocks::ZERO);
    }

    #[test]
    fn two_folds_increase_step_count() {
        let instance = build_step_ccs(5);
        let w1 = make_witness(5, 3, 8);
        let w2 = make_witness(2, 4, 6);
        let mut acc = zero_accumulator(&instance);
        let mut t = Transcript::new();
        fold_step(&mut acc, &instance, &w1, &mut t).unwrap();
        fold_step(&mut acc, &instance, &w2, &mut t).unwrap();
        assert_eq!(acc.step_count, 2);
    }
}
