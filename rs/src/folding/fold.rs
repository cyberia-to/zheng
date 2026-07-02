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

/// Compute M[row r] · z — the dot product for a single row.
fn row_dot(matrix: &crate::types::SparseMatrix, r: usize, z: &[Goldilocks]) -> Goldilocks {
    matrix.entries.get(r).map_or(Goldilocks::ZERO, |row| {
        row.iter().fold(Goldilocks::ZERO, |acc, &(col, c)| {
            acc + c * z.get(col).copied().unwrap_or(Goldilocks::ZERO)
        })
    })
}

/// Compute the HyperNova cross-term vector T (one entry per row).
///
/// For each degree-2 term and each row r:
///   T[r] = c · ((M_i[r]·w_acc)·(M_k[r]·w_new) + (M_i[r]·w_new)·(M_k[r]·w_acc))
///
/// Row-by-row computation ensures only diagonal contributions appear (r=s terms).
fn cross_term(instance: &CCSInstance, w_acc: &[Goldilocks], w_new: &[Goldilocks]) -> Vec<Goldilocks> {
    let m = instance.num_rows;
    let mut t = vec![Goldilocks::ZERO; m];
    for (multiset, &coeff) in instance.multisets.iter().zip(instance.coeffs.iter()) {
        if multiset.len() < 2 {
            continue;
        }
        let i = multiset[0];
        let k = multiset[1];
        for (r, t_r) in t.iter_mut().enumerate() {
            let mi_acc_r = row_dot(&instance.matrices[i], r, w_acc);
            let mk_acc_r = row_dot(&instance.matrices[k], r, w_acc);
            let mi_new_r = row_dot(&instance.matrices[i], r, w_new);
            let mk_new_r = row_dot(&instance.matrices[k], r, w_new);
            *t_r += coeff * (mi_acc_r * mk_new_r + mi_new_r * mk_acc_r);
        }
    }
    t
}

/// Compute the per-row CCS error vector from a witness.
///
/// error_evals[r] = Σ_j c_j · ∏_{i ∈ S_j} (M_i[row r] · z)
/// For a satisfying witness, all entries are 0.
fn error_evals(instance: &CCSInstance, z: &[Goldilocks]) -> Vec<Goldilocks> {
    let m = instance.num_rows;
    let mut e = vec![Goldilocks::ZERO; m];
    for (multiset, &coeff) in instance.multisets.iter().zip(instance.coeffs.iter()) {
        for (r, e_r) in e.iter_mut().enumerate() {
            let product = multiset.iter().fold(Goldilocks::ONE, |p, &idx| {
                p * row_dot(&instance.matrices[idx], r, z)
            });
            *e_r += coeff * product;
        }
    }
    e
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
        acc.error_evals = error_evals(instance, &z_new);
        acc.step_count = 1;
        return Ok(());
    }

    // Verify the instance matches the accumulator exactly.
    if acc.committed_instance != *instance {
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
    for &t_r in &t {
        transcript.absorb(&t_r.as_u64().to_le_bytes());
    }
    let beta = transcript.squeeze_challenge();

    // 3. Fold witnesses: w_folded = w_acc + beta · w_new
    let mut w_folded = w_acc.clone();
    for (wf, &wn) in w_folded.iter_mut().zip(z_new.iter()) {
        *wf += beta * wn;
    }

    // 4. Fold error: evaluate constraint on the folded witness directly.
    let e_folded = error_evals(instance, &w_folded);

    // 5. Update commitment.
    let c_folded = Brakedown::commit_raw(&w_folded);

    acc.folded_witness = CCSWitness { z: w_folded };
    acc.witness_commitment = c_folded;
    acc.error_evals = e_folded;
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
            error_evals: vec![Goldilocks::ZERO; instance.num_rows],
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
        // Error should be [0] for satisfying witness (all rows zero).
        assert!(acc.error_evals.iter().all(|&e| e == Goldilocks::ZERO));
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

    #[test]
    fn fold_step_is_deterministic() {
        let instance = build_step_ccs(5);
        let witness = make_witness(5, 3, 8);

        let mut acc1 = zero_accumulator(&instance);
        let mut t1 = Transcript::new();
        fold_step(&mut acc1, &instance, &witness, &mut t1).unwrap();

        let mut acc2 = zero_accumulator(&instance);
        let mut t2 = Transcript::new();
        fold_step(&mut acc2, &instance, &witness, &mut t2).unwrap();

        assert_eq!(acc1.step_count, acc2.step_count);
        assert!(acc1.error_evals.iter().zip(acc2.error_evals.iter()).all(|(a, b)| a.as_u64() == b.as_u64()));
        assert!(acc1.folded_witness.z.iter().zip(acc2.folded_witness.z.iter()).all(|(a, b)| a.as_u64() == b.as_u64()));
    }
}
