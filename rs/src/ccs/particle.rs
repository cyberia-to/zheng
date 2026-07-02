// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Poseidon2 round-transition CCS constraints for nox pattern-15 (hash).
//!
//! Each hash block emits 25 trace rows (24 round rows + 1 squeeze row).
//! `build_hash_steps_from_trace` produces 24 (CCSInstance, CCSWitness) pairs
//! per hash block — one per consecutive intra-block row pair.
//!
//! Extended witness: Z_LEN_HASH = 50 elements:
//!   z[0..16]  — r_t register file
//!   z[16..32] — r_{t+1} register file
//!   z[32]     — constant 1
//!   z[33..41] — state_k[8..16]  (capacity, prover-supplied)
//!   z[41..49] — state_{k+1}[8..16] (capacity, prover-supplied)
//!   z[49]     — y = inv(state_k[0] + rc)  (partial-round S-box inverse)
//!
//! For a partial-round pair (row_t.r[14] = k ∈ 3..19), the CCS encodes 16
//! simultaneous constraints across 16 matrix rows:
//!   Row 0:  y · (state_k[0] + rc) − 1 = 0            (S-box inversion)
//!   Row 1:  state_{k+1}[0] − DIAG[0]·y − sum = 0     (matmul i=0)
//!   Row r:  state_{k+1}[r] − DIAG[r]·state_k[r] − sum = 0  (matmul i=r, r=2..15)
//! where sum = state_{k+1}[1] − DIAG[1]·state_k[1].
//!
//! NOTE: fold.rs and spartan/prover.rs are currently m=1 implementations that
//! use only row 0 of each matrix. Extending to multi-row enforcement requires
//! upgrading the fold and decider. The constraint math is verified via
//! CCSInstance::is_satisfied_by in tests.

use nebu::Goldilocks;
use nox::TraceRow;

use hemera::constants::ROUND_CONSTANTS;
use hemera::field::{Goldilocks as HGold, MATRIX_DIAG_16};

use crate::types::{CCSInstance, CCSWitness, CommitError, SparseMatrix};

/// Length of the extended hash witness (standard 33 + 8 cap_k + 8 cap_k1 + 1 y).
pub const Z_LEN_HASH: usize = 50;

pub(crate) const IDX_CONST: usize = 32;
pub(crate) const IDX_CAP_K: usize = 33;
pub(crate) const IDX_CAP_K1: usize = 41;
pub(crate) const IDX_Y: usize = 49;

/// Prover-supplied auxiliary data for one Poseidon2 hash block.
///
/// `rate` is the 8-element rate input: the 4-element structural digest padded
/// to 8 with zeros. Passed to `StepSponge::absorb` to replay the permutation
/// and recover the capacity elements not stored in the trace.
pub struct HashAux {
    pub rate: [Goldilocks; 8],
}

/// z-index of state_k[i] in the extended witness.
pub(crate) fn sk(i: usize) -> usize {
    match i {
        0 => 4,  1 => 5,  2 => 6,  3 => 7,
        4 => 10, 5 => 11, 6 => 12, 7 => 13,
        _ => IDX_CAP_K + (i - 8),
    }
}

/// z-index of state_{k+1}[i] in the extended witness.
pub(crate) fn sk1(i: usize) -> usize {
    match i {
        0 => 20, 1 => 21, 2 => 22, 3 => 23,
        4 => 26, 5 => 27, 6 => 28, 7 => 29,
        _ => IDX_CAP_K1 + (i - 8),
    }
}

fn neg(x: Goldilocks) -> Goldilocks {
    Goldilocks::ZERO - x
}

fn hg(h: HGold) -> Goldilocks {
    Goldilocks::new(h.as_canonical_u64())
}

fn field_inv(x: Goldilocks) -> Goldilocks {
    hg(HGold::new(x.canonicalize().as_u64()).inv())
}

/// Trivial hash CCS (no constraints) for full-round pairs and the squeeze pair.
///
/// Uses num_rows=16 and Z_LEN_HASH columns to match `partial_round_ccs`
/// so all hash pairs can be folded into the same hash accumulator.
pub fn trivial_hash_ccs() -> CCSInstance {
    CCSInstance {
        matrices: vec![],
        multisets: vec![],
        coeffs: vec![],
        num_rows: 16,
        num_cols: Z_LEN_HASH,
    }
}

/// CCS instance for a partial-round transition.
///
/// Valid for pair (row_t, row_{t+1}) where row_t.r[14] = k ∈ 3..19.
/// Applies `permute_one_round(state, round=k+1)` where round k+1 ∈ 4..20
/// (hemera partial rounds, partial round index pr = k−3 ∈ 0..16).
///
/// Hemera constants used: ROUND_CONSTANTS[128+pr] (rc), MATRIX_DIAG_16 (DIAG).
pub fn partial_round_ccs(k: usize) -> CCSInstance {
    debug_assert!((3..19).contains(&k), "k={k} not in partial-round range 3..19");
    let pr = k - 3;
    let rc = hg(ROUND_CONSTANTS[128 + pr]);

    let mut diag = [Goldilocks::ZERO; 16];
    for i in 0..16 {
        diag[i] = hg(MATRIX_DIAG_16[i]);
    }

    // M_A: row 0 selects z[IDX_Y] = y
    let mut m_a = SparseMatrix::new(16, Z_LEN_HASH);
    m_a.set(0, IDX_Y, Goldilocks::ONE);

    // M_B: row 0 computes state_k[0] + rc  →  z[sk(0)]·1 + z[IDX_CONST]·rc
    let mut m_b = SparseMatrix::new(16, Z_LEN_HASH);
    m_b.set(0, sk(0), Goldilocks::ONE);
    m_b.set(0, IDX_CONST, rc);

    // M_C: row 0 selects z[IDX_CONST] = 1
    let mut m_c = SparseMatrix::new(16, Z_LEN_HASH);
    m_c.set(0, IDX_CONST, Goldilocks::ONE);

    // M_D: rows 1..15 for linear matmul constraints.
    //
    // All constraints use sum = state_{k+1}[1] − DIAG[1]·state_k[1] as reference.
    //
    // Row 1 (i=0): state_{k+1}[0] − DIAG[0]·y − state_{k+1}[1] + DIAG[1]·state_k[1] = 0
    // Row r (i=r): state_{k+1}[r] − DIAG[r]·state_k[r] − state_{k+1}[1] + DIAG[1]·state_k[1] = 0
    let mut m_d = SparseMatrix::new(16, Z_LEN_HASH);

    m_d.set(1, sk1(0), Goldilocks::ONE);
    m_d.set(1, IDX_Y,  neg(diag[0]));
    m_d.set(1, sk1(1), neg(Goldilocks::ONE));
    m_d.set(1, sk(1),  diag[1]);

    for r in 2..16usize {
        m_d.set(r, sk1(r), Goldilocks::ONE);
        m_d.set(r, sk(r),  neg(diag[r]));
        m_d.set(r, sk1(1), neg(Goldilocks::ONE));
        m_d.set(r, sk(1),  diag[1]);
    }

    CCSInstance {
        matrices: vec![m_a, m_b, m_c, m_d],
        multisets: vec![
            vec![0, 1],  // M_A · M_B: y · (state_k[0] + rc)
            vec![2],     // M_C: constant 1
            vec![3],     // M_D: linear matmul constraints
        ],
        coeffs: vec![
            Goldilocks::ONE,
            neg(Goldilocks::ONE),
            Goldilocks::ONE,
        ],
        num_rows: 16,
        num_cols: Z_LEN_HASH,
    }
}

/// Build the extended hash witness for a consecutive pair of hash trace rows.
///
/// `cap_k`  = state_k[8..16]  (capacity elements at row_t, prover-supplied).
/// `cap_k1` = state_{k+1}[8..16] (capacity elements at row_{t+1}).
/// `y`      = inv(state_k[0] + rc); pass Goldilocks::ZERO for non-partial pairs.
pub fn hash_witness(
    row_t: &TraceRow,
    row_t1: &TraceRow,
    cap_k: &[Goldilocks; 8],
    cap_k1: &[Goldilocks; 8],
    y: Goldilocks,
) -> CCSWitness {
    let mut z = Vec::with_capacity(Z_LEN_HASH);
    for &v in row_t.r().iter() {
        z.push(Goldilocks::new(v).canonicalize());
    }
    for &v in row_t1.r().iter() {
        z.push(Goldilocks::new(v).canonicalize());
    }
    z.push(Goldilocks::ONE);
    for &c in cap_k.iter()  { z.push(c); }
    for &c in cap_k1.iter() { z.push(c); }
    z.push(y);
    CCSWitness { z }
}

/// Build (CCSInstance, CCSWitness) pairs for all hash blocks in the trace.
///
/// Scans for consecutive tag=15 rows. For each block, replays the Poseidon2
/// permutation via StepSponge to recover the 8 capacity elements per round
/// (state[8..16]) that the nox trace omits.
///
/// `aux` must have one entry per hash block in trace order.
/// Produces 24 pairs per hash block (one per consecutive intra-block pair).
///
/// Returns `Err(CommitError::TraceOverflow)` if `aux` has fewer entries than
/// hash blocks in the trace.
pub fn build_hash_steps_from_trace(
    trace: &[TraceRow],
    aux: &[HashAux],
) -> Result<Vec<(CCSInstance, CCSWitness)>, CommitError> {
    let mut steps = Vec::new();
    let mut aux_idx = 0;
    let mut i = 0;

    while i < trace.len() {
        if trace[i].r()[0] != 15 {
            i += 1;
            continue;
        }
        let block_start = i;
        while i < trace.len() && trace[i].r()[0] == 15 {
            i += 1;
        }
        let block = &trace[block_start..i];
        if block.len() < 2 {
            continue;
        }

        let ha = aux.get(aux_idx).ok_or(CommitError::TraceOverflow)?;
        aux_idx += 1;

        // Convert rate to hemera's Goldilocks type for StepSponge.
        let mut rate_h = [HGold::ZERO; 8];
        for (j, r) in ha.rate.iter().enumerate() {
            rate_h[j] = HGold::new(r.canonicalize().as_u64());
        }

        // Replay the full permutation to get all 16-element states at each round.
        let mut full_states: Vec<[Goldilocks; 16]> = Vec::with_capacity(24);
        for state_h in hemera::StepSponge::absorb(&rate_h) {
            let mut s = [Goldilocks::ZERO; 16];
            for j in 0..16 {
                s[j] = Goldilocks::new(state_h[j].as_canonical_u64());
            }
            full_states.push(s);
        }

        for pair in block.windows(2) {
            let row_t  = &pair[0];
            let row_t1 = &pair[1];
            let k = row_t.r()[14] as usize;

            let state_k  = &full_states[k];
            let state_k1 = full_states.get(k + 1).unwrap_or(&full_states[23]);

            let mut cap_k  = [Goldilocks::ZERO; 8];
            let mut cap_k1 = [Goldilocks::ZERO; 8];
            cap_k.copy_from_slice(&state_k[8..16]);
            cap_k1.copy_from_slice(&state_k1[8..16]);

            let (instance, y) = if (3..19).contains(&k) {
                let pr = k - 3;
                let rc = hg(ROUND_CONSTANTS[128 + pr]);
                let y = field_inv(state_k[0] + rc);
                (partial_round_ccs(k), y)
            } else {
                (trivial_hash_ccs(), Goldilocks::ZERO)
            };

            let witness = hash_witness(row_t, row_t1, &cap_k, &cap_k1, y);
            steps.push((instance, witness));
        }
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hemera::field::Goldilocks as HGold;

    fn zero_rate_states() -> Vec<[HGold; 16]> {
        hemera::StepSponge::absorb(&[HGold::ZERO; 8]).collect()
    }

    /// Build a test witness directly from round states, bypassing TraceRow.
    ///
    /// TraceRow.r is private to nox; for unit tests we populate z directly
    /// using the same layout as hash_witness (which reads r() values).
    fn make_witness_from_states(
        state_k: &[HGold; 16],
        state_k1: &[HGold; 16],
        cap_k: &[Goldilocks; 8],
        cap_k1: &[Goldilocks; 8],
        y: Goldilocks,
    ) -> CCSWitness {
        let mut z = vec![Goldilocks::ZERO; Z_LEN_HASH];
        // r_t rate elements (z[0..16]).
        z[sk(0)] = hg(state_k[0]);
        z[sk(1)] = hg(state_k[1]);
        z[sk(2)] = hg(state_k[2]);
        z[sk(3)] = hg(state_k[3]);
        z[sk(4)] = hg(state_k[4]);
        z[sk(5)] = hg(state_k[5]);
        z[sk(6)] = hg(state_k[6]);
        z[sk(7)] = hg(state_k[7]);
        // r_{t+1} rate elements (z[16..32]).
        z[sk1(0)] = hg(state_k1[0]);
        z[sk1(1)] = hg(state_k1[1]);
        z[sk1(2)] = hg(state_k1[2]);
        z[sk1(3)] = hg(state_k1[3]);
        z[sk1(4)] = hg(state_k1[4]);
        z[sk1(5)] = hg(state_k1[5]);
        z[sk1(6)] = hg(state_k1[6]);
        z[sk1(7)] = hg(state_k1[7]);
        // Constant.
        z[IDX_CONST] = Goldilocks::ONE;
        // Capacity elements.
        for j in 0..8 { z[IDX_CAP_K + j]  = cap_k[j]; }
        for j in 0..8 { z[IDX_CAP_K1 + j] = cap_k1[j]; }
        // S-box inverse.
        z[IDX_Y] = y;
        CCSWitness { z }
    }

    #[test]
    fn partial_round_ccs_satisfied_by_all_real_partial_rounds() {
        let states = zero_rate_states();
        for k in 3..19usize {
            let state_k  = states[k];
            let state_k1 = states[k + 1];
            let pr = k - 3;
            let rc = hemera::constants::ROUND_CONSTANTS[128 + pr];

            let mut cap_k  = [Goldilocks::ZERO; 8];
            let mut cap_k1 = [Goldilocks::ZERO; 8];
            for j in 0..8 {
                cap_k[j]  = hg(state_k[8 + j]);
                cap_k1[j] = hg(state_k1[8 + j]);
            }

            let y = field_inv(hg(state_k[0]) + hg(rc));
            let witness = make_witness_from_states(&state_k, &state_k1, &cap_k, &cap_k1, y);
            let ccs = partial_round_ccs(k);

            assert!(ccs.is_satisfied_by(&witness),
                "partial_round_ccs not satisfied at k={k}");
        }
    }

    #[test]
    fn partial_round_ccs_rejects_wrong_next_state() {
        let states = zero_rate_states();
        let k = 5usize;
        let state_k   = states[k];
        let state_bad = states[k + 3];  // wrong: skip 3 rounds

        let pr = k - 3;
        let rc = hemera::constants::ROUND_CONSTANTS[128 + pr];

        let mut cap_k   = [Goldilocks::ZERO; 8];
        let mut cap_bad = [Goldilocks::ZERO; 8];
        for j in 0..8 {
            cap_k[j]   = hg(state_k[8 + j]);
            cap_bad[j] = hg(state_bad[8 + j]);
        }

        let y = field_inv(hg(state_k[0]) + hg(rc));
        let witness = make_witness_from_states(&state_k, &state_bad, &cap_k, &cap_bad, y);
        let ccs = partial_round_ccs(k);

        assert!(!ccs.is_satisfied_by(&witness),
            "partial_round_ccs should reject wrong next state at k={k}");
    }

    #[test]
    fn build_hash_steps_empty_trace() {
        let steps = build_hash_steps_from_trace(&[], &[]).unwrap();
        assert!(steps.is_empty());
    }

    #[test]
    fn partial_round_ccs_spartan_prove_verify() {
        use crate::spartan::prover::SpartanProver;
        use crate::spartan::verifier::SpartanVerifier;
        use crate::transcript::Transcript;

        let states = zero_rate_states();
        let k = 7usize;
        let state_k  = states[k];
        let state_k1 = states[k + 1];
        let pr = k - 3;
        let rc = hemera::constants::ROUND_CONSTANTS[128 + pr];

        let mut cap_k  = [Goldilocks::ZERO; 8];
        let mut cap_k1 = [Goldilocks::ZERO; 8];
        for j in 0..8 {
            cap_k[j]  = hg(state_k[8 + j]);
            cap_k1[j] = hg(state_k1[8 + j]);
        }

        let y = field_inv(hg(state_k[0]) + hg(rc));
        let witness = make_witness_from_states(&state_k, &state_k1, &cap_k, &cap_k1, y);
        let ccs = partial_round_ccs(k);

        assert!(ccs.is_satisfied_by(&witness), "precondition: witness must satisfy CCS");

        let mut pt = Transcript::new();
        let proof = SpartanProver::prove(&ccs, &witness, &mut pt);

        let mut vt = Transcript::new();
        assert!(SpartanVerifier::verify(&ccs, &proof, &[Goldilocks::ZERO; 16], &mut vt).is_ok(),
            "Spartan verify failed for partial round k={k}");
    }
}
