// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Per-pattern CCS constraint encodings for the 17 nox reduction patterns.
//!
//! Each function returns a CCSInstance with m=1 (single constraint row).
//! z = [r0_t..r15_t, r0_{t+1}..r15_{t+1}, 1]  (indices 0-32).

use nebu::Goldilocks;

use super::{reg_t, reg_t1, select_matrix, CONST_IDX, Z_LEN};
use crate::types::{CCSInstance, SparseMatrix};

fn neg_one() -> Goldilocks {
    Goldilocks::ZERO - Goldilocks::ONE
}

/// Build the CCS instance for the given pattern tag.
///
/// Returns a 1-row CCS with the appropriate constraint matrices for the
/// transition rule of that pattern.
pub fn build_step_ccs(pattern_tag: u8) -> CCSInstance {
    match pattern_tag {
        1  => pattern_quote(),
        2  => pattern_compose(),
        3  => pattern_cons(),
        4  => pattern_branch(),
        5  => pattern_add(),
        6  => pattern_sub(),
        7  => pattern_mul(),
        8  => pattern_inv(),
        9  => pattern_eq(),
        0  => pattern_axis(),
        10 => pattern_lt(),
        11 => pattern_xor(),
        12 => pattern_and(),
        13 => pattern_not(),
        14 => pattern_shl(),
        15 => pattern_hash(),
        16 => pattern_call(),
        17 => pattern_look_inline(),
        _  => trivial_ccs(),
    }
}

/// Trivial CCS with no constraints — always satisfied.
///
/// Used for unimplemented patterns (10-17) and for the empty accumulator.
pub fn trivial_ccs() -> CCSInstance {
    CCSInstance {
        matrices: vec![],
        multisets: vec![],
        coeffs: vec![],
        num_rows: 1,
        num_cols: Z_LEN,
    }
}

// ── helper ───────────────────────────────────────────────────────────────────

/// Build a CCSInstance from parallel (matrix_indices_per_term, coefficients).
///
/// terms: Vec<(Vec<usize_into_matrices>, Goldilocks)>
fn build_ccs(matrices: Vec<SparseMatrix>, terms: Vec<(Vec<usize>, Goldilocks)>) -> CCSInstance {
    let (multisets, coeffs): (Vec<_>, Vec<_>) = terms.into_iter().unzip();
    let num_cols = matrices.first().map_or(Z_LEN, |m| m.cols);
    CCSInstance {
        matrices,
        multisets,
        coeffs,
        num_rows: 1,
        num_cols,
    }
}

// ── pattern 1: quote ─────────────────────────────────────────────────────────
// r5_{t+1} = literal stored in r4_t (the formula body)
// C_1: r5_{t+1} - r4_t = 0
fn pattern_quote() -> CCSInstance {
    let m_r5_t1 = select_matrix(reg_t1(5));  // selects z[21]
    let m_r4_t  = select_matrix(reg_t(4));   // selects z[4]
    build_ccs(
        vec![m_r5_t1, m_r4_t],
        vec![
            (vec![0], Goldilocks::ONE),  // +r5_{t+1}
            (vec![1], neg_one()),        // -r4_t
        ],
    )
}

// ── pattern 2: compose ───────────────────────────────────────────────────────
// result of compose is r5_{t+1} = r3_t (output of sub-formula on subject).
// C_2: r5_{t+1} - r3_t = 0
fn pattern_compose() -> CCSInstance {
    let m_r5_t1 = select_matrix(reg_t1(5));
    let m_r3_t  = select_matrix(reg_t(3));
    build_ccs(
        vec![m_r5_t1, m_r3_t],
        vec![
            (vec![0], Goldilocks::ONE),
            (vec![1], neg_one()),
        ],
    )
}

// ── pattern 3: cons ──────────────────────────────────────────────────────────
// result is a cons pair; r5_{t+1} = r3_t (head already computed).
// C_3: r5_{t+1} - r3_t = 0
fn pattern_cons() -> CCSInstance {
    let m_r5_t1 = select_matrix(reg_t1(5));
    let m_r3_t  = select_matrix(reg_t(3));
    build_ccs(
        vec![m_r5_t1, m_r3_t],
        vec![
            (vec![0], Goldilocks::ONE),
            (vec![1], neg_one()),
        ],
    )
}

// ── pattern 4: branch ────────────────────────────────────────────────────────
// C_4: r5_{t+1} - r6_t + r8_t*(r6_t - r4_t) = 0
// decomposed: r5_{t+1} - r6_t + r8_t*r6_t - r8_t*r4_t = 0
// sel = r8_t, yes = r4_t, no = r6_t
fn pattern_branch() -> CCSInstance {
    // 6 matrices needed: r5_{t+1}, r6_t, r8_t×r6_t (two copies), r8_t×r4_t (two copies)
    let m_r5_t1    = select_matrix(reg_t1(5));
    let m_r6_t     = select_matrix(reg_t(6));
    let m_r8_t_a   = select_matrix(reg_t(8));
    let m_r6_t_dup = select_matrix(reg_t(6));
    let m_r8_t_b   = select_matrix(reg_t(8));
    let m_r4_t     = select_matrix(reg_t(4));

    CCSInstance {
        matrices: vec![m_r5_t1, m_r6_t, m_r8_t_a, m_r6_t_dup, m_r8_t_b, m_r4_t],
        multisets: vec![
            vec![0],    // +r5_{t+1}
            vec![1],    // -r6_t
            vec![2, 3], // +r8_t * r6_t  (matrices[2] × matrices[3])
            vec![4, 5], // -r8_t * r4_t  (matrices[4] × matrices[5])
        ],
        coeffs: vec![
            Goldilocks::ONE,
            neg_one(),
            Goldilocks::ONE,
            neg_one(),
        ],
        num_rows: 1,
        num_cols: Z_LEN,
    }
}

// ── pattern 5: add ───────────────────────────────────────────────────────────
// C_5: r5_{t+1} - r3_t - r4_t = 0
fn pattern_add() -> CCSInstance {
    let m_r5_t1 = select_matrix(reg_t1(5)); // z[21]
    let m_r3_t  = select_matrix(reg_t(3));  // z[3]
    let m_r4_t  = select_matrix(reg_t(4));  // z[4]
    build_ccs(
        vec![m_r5_t1, m_r3_t, m_r4_t],
        vec![
            (vec![0], Goldilocks::ONE), // +r5_{t+1}
            (vec![1], neg_one()),       // -r3_t
            (vec![2], neg_one()),       // -r4_t
        ],
    )
}

// ── pattern 6: sub ───────────────────────────────────────────────────────────
// C_6: r5_{t+1} - r3_t + r4_t = 0  (r5 = r3 - r4)
fn pattern_sub() -> CCSInstance {
    let m_r5_t1 = select_matrix(reg_t1(5));
    let m_r3_t  = select_matrix(reg_t(3));
    let m_r4_t  = select_matrix(reg_t(4));
    build_ccs(
        vec![m_r5_t1, m_r3_t, m_r4_t],
        vec![
            (vec![0], Goldilocks::ONE),  // +r5_{t+1}
            (vec![1], neg_one()),        // -r3_t
            (vec![2], Goldilocks::ONE),  // +r4_t
        ],
    )
}

// ── pattern 7: mul ───────────────────────────────────────────────────────────
// C_7: r5_{t+1} - r3_t * r4_t = 0
fn pattern_mul() -> CCSInstance {
    let m_r5_t1 = select_matrix(reg_t1(5));
    let m_r3_t  = select_matrix(reg_t(3));
    let m_r4_t  = select_matrix(reg_t(4));
    build_ccs(
        vec![m_r5_t1, m_r3_t, m_r4_t],
        vec![
            (vec![0],    Goldilocks::ONE), // +r5_{t+1}
            (vec![1, 2], neg_one()),       // -r3_t * r4_t (Hadamard)
        ],
    )
}

// ── pattern 8: inv ───────────────────────────────────────────────────────────
// C_8: r5_{t+1} * r3_t - 1 = 0
fn pattern_inv() -> CCSInstance {
    let m_r5_t1  = select_matrix(reg_t1(5));
    let m_r3_t   = select_matrix(reg_t(3));
    let m_const  = select_matrix(CONST_IDX);
    build_ccs(
        vec![m_r5_t1, m_r3_t, m_const],
        vec![
            (vec![0, 1], Goldilocks::ONE), // +r5_{t+1} * r3_t (Hadamard)
            (vec![2],    neg_one()),       // -1
        ],
    )
}

// ── pattern 9: eq ────────────────────────────────────────────────────────────
// Two sub-constraints:
// C_9a: r3_t*r8_t - r4_t*r8_t - r9_t = 0
// C_9b: r5_{t+1} - 1 + r9_t = 0
//
// Both constraints packed into one CCSInstance with 2 rows.
fn pattern_eq() -> CCSInstance {
    let mut mr3_2r  = SparseMatrix::new(2, Z_LEN);
    let mut mr4_2r  = SparseMatrix::new(2, Z_LEN);
    let mut mr8_2r  = SparseMatrix::new(2, Z_LEN);
    let mut mr9_2r  = SparseMatrix::new(2, Z_LEN);
    let mut mr5_2r  = SparseMatrix::new(2, Z_LEN);
    let mut mc_2r   = SparseMatrix::new(2, Z_LEN);

    mr3_2r.set(0, reg_t(3), Goldilocks::ONE);
    mr4_2r.set(0, reg_t(4), Goldilocks::ONE);
    mr8_2r.set(0, reg_t(8), Goldilocks::ONE);
    mr8_2r.set(1, reg_t(8), Goldilocks::ONE);  // r8 appears in both rows' context
    mr9_2r.set(0, reg_t(9), Goldilocks::ONE);
    mr9_2r.set(1, reg_t(9), Goldilocks::ONE);
    mr5_2r.set(1, reg_t1(5), Goldilocks::ONE);
    mc_2r.set(1, CONST_IDX, Goldilocks::ONE);

    CCSInstance {
        // matrices indexed 0..5
        matrices: vec![mr3_2r, mr4_2r, mr8_2r, mr9_2r, mr5_2r, mc_2r],
        multisets: vec![
            vec![0, 2], // r3_t * r8_t  (row 0)
            vec![1, 2], // r4_t * r8_t  (row 0)
            vec![3],    // r9_t         (row 0)
            vec![4],    // r5_{t+1}     (row 1)
            vec![5],    // 1            (row 1)
            vec![3],    // r9_t         (row 1)  — reuse matrix index 3
        ],
        coeffs: vec![
            Goldilocks::ONE,  // +r3*r8
            neg_one(),        // -r4*r8
            neg_one(),        // -r9
            Goldilocks::ONE,  // +r5_{t+1}
            neg_one(),        // -1
            Goldilocks::ONE,  // +r9
        ],
        num_rows: 2,
        num_cols: Z_LEN,
    }
}

// ── pattern 0: axis ──────────────────────────────────────────────────────────
// Single-row; cost 1. Lens opening verified via axis_acc (separate fold).
// Inline constraint: budget decrement r9 = r8 - 1.
// Commitment binding (r11-r14) is checked by the axis_acc, not here.
fn pattern_axis() -> CCSInstance {
    let m_r9 = select_matrix(reg_t(9));   // z[9]  = budget_out
    let m_r8 = select_matrix(reg_t(8));   // z[8]  = budget_in
    let m_c  = select_matrix(CONST_IDX); // z[32] = 1
    build_ccs(
        vec![m_r9, m_r8, m_c],
        vec![
            (vec![0], Goldilocks::ONE), // +r9
            (vec![1], neg_one()),       // -r8
            (vec![2], Goldilocks::ONE), // +1  → r9 - r8 + 1 = 0 ↔ r9 = r8 - 1
        ],
    )
}

// ── pattern 10: lt ───────────────────────────────────────────────────────────
// 64-row block; per-row r10 = a_k ∈ {0,1}.
// C_10: a_k * (a_k - 1) = 0  →  a_k² - a_k = 0
fn pattern_lt() -> CCSInstance {
    let m_ak = select_matrix(reg_t(10)); // z[10]
    build_ccs(
        vec![m_ak],
        vec![
            (vec![0, 0], Goldilocks::ONE), // +a_k²
            (vec![0],    neg_one()),       // -a_k
        ],
    )
}

// ── pattern 11: xor ──────────────────────────────────────────────────────────
// 32-row block; per-row r10=a_k, r11=b_k, r12=c_k.
// C_11: a_k + b_k - 2·a_k·b_k - c_k = 0  (XOR gadget)
fn pattern_xor() -> CCSInstance {
    let m_ak = select_matrix(reg_t(10));
    let m_bk = select_matrix(reg_t(11));
    let m_ck = select_matrix(reg_t(12));
    let neg_two = Goldilocks::ZERO - Goldilocks::new(2);
    build_ccs(
        vec![m_ak, m_bk, m_ck],
        vec![
            (vec![0],    Goldilocks::ONE), // +a_k
            (vec![1],    Goldilocks::ONE), // +b_k
            (vec![0, 1], neg_two),         // -2·a_k·b_k
            (vec![2],    neg_one()),       // -c_k
        ],
    )
}

// ── pattern 12: and ──────────────────────────────────────────────────────────
// 32-row block; per-row r10=a_k, r11=b_k, r12=c_k.
// C_12: a_k·b_k - c_k = 0  (AND gadget)
fn pattern_and() -> CCSInstance {
    let m_ak = select_matrix(reg_t(10));
    let m_bk = select_matrix(reg_t(11));
    let m_ck = select_matrix(reg_t(12));
    build_ccs(
        vec![m_ak, m_bk, m_ck],
        vec![
            (vec![0, 1], Goldilocks::ONE), // +a_k·b_k
            (vec![2],    neg_one()),       // -c_k
        ],
    )
}

// ── pattern 13: not ──────────────────────────────────────────────────────────
// 32-row block; per-row r10=a_k, r12=c_k, r11=0 (unused).
// C_13: a_k + c_k - 1 = 0  (NOT bit gadget: c_k = 1 - a_k)
fn pattern_not() -> CCSInstance {
    let m_ak    = select_matrix(reg_t(10));  // z[10]
    let m_ck    = select_matrix(reg_t(12));  // z[12]
    let m_const = select_matrix(CONST_IDX);  // z[32]
    build_ccs(
        vec![m_ak, m_ck, m_const],
        vec![
            (vec![0], Goldilocks::ONE), // +a_k
            (vec![1], Goldilocks::ONE), // +c_k
            (vec![2], neg_one()),       // -1
        ],
    )
}

// ── pattern 14: shl ──────────────────────────────────────────────────────────
// 32-row block; per-row r11=src_bit, r12=c_k (output bit).
// C_14: c_k - src_bit = 0
fn pattern_shl() -> CCSInstance {
    let m_ck  = select_matrix(reg_t(12)); // z[12]
    let m_src = select_matrix(reg_t(11)); // z[11]
    build_ccs(
        vec![m_ck, m_src],
        vec![
            (vec![0], Goldilocks::ONE), // +c_k
            (vec![1], neg_one()),       // -src_bit
        ],
    )
}

// ── pattern 15: hash ─────────────────────────────────────────────────────────
// 25-row block (24 round rows + 1 squeeze); r14 = round index (0..24).
// C_15: r14_{t+1} - r14_t - 1 = 0  (round counter increments by 1)
// Applied only to intra-block pairs (both rows tag=15) via build_ccs_from_trace.
fn pattern_hash() -> CCSInstance {
    let m_r14_t1 = select_matrix(reg_t1(14)); // z[30]
    let m_r14_t  = select_matrix(reg_t(14));  // z[14]
    let m_const  = select_matrix(CONST_IDX);  // z[32]
    build_ccs(
        vec![m_r14_t1, m_r14_t, m_const],
        vec![
            (vec![0], Goldilocks::ONE), // +r14_{t+1}
            (vec![1], neg_one()),       // -r14_t
            (vec![2], neg_one()),       // -1
        ],
    )
}

// ── pattern 16: call ─────────────────────────────────────────────────────────
// C_16: check formula result must be zero. Full call verification wires r6 to check sub-row.
// r6 = result of check formula (must be 0 for call success)
// C_16: r6 = 0
fn pattern_call() -> CCSInstance {
    let m_r6 = select_matrix(reg_t(6));  // z[6]
    build_ccs(
        vec![m_r6],
        vec![
            (vec![0], Goldilocks::ONE),  // +r6
        ],
    )
}

// Pattern 17 (look): 2 inline wiring constraints (root binding, eval point binding)
// require BBG_root from Statement and eval(r4) derivation.
// See bbg/.claude/plans/pattern17-look-integration.md
fn pattern_look_inline() -> CCSInstance {
    trivial_ccs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::{reg_t, reg_t1, CONST_IDX, Z_LEN};
    use crate::types::{CCSWitness};

    fn make_z(vals: &[(usize, u64)]) -> Vec<Goldilocks> {
        let mut z = vec![Goldilocks::ZERO; Z_LEN];
        z[CONST_IDX] = Goldilocks::ONE;
        for &(idx, v) in vals {
            z[idx] = Goldilocks::new(v);
        }
        z
    }

    #[test]
    fn pattern_axis_budget_decrement() {
        // r8=10, r9=9: 9 - 10 + 1 = 0 ✓
        let z = make_z(&[(reg_t(8), 10), (reg_t(9), 9)]);
        assert!(pattern_axis().is_satisfied_by(&CCSWitness { z }));
        // r8=10, r9=8: 8 - 10 + 1 = -1 ≠ 0 ✗
        let z = make_z(&[(reg_t(8), 10), (reg_t(9), 8)]);
        assert!(!pattern_axis().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_add_satisfying_witness() {
        // r3=5, r4=3, r5_{t+1}=8: 8 - 5 - 3 = 0
        let z = make_z(&[(reg_t(3), 5), (reg_t(4), 3), (reg_t1(5), 8)]);
        let ccs = pattern_add();
        assert!(ccs.is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_add_wrong_witness() {
        let z = make_z(&[(reg_t(3), 5), (reg_t(4), 3), (reg_t1(5), 7)]);
        let ccs = pattern_add();
        assert!(!ccs.is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_sub_satisfying_witness() {
        // r3=7, r4=2, r5=5: 5 - 7 + 2 = 0
        let z = make_z(&[(reg_t(3), 7), (reg_t(4), 2), (reg_t1(5), 5)]);
        let ccs = pattern_sub();
        assert!(ccs.is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_mul_satisfying_witness() {
        // r3=6, r4=7, r5=42: 42 - 6*7 = 0
        let z = make_z(&[(reg_t(3), 6), (reg_t(4), 7), (reg_t1(5), 42)]);
        let ccs = pattern_mul();
        assert!(ccs.is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_mul_wrong_witness() {
        let z = make_z(&[(reg_t(3), 6), (reg_t(4), 7), (reg_t1(5), 43)]);
        let ccs = pattern_mul();
        assert!(!ccs.is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_lt_bit_validity_accepts_bits() {
        // a_k=0: 0*(0-1)=0 ✓
        let z = make_z(&[(reg_t(10), 0)]);
        assert!(pattern_lt().is_satisfied_by(&CCSWitness { z }));
        // a_k=1: 1*(1-1)=0 ✓
        let z = make_z(&[(reg_t(10), 1)]);
        assert!(pattern_lt().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_lt_bit_validity_rejects_non_bit() {
        // a_k=2: 2*(2-1)=2 ≠ 0 ✗
        let z = make_z(&[(reg_t(10), 2)]);
        assert!(!pattern_lt().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_xor_gadget_satisfying() {
        // 1 XOR 0 = 1: 1+0-0-1=0 ✓
        let z = make_z(&[(reg_t(10), 1), (reg_t(11), 0), (reg_t(12), 1)]);
        assert!(pattern_xor().is_satisfied_by(&CCSWitness { z }));
        // 1 XOR 1 = 0: 1+1-2-0=0 ✓
        let z = make_z(&[(reg_t(10), 1), (reg_t(11), 1), (reg_t(12), 0)]);
        assert!(pattern_xor().is_satisfied_by(&CCSWitness { z }));
        // 1 XOR 0 ≠ 0: 1+0-0-0=1 ✗
        let z = make_z(&[(reg_t(10), 1), (reg_t(11), 0), (reg_t(12), 0)]);
        assert!(!pattern_xor().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_and_gadget_satisfying() {
        // 1 AND 1 = 1: 1-1=0 ✓
        let z = make_z(&[(reg_t(10), 1), (reg_t(11), 1), (reg_t(12), 1)]);
        assert!(pattern_and().is_satisfied_by(&CCSWitness { z }));
        // 1 AND 0 = 0: 0-0=0 ✓
        let z = make_z(&[(reg_t(10), 1), (reg_t(11), 0), (reg_t(12), 0)]);
        assert!(pattern_and().is_satisfied_by(&CCSWitness { z }));
        // 1 AND 1 ≠ 0: 1-0=1 ✗
        let z = make_z(&[(reg_t(10), 1), (reg_t(11), 1), (reg_t(12), 0)]);
        assert!(!pattern_and().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_not_bit_gadget() {
        // a_k=0, c_k=1: 0+1-1=0 ✓
        let z = make_z(&[(reg_t(10), 0), (reg_t(12), 1)]);
        assert!(pattern_not().is_satisfied_by(&CCSWitness { z }));
        // a_k=1, c_k=0: 1+0-1=0 ✓
        let z = make_z(&[(reg_t(10), 1), (reg_t(12), 0)]);
        assert!(pattern_not().is_satisfied_by(&CCSWitness { z }));
        // a_k=1, c_k=1: 1+1-1=1 ✗
        let z = make_z(&[(reg_t(10), 1), (reg_t(12), 1)]);
        assert!(!pattern_not().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_shl_src_bit_propagation() {
        // src_bit=1, c_k=1: 1-1=0 ✓
        let z = make_z(&[(reg_t(11), 1), (reg_t(12), 1)]);
        assert!(pattern_shl().is_satisfied_by(&CCSWitness { z }));
        // src_bit=0, c_k=1: 1-0=1 ✗
        let z = make_z(&[(reg_t(11), 0), (reg_t(12), 1)]);
        assert!(!pattern_shl().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_hash_round_counter_increments() {
        // r14_t=5, r14_{t+1}=6: 6-5-1=0 ✓
        let z = make_z(&[(reg_t(14), 5), (reg_t1(14), 6)]);
        assert!(pattern_hash().is_satisfied_by(&CCSWitness { z }));
        // r14_t=5, r14_{t+1}=7: 7-5-1=1 ✗
        let z = make_z(&[(reg_t(14), 5), (reg_t1(14), 7)]);
        assert!(!pattern_hash().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_call_result_must_be_zero() {
        let z = make_z(&[(reg_t(6), 0)]);
        assert!(pattern_call().is_satisfied_by(&CCSWitness { z }));
        let z = make_z(&[(reg_t(6), 1)]);
        assert!(!pattern_call().is_satisfied_by(&CCSWitness { z }));
    }
}
