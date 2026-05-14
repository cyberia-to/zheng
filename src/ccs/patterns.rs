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
// C_4: sel*(r5_{t+1} - yes) + (1-sel)*(r5_{t+1} - no) = 0
// = r5_{t+1} - no + sel*(no - yes) = 0  (degree 2 via sel*r5)
// Using sub-constraint: sel*(next - yes) = 0 AND (1-sel)*(next - no) = 0.
// Simplified linear form: r5_{t+1} = r4_t * sel + r6_t * (1 - sel).
// Here sel = r8_t (bool auxiliary), yes = r4_t, no = r6_t.
fn pattern_branch() -> CCSInstance {
    // C_4a: r5_{t+1} - r6_t + r8_t*(r6_t - r4_t) = 0
    // decompose: r5_{t+1} - r6_t + r8_t*r6_t - r8_t*r4_t = 0
    let m_r5_t1 = select_matrix(reg_t1(5));
    let m_r6_t  = select_matrix(reg_t(6));
    let m_r8_t  = select_matrix(reg_t(8)); // selector auxiliary
    let m_r4_t  = select_matrix(reg_t(4));

    // Need two extra matrices for the products r8*r6 and r8*r4
    let m_r8_t_dup  = select_matrix(reg_t(8));
    let m_r6_t_dup  = select_matrix(reg_t(6));
    let m_r8_t_dup2 = select_matrix(reg_t(8));
    let m_r4_t_dup  = select_matrix(reg_t(4));

    CCSInstance {
        matrices: vec![m_r5_t1, m_r6_t, m_r8_t, m_r6_t_dup, m_r8_t_dup, m_r4_t, m_r8_t_dup2, m_r4_t_dup],
        multisets: vec![
            vec![0],    // r5_{t+1}
            vec![1],    // -r6_t
            vec![2, 3], // +r8_t * r6_t
            vec![4, 5], // -r8_t * r4_t (wait, wrong indices, fix below)
        ],
        coeffs: vec![
            Goldilocks::ONE,  // +r5_{t+1}
            neg_one(),        // -r6_t
            Goldilocks::ONE,  // +r8_t * r6_t  (matrices 2,3)
            neg_one(),        // -r8_t * r4_t  (matrices 4,5)
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

// Pattern 0 (axis): constraint is Lens.verify(r4, r6, r7) via folded CCS sub-instance.
// Inline wiring constraints require BBG/lens integration — deferred.
// See lens/.claude/plans/pattern0-axis-folded-opening.md
fn pattern_axis() -> CCSInstance {
    trivial_ccs()
}

// ── pattern 10: lt ───────────────────────────────────────────────────────────
// r6 = result (0 if r4 < r5, else 1), r11 = borrow/sign bit.
// C_10: r6 + r11 - 1 = 0  (result = 1 - borrow)
// Full 64-bit range decomposition requires per-bit witnesses in nox trace.
// See nox/.claude/plans/pattern-bit-decomp.md
fn pattern_lt() -> CCSInstance {
    let m_r6    = select_matrix(reg_t(6));   // z[6]
    let m_r11   = select_matrix(reg_t(11));  // z[11]
    let m_const = select_matrix(CONST_IDX);  // z[32]
    build_ccs(
        vec![m_r6, m_r11, m_const],
        vec![
            (vec![0], Goldilocks::ONE),  // +r6
            (vec![1], Goldilocks::ONE),  // +r11
            (vec![2], neg_one()),        // -1
        ],
    )
}

// Pattern 11 (xor): bit-by-bit XOR (c_k = a_k + b_k - 2*a_k*b_k) requires per-bit
// witnesses not present in single-row trace. See nox/.claude/plans/pattern-bit-decomp.md
fn pattern_xor() -> CCSInstance {
    trivial_ccs()
}

// Pattern 12 (and): bit-by-bit AND (c_k = a_k * b_k) requires per-bit witnesses.
// See nox/.claude/plans/pattern-bit-decomp.md
fn pattern_and() -> CCSInstance {
    trivial_ccs()
}

// ── pattern 13: not ──────────────────────────────────────────────────────────
// r6 = NOT r4 = (2^32 - 1) - r4
// C_13: r6 + r4 - (2^32 - 1) = 0
fn pattern_not() -> CCSInstance {
    let m_r6    = select_matrix(reg_t(6));   // z[6]
    let m_r4    = select_matrix(reg_t(4));   // z[4]
    let m_const = select_matrix(CONST_IDX);  // z[32]
    let neg_word_mask = Goldilocks::ZERO - Goldilocks::new(4294967295u64);
    build_ccs(
        vec![m_r6, m_r4, m_const],
        vec![
            (vec![0], Goldilocks::ONE),  // +r6
            (vec![1], Goldilocks::ONE),  // +r4
            (vec![2], neg_word_mask),    // -(2^32 - 1)
        ],
    )
}

// Pattern 14 (shl): r6 = r4 * 2^r5 requires 2^r5 as auxiliary (variable shift).
// See nox/.claude/plans/pattern-bit-decomp.md
fn pattern_shl() -> CCSInstance {
    trivial_ccs()
}

// Pattern 15 (hash): Poseidon2 round constraints require ~300-row multi-row trace.
// nox currently emits a summary row. See nox/.claude/plans/pattern15-multi-row-hash-trace.md
fn pattern_hash() -> CCSInstance {
    trivial_ccs()
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
    fn pattern_lt_result_consistency() {
        // borrow=1 → result=0 (r4 < r5)
        let z = make_z(&[(reg_t(6), 0), (reg_t(11), 1)]);
        assert!(pattern_lt().is_satisfied_by(&CCSWitness { z }));
        // borrow=0 → result=1 (r4 >= r5)
        let z = make_z(&[(reg_t(6), 1), (reg_t(11), 0)]);
        assert!(pattern_lt().is_satisfied_by(&CCSWitness { z }));
        // borrow=1 but result=1 → violation
        let z = make_z(&[(reg_t(6), 1), (reg_t(11), 1)]);
        assert!(!pattern_lt().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_not_bitwise_complement() {
        // NOT 5 = 0xFFFFFFFA = 4294967290
        let input = 5u64;
        let expected = 4294967295u64 - input; // = 4294967290
        let z = make_z(&[(reg_t(4), input), (reg_t(6), expected)]);
        assert!(pattern_not().is_satisfied_by(&CCSWitness { z }));
        // wrong complement → violation
        let z = make_z(&[(reg_t(4), input), (reg_t(6), expected + 1)]);
        assert!(!pattern_not().is_satisfied_by(&CCSWitness { z }));
    }

    #[test]
    fn pattern_call_result_must_be_zero() {
        let z = make_z(&[(reg_t(6), 0)]);
        assert!(pattern_call().is_satisfied_by(&CCSWitness { z }));
        let z = make_z(&[(reg_t(6), 1)]);
        assert!(!pattern_call().is_satisfied_by(&CCSWitness { z }));
    }
}
