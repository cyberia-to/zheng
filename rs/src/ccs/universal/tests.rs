//! Universal step instance: per-pattern gadgets and the selector rules.

use super::*;
use crate::ccs::selector::is_satisfied;
use crate::ccs::universal::test_witness;

fn ok(vals: &[(usize, u64)]) -> bool {
    is_satisfied(universal_ccs(), &test_witness(vals))
}

fn tagged(tag: u64, vals: &[(usize, u64)]) -> Vec<(usize, u64)> {
    let mut v = vec![(reg_t(0), tag)];
    v.extend_from_slice(vals);
    v
}

#[test]
fn instance_shape() {
    let u = universal_ccs();
    assert_eq!(u.num_rows, NUM_ROWS);
    assert_eq!(u.num_cols, Z_LEN);
    assert_eq!(u.matrices.len(), NUM_MATRICES);
    assert_eq!(u.multisets.iter().map(|m| m.len()).max(), Some(4), "max degree 4");
}

// ── selector rules ───────────────────────────────────────────────────────────

#[test]
fn every_pattern_tag_has_a_satisfiable_row() {
    // A row with the right selector and otherwise zero registers satisfies
    // patterns whose gadgets vanish on zeros; those that do not need
    // registers set — covered by the gadget tests below.
    for p in [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 17] {
        assert!(ok(&tagged(p, &[])), "tag {p} all-zero row");
    }
    assert!(ok(&tagged(0, &[(reg_t(8), 1)])), "axis with r9 = r8 − 1");
    assert!(ok(&tagged(13, &[(reg_t(12), 1)])), "not with c = 1 − a");
}

#[test]
fn unknown_tag_leaves_no_selector_and_fails() {
    // r0 = 255: no selector column can be 1 (s_p·(r0−p) = 0 for all p) and
    // the sum row demands one — unsatisfiable.
    assert!(!ok(&tagged(255, &[])));
    assert!(!ok(&tagged(18, &[])));
}

#[test]
fn wrong_selector_for_r0_fails() {
    // An add row (r0 = 5) satisfied as add, then re-labelled: s_7 = 1
    // instead of s_5 with r0 still 5 breaks s_7·(r0 − 7) = 0.
    let mut w = test_witness(&tagged(5, &[(reg_t(4), 2), (reg_t(5), 3), (reg_t(6), 5)]));
    assert!(is_satisfied(universal_ccs(), &w));
    w.z[sel(5)] = Goldilocks::ZERO;
    w.z[sel(7)] = Goldilocks::ONE;
    assert!(!is_satisfied(universal_ccs(), &w), "selector must match r0");
    // Two selectors: sum row breaks (and s_7's own row).
    w.z[sel(5)] = Goldilocks::ONE;
    assert!(!is_satisfied(universal_ccs(), &w), "selectors are one-hot");
    // No selector: sum row breaks.
    w.z[sel(5)] = Goldilocks::ZERO;
    w.z[sel(7)] = Goldilocks::ZERO;
    assert!(!is_satisfied(universal_ccs(), &w), "one selector is mandatory");
}

#[test]
fn mismatched_r0_fails_even_with_satisfied_gadget() {
    // Registers satisfy add, selector says add, but r0 = 7: s_5·(r0 − 5) ≠ 0.
    let mut w = test_witness(&tagged(5, &[(reg_t(4), 2), (reg_t(5), 3), (reg_t(6), 5)]));
    w.z[reg_t(0)] = Goldilocks::new(7);
    assert!(!is_satisfied(universal_ccs(), &w));
}

#[test]
fn selector_gate_cannot_be_scaled() {
    // s_5 = 2 satisfies s_5·(r0 − 5) = 0 but not Σ s_p = 1; with a
    // violated add gadget the scaled gate does not hide it either.
    let mut w = test_witness(&tagged(5, &[(reg_t(4), 2), (reg_t(5), 3), (reg_t(6), 9)]));
    w.z[sel(5)] = Goldilocks::new(2);
    assert!(!is_satisfied(universal_ccs(), &w));
}

#[test]
fn hash_round_selector_binds_to_r14() {
    use crate::ccs::particle::replay_states;
    let states = replay_states(&[Goldilocks::ZERO; 8]);
    let k = 5usize;
    let honest = poseidon_witness(&states[k], &states[k + 1], k);
    assert!(is_satisfied(universal_ccs(), &honest));

    // Shift the one-hot to the wrong round: u_k·(r14 − k) = 0 breaks.
    let mut w = honest.clone();
    w.z[round_sel(k)] = Goldilocks::ZERO;
    w.z[round_sel(k + 1)] = Goldilocks::ONE;
    assert!(!is_satisfied(universal_ccs(), &w), "round selector must match r14");

    // Drop the round selector entirely: Σ u = s_15 breaks.
    let mut w = honest.clone();
    w.z[round_sel(k)] = Goldilocks::ZERO;
    w.z[IDX_PI] = Goldilocks::ZERO;
    w.z[IDX_RC] = Goldilocks::ZERO;
    w.z[IDX_KAPPA] = Goldilocks::ZERO;
    assert!(!is_satisfied(universal_ccs(), &w), "a hash row must select its round");

    // Wrong round constant: rc − Σ RC·u = 0 breaks (and the S-box row).
    let mut w = honest.clone();
    w.z[IDX_RC] += Goldilocks::ONE;
    assert!(!is_satisfied(universal_ccs(), &w), "rc is bound to the round index");

    // Clear π to escape the partial-round rows: π − Σ u_j = 0 breaks.
    let mut w = honest.clone();
    w.z[IDX_PI] = Goldilocks::ZERO;
    assert!(!is_satisfied(universal_ccs(), &w), "π is bound to the round selectors");
}

#[test]
fn non_hash_row_cannot_arm_poseidon_gates() {
    // An axis row whose r14 happens to be 5 (commitment limb): setting u_5
    // is blocked by Σ u = s_15 = 0.
    let mut w = test_witness(&tagged(0, &[(reg_t(8), 1), (reg_t(14), 5)]));
    assert!(is_satisfied(universal_ccs(), &w));
    w.z[round_sel(5)] = Goldilocks::ONE;
    w.z[IDX_PI] = Goldilocks::ONE;
    w.z[IDX_RC] = partial_rc(2);
    assert!(!is_satisfied(universal_ccs(), &w));
}

#[test]
fn squeeze_boundary_pair_has_no_counter_constraint() {
    // Squeeze row (k = 24) followed by a quote row: κ = 0, no r14 chain.
    assert!(ok(&tagged(15, &[(reg_t(14), 24), (reg_t1(0), 1), (reg_t1(14), 0)])));
    // Round row k = 7 followed by k = 9: κ = 1 and the counter breaks.
    assert!(!ok(&tagged(15, &[(reg_t(14), 7), (reg_t1(14), 9)])));
    // Out-of-range round index: no u_k can be set.
    assert!(!ok(&tagged(15, &[(reg_t(14), 25), (reg_t1(14), 26)])));
}

// ── pattern gadgets ──────────────────────────────────────────────────────────

#[test]
fn pattern_axis_budget_decrement() {
    assert!(ok(&tagged(0, &[(reg_t(8), 10), (reg_t(9), 9)])));
    assert!(!ok(&tagged(0, &[(reg_t(8), 10), (reg_t(9), 8)])));
}

#[test]
fn pattern_quote_result_equals_body_in_row() {
    assert!(ok(&tagged(1, &[(reg_t(4), 42), (reg_t(7), 42)])));
    assert!(!ok(&tagged(1, &[(reg_t(4), 42), (reg_t(7), 41)])));
}

#[test]
fn pattern_add_sub_mul() {
    assert!(ok(&tagged(5, &[(reg_t(4), 5), (reg_t(5), 3), (reg_t(6), 8)])));
    assert!(!ok(&tagged(5, &[(reg_t(4), 5), (reg_t(5), 3), (reg_t(6), 7)])));
    assert!(ok(&tagged(6, &[(reg_t(4), 7), (reg_t(5), 2), (reg_t(6), 5)])));
    assert!(!ok(&tagged(6, &[(reg_t(4), 7), (reg_t(5), 2), (reg_t(6), 6)])));
    assert!(ok(&tagged(7, &[(reg_t(4), 6), (reg_t(5), 7), (reg_t(6), 42)])));
    assert!(!ok(&tagged(7, &[(reg_t(4), 6), (reg_t(5), 7), (reg_t(6), 43)])));
}

#[test]
fn pattern_inv_final_row_holds_the_inverse() {
    let inv7 = Goldilocks::new(7).inv().as_u64();
    // chain rows: r6 = 0
    assert!(ok(&tagged(8, &[(reg_t(4), 7), (reg_t(10), 49)])));
    // final row: r6 = v⁻¹
    assert!(ok(&tagged(8, &[(reg_t(4), 7), (reg_t(6), inv7)])));
    // forged inverse
    assert!(!ok(&tagged(8, &[(reg_t(4), 7), (reg_t(6), inv7 + 1)])));
}

#[test]
fn pattern_eq_gadget() {
    assert!(ok(&tagged(9, &[(reg_t(4), 9), (reg_t(5), 9)])));
    let inv5 = (Goldilocks::new(9) - Goldilocks::new(4)).inv().as_u64();
    assert!(ok(&tagged(9, &[(reg_t(4), 9), (reg_t(5), 4), (reg_t(6), 1), (reg_t(7), inv5)])));
    // unequal operands claimed equal
    assert!(!ok(&tagged(9, &[(reg_t(4), 9), (reg_t(5), 4)])));
    // equal operands claimed unequal
    assert!(!ok(&tagged(9, &[(reg_t(4), 9), (reg_t(5), 9), (reg_t(6), 1)])));
}

#[test]
fn pattern_branch_selector_gadget() {
    assert!(ok(&tagged(4, &[])));
    let inv7 = Goldilocks::new(7).inv().as_u64();
    assert!(ok(&tagged(4, &[(reg_t(4), 7), (reg_t(5), inv7), (reg_t(10), 1)])));
    assert!(!ok(&tagged(4, &[(reg_t(4), 7), (reg_t(5), inv7)])));
    assert!(!ok(&tagged(4, &[(reg_t(10), 1)])));
}

#[test]
fn pattern_lt_bits_are_boolean() {
    assert!(ok(&tagged(10, &[(reg_t(10), 0), (reg_t(11), 1)])));
    assert!(ok(&tagged(10, &[(reg_t(10), 1), (reg_t(11), 0)])));
    assert!(!ok(&tagged(10, &[(reg_t(10), 2)])));
    assert!(!ok(&tagged(10, &[(reg_t(11), 2)])));
}

#[test]
fn pattern_xor_gadget() {
    assert!(ok(&tagged(11, &[(reg_t(10), 1), (reg_t(11), 0), (reg_t(12), 1)])));
    assert!(ok(&tagged(11, &[(reg_t(10), 1), (reg_t(11), 1), (reg_t(12), 0)])));
    assert!(!ok(&tagged(11, &[(reg_t(10), 1), (reg_t(11), 0), (reg_t(12), 0)])));
    // non-boolean operand bit
    assert!(!ok(&tagged(11, &[(reg_t(10), 2), (reg_t(11), 0), (reg_t(12), 2)])));
}

#[test]
fn pattern_and_gadget() {
    assert!(ok(&tagged(12, &[(reg_t(10), 1), (reg_t(11), 1), (reg_t(12), 1)])));
    assert!(ok(&tagged(12, &[(reg_t(10), 1), (reg_t(11), 0), (reg_t(12), 0)])));
    assert!(!ok(&tagged(12, &[(reg_t(10), 1), (reg_t(11), 1), (reg_t(12), 0)])));
    assert!(!ok(&tagged(12, &[(reg_t(10), 2), (reg_t(11), 1), (reg_t(12), 2)])));
}

#[test]
fn pattern_not_gadget() {
    assert!(ok(&tagged(13, &[(reg_t(10), 0), (reg_t(12), 1)])));
    assert!(ok(&tagged(13, &[(reg_t(10), 1), (reg_t(12), 0)])));
    assert!(!ok(&tagged(13, &[(reg_t(10), 1), (reg_t(12), 1)])));
    // r11 must be zero on unary rows
    assert!(!ok(&tagged(13, &[(reg_t(10), 0), (reg_t(11), 1), (reg_t(12), 1)])));
}

#[test]
fn pattern_shl_src_bit_propagation() {
    assert!(ok(&tagged(14, &[(reg_t(11), 1), (reg_t(12), 1)])));
    assert!(!ok(&tagged(14, &[(reg_t(11), 0), (reg_t(12), 1)])));
}

#[test]
fn pattern_hash_round_counter_increments() {
    assert!(ok(&tagged(15, &[(reg_t(14), 0), (reg_t1(14), 1)])));
    assert!(!ok(&tagged(15, &[(reg_t(14), 0), (reg_t1(14), 2)])));
}

#[test]
fn pattern_call_result_must_be_zero() {
    assert!(ok(&tagged(16, &[(reg_t(6), 0)])));
    assert!(!ok(&tagged(16, &[(reg_t(6), 1)])));
}

#[test]
fn gadgets_of_other_patterns_are_inert() {
    // A quote row with registers that would violate add, mul, eq, branch,
    // the bit gadgets and the hash counter — all gated off by s_1.
    assert!(ok(&tagged(
        1,
        &[
            (reg_t(4), 42),
            (reg_t(7), 42),
            (reg_t(5), 3),
            (reg_t(6), 1000),
            (reg_t(10), 5),
            (reg_t(11), 5),
            (reg_t(12), 5),
            (reg_t(14), 3),
            (reg_t1(14), 9),
        ]
    )));
}
