// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! The universal step CCS: ONE instance for every Layer-1 row.
//!
//! specs/constraints.md §"the combined constraint": `C(t) = Σ_p s_p · C_p(t)`
//! with one-hot selector columns `s_0..s_17` in the witness (not Lagrange
//! polynomials over r0 — those raise the degree by 17; the one-hot columns
//! raise it by exactly one). Every trace pair (row t, row t+1) and every
//! synthetic Poseidon2 round (Fiat-Shamir transcript replay, BBG root chain)
//! is a witness of this single instance, so the whole Layer-1 argument is one
//! HyperNova accumulator and one decider, whatever the program.
//!
//! Witness layout (`Z_LEN` = 96, padded to 128 for the lens):
//!
//! ```text
//! z[0..16]   r_t             z[16..32]  r_{t+1}         z[32]  1
//! z[33..51]  s_0..s_17       pattern selectors, one-hot on r0_t
//! z[51..76]  u_0..u_24       Poseidon2 round selectors, one-hot on r14_t
//!                            when s_15 = 1, all zero otherwise
//! z[76] π    partial-round flag  = Σ_{j=3..18} u_j
//! z[77] κ    round-counter flag  = s_15 − u_24
//! z[78] rc   round constant      = Σ_{j=3..18} RC[128+j−3] · u_j
//! z[79..87]  state_k[8..16]      capacity at row t   (prover-supplied)
//! z[87..95]  state_{k+1}[8..16]  capacity at row t+1 (prover-supplied)
//! z[95] y    inv(state_k[0] + rc), the partial-round S-box witness
//! ```
//!
//! Constraint rows (`NUM_ROWS` = 64):
//!
//! ```text
//!  0..18  s_p · (r0 − p) = 0          one row per pattern p
//!  18     Σ_p s_p − 1 = 0
//! 19..44  u_k · (r14 − k) = 0         one row per round k ∈ 0..25
//!  44     Σ_k u_k − s_15 = 0
//!  45     π − Σ_{j=3..18} u_j = 0
//!  46     κ − s_15 + u_24 = 0
//!  47     rc − Σ_j RC_j · u_j = 0
//! 48..64  pattern rows: every pattern's constraints, each multiplied by
//!         its gate (s_p, π or κ); rows are shared across patterns because
//!         exactly one gate is live on any satisfying witness
//! ```
//!
//! Soundness of the gating: rows 0..18 force exactly one `s_p` to be
//! non-zero (two non-zero selectors would need two values of r0) and the
//! sum row makes it 1, so the pattern terms of every other pattern vanish
//! identically. Rows 19..44 do the same for `u` under s_15 = 1 and force
//! `u = 0` under s_15 = 0, so π and κ are 0 on every non-hash row — the
//! Poseidon2 terms cannot leak into another pattern's rows.
//!
//! The instance is built from 15 "slot" matrices and 6 product terms of
//! fixed shape ({A0,B0}, {C0,D0,E0}, {A1,B1}, {C1,D1,E1}, {F,G,H,I}, {P},
//! all with coefficient 1). A row places one linear form per slot it uses;
//! the sign of a term is carried by its linear forms. Slot family 0 hosts
//! the selector rows and the Poseidon2 partial round, family 1 the pattern
//! gadgets, {F,G,H,I} the two degree-4 gadgets (branch, inv), {P} the
//! ungated linear rows.

use std::sync::OnceLock;

use nebu::Goldilocks;

use hemera::constants::ROUND_CONSTANTS;
use hemera::field::{Goldilocks as HGold, MATRIX_DIAG_16};

use crate::types::{CCSInstance, CCSWitness, SparseMatrix};

/// Number of nox reduction patterns (tags 0..17).
pub const NUM_PATTERNS: usize = 18;
/// Poseidon2 rows per hash block: 24 round rows + the squeeze row (r14 = 24).
pub const NUM_ROUNDS: usize = 25;
/// First partial round index (r14 = 3 transitions into hemera partial round 0).
pub const PARTIAL_FIRST: usize = 3;
/// Number of partial rounds.
pub const NUM_PARTIAL: usize = 16;

/// Length of the universal witness before padding.
pub const Z_LEN: usize = 96;
/// Rows of the universal instance.
pub const NUM_ROWS: usize = 64;

/// z-index of register r at row t.
pub const fn reg_t(r: usize) -> usize {
    r
}
/// z-index of register r at row t+1.
pub const fn reg_t1(r: usize) -> usize {
    r + 16
}
/// z-index of the constant 1.
pub const CONST_IDX: usize = 32;
/// z-index of pattern selector s_p.
pub const fn sel(p: usize) -> usize {
    33 + p
}
/// z-index of round selector u_k.
pub const fn round_sel(k: usize) -> usize {
    51 + k
}
/// z-index of the partial-round flag π.
pub const IDX_PI: usize = 76;
/// z-index of the round-counter flag κ.
pub const IDX_KAPPA: usize = 77;
/// z-index of the round constant rc.
pub const IDX_RC: usize = 78;
/// z-index of state_k[8 + i] (capacity at row t).
pub const fn cap_k(i: usize) -> usize {
    79 + i
}
/// z-index of state_{k+1}[8 + i] (capacity at row t+1).
pub const fn cap_k1(i: usize) -> usize {
    87 + i
}
/// z-index of the S-box inverse witness y.
pub const IDX_Y: usize = 95;

/// z-index of Poseidon2 state_k[i]: rate in the trace registers
/// (r4-r7 = state[0..4], r10-r13 = state[4..8]), capacity in the aux columns.
pub const fn sk(i: usize) -> usize {
    match i {
        0..=3 => reg_t(4 + i),
        4..=7 => reg_t(10 + i - 4),
        _ => cap_k(i - 8),
    }
}
/// z-index of state_{k+1}[i].
pub const fn sk1(i: usize) -> usize {
    match i {
        0..=3 => reg_t1(4 + i),
        4..=7 => reg_t1(10 + i - 4),
        _ => cap_k1(i - 8),
    }
}

// ── rows ─────────────────────────────────────────────────────────────────────

const ROW_SEL: usize = 0; // + p
const ROW_SEL_SUM: usize = 18;
const ROW_ROUND: usize = 19; // + k
const ROW_ROUND_SUM: usize = 44;
const ROW_PI: usize = 45;
const ROW_KAPPA: usize = 46;
const ROW_RC: usize = 47;
const ROW_PAT: usize = 48; // + i, i ∈ 0..16

// ── slots ────────────────────────────────────────────────────────────────────

const A0: usize = 0;
const B0: usize = 1;
const C0: usize = 2;
const D0: usize = 3;
const E0: usize = 4;
const A1: usize = 5;
const B1: usize = 6;
const C1: usize = 7;
const D1: usize = 8;
const E1: usize = 9;
const F: usize = 10;
const G: usize = 11;
const H: usize = 12;
const I: usize = 13;
const P: usize = 14;
const NUM_MATRICES: usize = 15;
/// The two degree-3 slot triples.
const CDE0: (usize, usize, usize) = (C0, D0, E0);
const CDE1: (usize, usize, usize) = (C1, D1, E1);

fn hg(h: HGold) -> Goldilocks {
    Goldilocks::new(h.as_canonical_u64())
}

fn neg(x: Goldilocks) -> Goldilocks {
    Goldilocks::ZERO - x
}

/// The hemera round constant of partial round `pr` (0..16).
pub fn partial_rc(pr: usize) -> Goldilocks {
    hg(ROUND_CONSTANTS[128 + pr])
}

/// A linear form over z: Σ coeff · z[col].
type Form<'a> = &'a [(usize, Goldilocks)];

struct Builder {
    m: Vec<SparseMatrix>,
}

impl Builder {
    fn new() -> Self {
        Self { m: (0..NUM_MATRICES).map(|_| SparseMatrix::new(NUM_ROWS, Z_LEN)).collect() }
    }

    fn put(&mut self, slot: usize, row: usize, form: Form) {
        debug_assert!(
            self.m[slot].entries[row].is_empty(),
            "slot {slot} already placed on row {row}: two gadgets collide"
        );
        for &(col, c) in form {
            self.m[slot].set(row, col, c);
        }
    }

    /// Gated linear gadget: gate · form = 0 on `row`, slots (a, b).
    fn lin(&mut self, row: usize, a: usize, b: usize, gate: usize, form: Form) {
        self.put(a, row, &[(gate, Goldilocks::ONE)]);
        self.put(b, row, form);
    }

    /// Gated product gadget: gate · l · r = 0 on `row`, slot triple (c, d, e).
    fn prod(&mut self, row: usize, (c, d, e): (usize, usize, usize), gate: usize, l: Form, r: Form) {
        self.put(c, row, &[(gate, Goldilocks::ONE)]);
        self.put(d, row, l);
        self.put(e, row, r);
    }
}

fn one() -> Goldilocks {
    Goldilocks::ONE
}
fn m1() -> Goldilocks {
    neg(Goldilocks::ONE)
}

/// Build the universal instance. Prefer [`universal_ccs`] (built once).
fn build() -> CCSInstance {
    let mut b = Builder::new();

    // Pattern selectors: s_p · (r0 − p) = 0, then Σ s_p = 1.
    for p in 0..NUM_PATTERNS {
        b.lin(
            ROW_SEL + p,
            A0,
            B0,
            sel(p),
            &[(reg_t(0), one()), (CONST_IDX, neg(Goldilocks::new(p as u64)))],
        );
    }
    let mut sum: Vec<(usize, Goldilocks)> = (0..NUM_PATTERNS).map(|p| (sel(p), one())).collect();
    sum.push((CONST_IDX, m1()));
    b.put(P, ROW_SEL_SUM, &sum);

    // Round selectors: u_k · (r14 − k) = 0, then Σ u_k = s_15.
    for k in 0..NUM_ROUNDS {
        b.lin(
            ROW_ROUND + k,
            A0,
            B0,
            round_sel(k),
            &[(reg_t(14), one()), (CONST_IDX, neg(Goldilocks::new(k as u64)))],
        );
    }
    let mut usum: Vec<(usize, Goldilocks)> = (0..NUM_ROUNDS).map(|k| (round_sel(k), one())).collect();
    usum.push((sel(15), m1()));
    b.put(P, ROW_ROUND_SUM, &usum);

    // Derived flags: π, κ, rc.
    let mut pi: Vec<(usize, Goldilocks)> = vec![(IDX_PI, one())];
    let mut rc: Vec<(usize, Goldilocks)> = vec![(IDX_RC, one())];
    for pr in 0..NUM_PARTIAL {
        pi.push((round_sel(PARTIAL_FIRST + pr), m1()));
        rc.push((round_sel(PARTIAL_FIRST + pr), neg(partial_rc(pr))));
    }
    b.put(P, ROW_PI, &pi);
    b.put(P, ROW_KAPPA, &[(IDX_KAPPA, one()), (sel(15), m1()), (round_sel(24), one())]);
    b.put(P, ROW_RC, &rc);

    // ── Poseidon2 partial round (gate π), slot family 0 on rows 48..64 ──────
    // Row 0: y · (state_k[0] + rc) − 1 = 0
    b.prod(ROW_PAT, CDE0, IDX_PI, &[(IDX_Y, one())], &[(sk(0), one()), (IDX_RC, one())]);
    b.lin(ROW_PAT, A0, B0, IDX_PI, &[(CONST_IDX, m1())]);
    // Rows 1..16: matmul_internal, sum = state_{k+1}[1] − DIAG[1]·state_k[1]:
    //   i = 1:  state_{k+1}[0] − DIAG[0]·y − sum = 0
    //   i ≥ 2:  state_{k+1}[i] − DIAG[i]·state_k[i] − sum = 0
    let diag: Vec<Goldilocks> = MATRIX_DIAG_16.iter().map(|&d| hg(d)).collect();
    b.lin(
        ROW_PAT + 1,
        A0,
        B0,
        IDX_PI,
        &[(sk1(0), one()), (IDX_Y, neg(diag[0])), (sk1(1), m1()), (sk(1), diag[1])],
    );
    for i in 2..16 {
        b.lin(
            ROW_PAT + i,
            A0,
            B0,
            IDX_PI,
            &[(sk1(i), one()), (sk(i), neg(diag[i])), (sk1(1), m1()), (sk(1), diag[1])],
        );
    }

    // ── pattern gadgets, slot family 1 + {F,G,H,I} on rows 48..64 ───────────
    // 0 axis: r9 − r8 + 1 = 0 (budget decrement).
    b.lin(ROW_PAT, A1, B1, sel(0), &[(reg_t(9), one()), (reg_t(8), m1()), (CONST_IDX, one())]);
    // 1 quote: r7 − r4 = 0.
    b.lin(ROW_PAT + 1, A1, B1, sel(1), &[(reg_t(7), one()), (reg_t(4), m1())]);
    // 4 branch: r10 · (1 − r4·r5) = 0 ; r4 · (1 − r10) = 0.
    b.lin(ROW_PAT + 2, A1, B1, sel(4), &[(reg_t(10), one())]);
    b.put(F, ROW_PAT + 2, &[(sel(4), one())]);
    b.put(G, ROW_PAT + 2, &[(reg_t(10), m1())]);
    b.put(H, ROW_PAT + 2, &[(reg_t(4), one())]);
    b.put(I, ROW_PAT + 2, &[(reg_t(5), one())]);
    b.prod(ROW_PAT + 3, CDE1, sel(4), &[(reg_t(4), one())], &[(CONST_IDX, one()), (reg_t(10), m1())]);
    // 15 hash round counter (gate κ): r14_{t+1} − r14_t − 1 = 0.
    b.lin(ROW_PAT + 3, A1, B1, IDX_KAPPA, &[(reg_t1(14), one()), (reg_t(14), m1()), (CONST_IDX, m1())]);
    // 5 add: r6 − r4 − r5 = 0.
    b.lin(ROW_PAT + 4, A1, B1, sel(5), &[(reg_t(6), one()), (reg_t(4), m1()), (reg_t(5), m1())]);
    // 6 sub: r6 − r4 + r5 = 0.
    b.lin(ROW_PAT + 5, A1, B1, sel(6), &[(reg_t(6), one()), (reg_t(4), m1()), (reg_t(5), one())]);
    // 7 mul: r6 − r4·r5 = 0.
    b.lin(ROW_PAT + 6, A1, B1, sel(7), &[(reg_t(6), one())]);
    b.prod(ROW_PAT + 6, CDE1, sel(7), &[(reg_t(4), m1())], &[(reg_t(5), one())]);
    // 8 inv: r6 · (r6·r4 − 1) = 0 — r6 is 0 on chain rows, v⁻¹ on the final row.
    b.put(F, ROW_PAT + 7, &[(sel(8), one())]);
    b.put(G, ROW_PAT + 7, &[(reg_t(6), one())]);
    b.put(H, ROW_PAT + 7, &[(reg_t(6), one())]);
    b.put(I, ROW_PAT + 7, &[(reg_t(4), one())]);
    b.prod(ROW_PAT + 7, CDE1, sel(8), &[(reg_t(6), one())], &[(CONST_IDX, m1())]);
    // 9 eq: (r4−r5)(1−r6) = 0 ; r6(1−r6) = 0 ; (r4−r5)·r7 − r6 = 0.
    let diff = [(reg_t(4), one()), (reg_t(5), m1())];
    let one_m_r6 = [(CONST_IDX, one()), (reg_t(6), m1())];
    b.prod(ROW_PAT + 8, CDE1, sel(9), &diff, &one_m_r6);
    b.prod(ROW_PAT + 9, CDE1, sel(9), &[(reg_t(6), one())], &one_m_r6);
    b.prod(ROW_PAT + 10, CDE1, sel(9), &diff, &[(reg_t(7), one())]);
    b.lin(ROW_PAT + 10, A1, B1, sel(9), &[(reg_t(6), m1())]);
    // 16 call: r6 = 0 (check formula result).
    b.lin(ROW_PAT + 8, A1, B1, sel(16), &[(reg_t(6), one())]);
    // 10 lt: r10, r11 ∈ {0,1}.
    let r10 = [(reg_t(10), one())];
    let r11 = [(reg_t(11), one())];
    let r10_m1 = [(reg_t(10), one()), (CONST_IDX, m1())];
    let r11_m1 = [(reg_t(11), one()), (CONST_IDX, m1())];
    b.prod(ROW_PAT + 11, CDE1, sel(10), &r10, &r10_m1);
    b.prod(ROW_PAT + 14, CDE1, sel(10), &r11, &r11_m1);
    // 11 xor: r10 + r11 − 2·r10·r11 − r12 = 0 ; r10, r11 ∈ {0,1}.
    b.lin(ROW_PAT + 12, A1, B1, sel(11), &[(reg_t(10), one()), (reg_t(11), one()), (reg_t(12), m1())]);
    b.prod(ROW_PAT + 12, CDE1, sel(11), &[(reg_t(10), neg(Goldilocks::new(2)))], &r11);
    b.prod(ROW_PAT + 1, CDE1, sel(11), &r10, &r10_m1);
    b.prod(ROW_PAT + 4, CDE1, sel(11), &r11, &r11_m1);
    // 12 and: r10·r11 − r12 = 0 ; r10, r11 ∈ {0,1}.
    b.prod(ROW_PAT + 13, CDE1, sel(12), &r10, &r11);
    b.lin(ROW_PAT + 13, A1, B1, sel(12), &[(reg_t(12), m1())]);
    b.prod(ROW_PAT + 5, CDE1, sel(12), &r10, &r10_m1);
    b.prod(ROW_PAT + 15, CDE1, sel(12), &r11, &r11_m1);
    // 13 not: r10 + r12 − 1 = 0 ; r11 = 0.
    b.lin(ROW_PAT + 14, A1, B1, sel(13), &[(reg_t(10), one()), (reg_t(12), one()), (CONST_IDX, m1())]);
    b.lin(ROW_PAT + 7, A1, B1, sel(13), &r11);
    // 14 shl: r12 − r11 = 0.
    b.lin(ROW_PAT + 15, A1, B1, sel(14), &[(reg_t(12), one()), (reg_t(11), m1())]);
    // 2 compose, 3 cons, 17 look: no in-row constraint (cross-row wiring
    // and the look bindings live elsewhere — see specs/constraints.md).

    CCSInstance {
        matrices: b.m,
        multisets: vec![
            vec![A0, B0],
            vec![C0, D0, E0],
            vec![A1, B1],
            vec![C1, D1, E1],
            vec![F, G, H, I],
            vec![P],
        ],
        coeffs: vec![Goldilocks::ONE; 6],
        num_rows: NUM_ROWS,
        num_cols: Z_LEN,
    }
}

/// The universal step instance, built once per process.
pub fn universal_ccs() -> &'static CCSInstance {
    static CELL: OnceLock<CCSInstance> = OnceLock::new();
    CELL.get_or_init(build)
}

/// Poseidon2 capacity columns of one witness: state_k[8..16], state_{k+1}[8..16].
#[derive(Clone, Copy, Debug, Default)]
pub struct Capacity {
    pub k: [Goldilocks; 8],
    pub k1: [Goldilocks; 8],
}

/// Build the universal witness for the pair (row t, row t+1).
///
/// Selectors, round selectors, flags, the round constant and the S-box
/// inverse are all derived from the registers — the prover supplies only
/// the capacity columns (`caps`, needed on hash rows). A tag outside 0..18
/// or a round index outside 0..25 leaves the one-hot rows unsatisfiable;
/// the commit-time gate reports such rows.
pub fn universal_witness(
    regs_t: &[Goldilocks; 16],
    regs_t1: &[Goldilocks; 16],
    caps: Option<&Capacity>,
) -> CCSWitness {
    let mut z = vec![Goldilocks::ZERO; Z_LEN];
    z[..16].copy_from_slice(regs_t);
    z[16..32].copy_from_slice(regs_t1);
    z[CONST_IDX] = Goldilocks::ONE;

    let tag = regs_t[0].canonicalize().as_u64();
    if (tag as usize) < NUM_PATTERNS {
        z[sel(tag as usize)] = Goldilocks::ONE;
    }
    if tag == 15 {
        let k = regs_t[14].canonicalize().as_u64() as usize;
        if k < NUM_ROUNDS {
            z[round_sel(k)] = Goldilocks::ONE;
        }
        if k < NUM_ROUNDS - 1 {
            z[IDX_KAPPA] = Goldilocks::ONE;
        }
        if let Some(c) = caps {
            z[cap_k(0)..cap_k(8)].copy_from_slice(&c.k);
            z[cap_k1(0)..cap_k1(8)].copy_from_slice(&c.k1);
        }
        if (PARTIAL_FIRST..PARTIAL_FIRST + NUM_PARTIAL).contains(&k) {
            let rc = partial_rc(k - PARTIAL_FIRST);
            z[IDX_PI] = Goldilocks::ONE;
            z[IDX_RC] = rc;
            z[IDX_Y] = (regs_t[4] + rc).inv();
        }
    }
    CCSWitness { z }
}

/// Test witness from z-index assignments: `vals` are (z-index, value) pairs
/// over the register columns (`reg_t`, `reg_t1`); selectors and flags are
/// derived from r0/r14 exactly as for a real trace pair.
#[cfg(test)]
pub(crate) fn test_witness(vals: &[(usize, u64)]) -> CCSWitness {
    let mut regs = [[Goldilocks::ZERO; 16]; 2];
    for &(idx, v) in vals {
        regs[idx / 16][idx % 16] = Goldilocks::new(v);
    }
    universal_witness(&regs[0], &regs[1], None)
}

#[cfg(test)]
mod tests;

/// Registers of a synthetic Poseidon2 round row: the post-round state `k`
/// laid out as nox lays out a hash row (r0 = 15, rate in r4-r7 / r10-r13,
/// r14 = k), everything else zero.
pub fn poseidon_regs(state: &[Goldilocks; 16], k: usize) -> [Goldilocks; 16] {
    let mut r = [Goldilocks::ZERO; 16];
    r[0] = Goldilocks::new(15);
    r[4..8].copy_from_slice(&state[0..4]);
    r[10..14].copy_from_slice(&state[4..8]);
    r[14] = Goldilocks::new(k as u64);
    r
}

/// Capacity columns from two full 16-element states.
pub fn capacity(state_k: &[Goldilocks; 16], state_k1: &[Goldilocks; 16]) -> Capacity {
    let mut c = Capacity::default();
    c.k.copy_from_slice(&state_k[8..16]);
    c.k1.copy_from_slice(&state_k1[8..16]);
    c
}

/// The universal witness of one synthetic Poseidon2 transition
/// state_k → state_{k+1} (round index k, 0..24) — the row shape shared by
/// the Fiat-Shamir transcript replay and the BBG root chain.
pub fn poseidon_witness(state_k: &[Goldilocks; 16], state_k1: &[Goldilocks; 16], k: usize) -> CCSWitness {
    let caps = capacity(state_k, state_k1);
    universal_witness(&poseidon_regs(state_k, k), &poseidon_regs(state_k1, k + 1), Some(&caps))
}
