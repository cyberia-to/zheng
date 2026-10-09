//! Column layout, row kinds, table tags and costs of the nox machine
//! (`specs/machine.md` § layout). One row is 64 phase-1 columns; columns
//! are shared between row kinds, every constraint is gated by the kind (or
//! by a public phase column in the permutation region).

/// Phase-1 columns.
pub const W1: usize = 64;

// ── row kinds (one-hot, boolean) ─────────────────────────────────────
pub const K_INIT: usize = 0;
pub const K_EVAL: usize = 1;
pub const K_RET: usize = 2;
/// Auxiliary machine rows; the sub-kind is a one-hot flag (`S_*`).
pub const K_AUX: usize = 3;
/// Axis walk: one level per row, most significant path bit first.
pub const K_AXW: usize = 4;
pub const K_HDA: usize = 5;
pub const K_HDB: usize = 6;
pub const K_EQD: usize = 7;
pub const K_PERM: usize = 8;
pub const K_PAD: usize = 9;
pub const KINDS: usize = 10;
/// Kinds that belong to the machine's control flow.
pub const MACHINE: [usize; 7] = [K_EVAL, K_RET, K_AUX, K_AXW, K_HDA, K_HDB, K_EQD];

// ── machine state ────────────────────────────────────────────────────
pub const OBJ: usize = 10;
/// Formula (EVAL), value (RET, EQD), path prefix (AXW), operand (WBIT).
pub const X: usize = 11;
/// Continuation: id of the top frame, 0 = empty.
pub const K: usize = 12;
pub const D: usize = 13;
pub const CYC: usize = 14;
pub const ALLOC: usize = 15;

// ── flags 16..31: EVAL opcodes / RET frame kinds / AUX sub-kinds / PERM jobs
pub const FLAG0: usize = 16;
pub const FLAGS: usize = 16;

/// EVAL opcode flags (offset from `FLAG0`), with the nox tag and cost.
/// `OP_WORD` covers xor, and, shl (tags 11, 12, 14; cost 32): its tag is
/// the formula's own tag atom, restricted to those three.
pub const OPS: [(usize, u64, u64); 15] = [
    (0, 0, 1),    // axis
    (1, 1, 1),    // quote
    (2, 2, 1),    // compose
    (3, 3, 1),    // cons
    (4, 4, 1),    // branch
    (5, 5, 1),    // add
    (6, 6, 1),    // sub
    (7, 7, 1),    // mul
    (8, 8, 64),   // inv
    (9, 9, 1),    // eq
    (10, 15, 25), // hash
    (11, 10, 64), // lt
    (13, 13, 32), // not
    (14, 16, 1),  // call
    (15, 17, 1),  // look
];
pub const OP_AXIS: usize = FLAG0;
pub const OP_QUOTE: usize = FLAG0 + 1;
pub const OP_COMPOSE: usize = FLAG0 + 2;
pub const OP_CONS: usize = FLAG0 + 3;
pub const OP_BRANCH: usize = FLAG0 + 4;
pub const OP_ADD: usize = FLAG0 + 5;
pub const OP_SUB: usize = FLAG0 + 6;
pub const OP_MUL: usize = FLAG0 + 7;
pub const OP_INV: usize = FLAG0 + 8;
pub const OP_EQ: usize = FLAG0 + 9;
pub const OP_HASH: usize = FLAG0 + 10;
pub const OP_LT: usize = FLAG0 + 11;
pub const OP_WORD: usize = FLAG0 + 12;
pub const OP_NOT: usize = FLAG0 + 13;
pub const OP_CALL: usize = FLAG0 + 14;
pub const OP_LOOK: usize = FLAG0 + 15;
/// The tags `OP_WORD` admits, and its cost.
pub const WORD_TAGS: [u64; 3] = [11, 12, 14];
pub const WORD_COST: u64 = 32;
/// nox tags of the word and comparison opcodes.
pub const T_LT: u64 = 10;
pub const T_XOR: u64 = 11;
pub const T_AND: u64 = 12;
pub const T_NOT: u64 = 13;
pub const T_SHL: u64 = 14;
pub const T_EQ: u64 = 9;
pub const T_LOOK: u64 = 17;

/// RET frame-kind flags.
pub const F_CONS1: usize = FLAG0;
pub const F_CONS2: usize = FLAG0 + 1;
pub const F_COMP1: usize = FLAG0 + 2;
pub const F_COMP2: usize = FLAG0 + 3;
pub const F_BR: usize = FLAG0 + 4;
/// First operand of a binary opcode returned: the frame is `B1(op)`.
pub const F_B1: usize = FLAG0 + 5;
/// add / sub / mul: the frame is `B2(op)`, `op ∈ {5, 6, 7}`.
pub const F_B2AR: usize = FLAG0 + 6;
pub const F_B2EQ: usize = FLAG0 + 7;
pub const F_UHASH: usize = FLAG0 + 8;
pub const F_UINV: usize = FLAG0 + 9;
pub const F_TERM: usize = FLAG0 + 10;
/// lt / xor / and / not / shl: the frame is `B2(op)`; WBIT rows follow.
pub const F_B2W: usize = FLAG0 + 11;
pub const F_CALL1: usize = FLAG0 + 12;
pub const F_CALL2: usize = FLAG0 + 13;
pub const F_B2LOOK: usize = FLAG0 + 14;
/// RET flags in use (flag 15 is never set on a RET row).
pub const RET_FLAGS: usize = 15;

// ── memory slots 32..55: 4 × (KEY, P0, P1, P2, P3, M) ─────────────────
pub const SLOT0: usize = 32;
pub const SLOTS: usize = 4;
pub const SLOT_W: usize = 6;
pub const fn slot(s: usize, field: usize) -> usize {
    SLOT0 + s * SLOT_W + field
}
pub const KEY: usize = 0;
pub const P0: usize = 1;
pub const M: usize = 5;

// ── witnesses 56..63 ─────────────────────────────────────────────────
pub const WIT: usize = 56;
// EVAL
pub const E_DINV: usize = WIT; // (D − 1001)·DINV = 1
pub const E_A0INV: usize = WIT + 1; // axis: a·A0INV = 1 − IS0
pub const E_A1INV: usize = WIT + 2; // axis: (a − 1)·A1INV = 1 − IS1
pub const E_IS0: usize = WIT + 3;
pub const E_IS1: usize = WIT + 4;
// RET BR
pub const R_TINV: usize = WIT; // tv·TINV = 1 − Z
pub const R_Z: usize = WIT + 1;
// RET B2AR: one-hot add / sub / mul
pub const R_SADD: usize = WIT;
pub const R_SSUB: usize = WIT + 1;
pub const R_SMUL: usize = WIT + 2;
/// RET B1 / B2AR / B2W: the frame's nox opcode (authenticated by the
/// frame's tag `TAG_B1 + op` / `TAG_B2 + op`).
pub const R_OP: usize = WIT + 7;
/// RET B1: `(op − 5)(op − 6)(op − 7)(op − 9)(op − 10)`, the first factor
/// of the restriction of `op` to the B1 opcodes (degree split).
pub const R_OPY: usize = WIT + 6;
/// The opcodes whose frames are B1 frames: add, sub, mul, eq, lt, xor,
/// and, shl, look.
pub const B1_OPS: [u64; 9] = [5, 6, 7, 9, 10, 11, 12, 14, 17];
// RET B2EQ / EQD
pub const Q_KA: usize = WIT; // 1: operand atom
pub const Q_KB: usize = WIT + 1;
pub const Q_EINV: usize = WIT + 2; // atoms: (u − w)·EINV = 1 − IS_EQ
pub const Q_ISEQ: usize = WIT + 3;
pub const Q_DW: usize = WIT + 4; // EQD: Σ diff_k·DW_k = 1 − IS_EQ (4 columns 60..63)
// AXW: OBJ node, X path prefix, D target address
pub const A_BIT: usize = WIT;
pub const A_CNT: usize = WIT + 1;
pub const A_C63: usize = WIT + 2; // (CNT − 63)·C63 = 1
pub const A_PH: usize = WIT + 3; // 1 on steps 0..=30
pub const A_AH: usize = WIT + 4; // AND of the bits of steps 0..=30 so far
pub const A_OL: usize = WIT + 5; // OR of the bits of steps 31.. so far
pub const A_E30: usize = WIT + 6; // [CNT = 30]
pub const A_I30: usize = WIT + 7;
pub const A_E62: usize = FLAG0; // [CNT = 62]
pub const A_I62: usize = FLAG0 + 1;
/// Longest axis path (levels below the root): addresses `< 2^64`.
pub const AXIS_LEVELS: u64 = 63;

// ── AUX rows: sub-kind flags ──────────────────────────────────────────
/// look: the subject's root noun against the statement, the value atom.
pub const S_LOOK: usize = FLAG0;
/// call witness: one atom, one pair (post-order, a stack of cells), the
/// join that pairs the witness with the subject.
pub const S_WATOM: usize = FLAG0 + 1;
pub const S_WPAIR: usize = FLAG0 + 2;
pub const S_WJOIN: usize = FLAG0 + 3;
/// one bit position of a word / comparison opcode (32 rows).
pub const S_WBIT: usize = FLAG0 + 4;
pub const SUBKINDS: [usize; 5] = [S_LOOK, S_WATOM, S_WPAIR, S_WJOIN, S_WBIT];
/// Witness stack pointer (witness rows).
pub const W_SP: usize = FLAG0 + 15;
// WBIT rows: opcode flags (constant over the 32 rows), counter
pub const B_XOR: usize = FLAG0 + 5;
pub const B_AND: usize = FLAG0 + 6;
pub const B_NOT: usize = FLAG0 + 7;
pub const B_SHL: usize = FLAG0 + 8;
pub const B_LT: usize = FLAG0 + 9;
pub const WOPS: [(usize, u64); 5] = [(B_XOR, T_XOR), (B_AND, T_AND), (B_NOT, T_NOT), (B_SHL, T_SHL), (B_LT, T_LT)];
pub const B_CNT: usize = FLAG0 + 10;
pub const B_LINV: usize = FLAG0 + 11; // (CNT − 31)·LINV = 1 − LAST
pub const B_LAST: usize = FLAG0 + 12;
pub const B_FINV: usize = FLAG0 + 13; // CNT·FINV = 1 − FIRST
pub const B_FIRST: usize = FLAG0 + 14;
/// WBIT data columns `G(i)` (the slot area is unused on WBIT rows).
pub const fn wg(i: usize) -> usize {
    SLOT0 + i
}
// remainders peeled one bit per row: xor/and/not/shl (A, B, C, H),
// lt (A lo, B lo, A hi, B hi); their bits
pub const G_R0: usize = wg(0);
pub const G_R1: usize = wg(1);
pub const G_R2: usize = wg(2);
pub const G_R3: usize = wg(3);
pub const G_B0: usize = wg(4);
pub const G_B1: usize = wg(5);
pub const G_B2: usize = wg(6);
pub const G_B3: usize = wg(7);
// shl
pub const G_P: usize = wg(8); // 2^(n mod 32) under construction
pub const G_Q: usize = wg(9); // 2^(2^CNT)
pub const G_I5: usize = wg(10); // [CNT = 5]
pub const G_V5: usize = wg(11);
pub const G_Z: usize = wg(12); // [n < 32]
pub const G_ZI: usize = wg(13);
pub const G_CI: usize = wg(14); // c' = (u·2^n) mod 2^32
pub const G_HI: usize = wg(15); // 2·⌊u·2^n / 2^32⌋
// lt: running canonical checks and comparisons (current, after this row)
pub const G_NA: usize = wg(8);
pub const G_OA: usize = wg(9);
pub const G_NB: usize = wg(10);
pub const G_OB: usize = wg(11);
pub const G_NA2: usize = wg(12);
pub const G_OA2: usize = wg(13);
pub const G_NB2: usize = wg(14);
pub const G_OB2: usize = wg(15);
pub const G_LL: usize = wg(16);
pub const G_LH: usize = wg(17);
pub const G_EH: usize = wg(18);
pub const G_LL2: usize = wg(19);
pub const G_LH2: usize = wg(20);
pub const G_EH2: usize = wg(21);

// ── permutation region (rows ≥ the region start, 32-row blocks) ───────
pub const JOB_ID: usize = OBJ;
pub const STATE: usize = X; // 16 columns 11..26
pub const PINV: usize = 27;
pub const J_PAIR: usize = 28;
pub const J_ATOM1: usize = 29;
pub const J_ATOM2: usize = 30;
pub const J_HOP: usize = 31;
/// Bits rows of an atom job (phases 0, 1).
pub const B_LO: usize = 11;
pub const B_HL: usize = 12;
pub const B_HT: usize = 13;
pub const B_MINV: usize = 14;
pub const B_MAX: usize = 15;
pub const B_LOC: usize = 16;
pub const B_BITS: usize = 32; // 32 columns 32..63

pub const BLOCK: usize = 32;
pub const PH_BITS0: usize = 0;
pub const PH_BITS1: usize = 1;
pub const PH_MDS: usize = 2;
pub const PH_ROUND0: usize = 3; // rounds 0..23 at phases 3..26
pub const PH_OUT: usize = 27;

// ── memory tags ──────────────────────────────────────────────────────
pub const TAG_ATOM: u64 = 1;
pub const TAG_PAIR: u64 = 2;
pub const TAG_DIG: u64 = 3;
pub const TAG_HOP: u64 = 4;
pub const TAG_ABASE: u64 = 5;
/// An authenticated state read `(id; namespace, key, value)` (init only).
pub const TAG_STATE: u64 = 6;
/// A call-witness stack cell `(id; top, next)`.
pub const TAG_SCELL: u64 = 7;
pub const TAG_CONS1: u64 = 16;
pub const TAG_CONS2: u64 = 17;
pub const TAG_COMP1: u64 = 18;
pub const TAG_COMP2: u64 = 19;
pub const TAG_BR: u64 = 20;
pub const TAG_UHASH: u64 = 29;
pub const TAG_UINV: u64 = 30;
pub const TAG_CALL1: u64 = 31;
pub const TAG_CALL2: u64 = 32;
/// Binary-opcode frames: `TAG_B1 + op` after the first operand is due,
/// `TAG_B2 + op` after the second (op = the nox tag, ≤ 17).
pub const TAG_B1: u64 = 64;
pub const TAG_B2: u64 = 96;

/// Frame tag of each fixed-tag RET frame flag (`F_TERM` has none; B1,
/// B2AR and B2W carry `TAG_B1/2 + R_OP`, B2EQ and B2LOOK a fixed op).
pub const FRAME_TAGS: [(usize, u64); 11] = [
    (F_CONS1, TAG_CONS1),
    (F_CONS2, TAG_CONS2),
    (F_COMP1, TAG_COMP1),
    (F_COMP2, TAG_COMP2),
    (F_BR, TAG_BR),
    (F_UHASH, TAG_UHASH),
    (F_UINV, TAG_UINV),
    (F_CALL1, TAG_CALL1),
    (F_CALL2, TAG_CALL2),
    (F_B2EQ, TAG_B2 + T_EQ),
    (F_B2LOOK, TAG_B2 + T_LOOK),
];

/// Native depth limit (`nox::reduce`'s `MAX_DEPTH`): an evaluation at
/// depth `D > 1000` is a `Malformed` error.
pub const MAX_DEPTH: u64 = 1000;

/// Phase-2 columns: four slot inverses (Fp3) and the running sum (Fp3).
pub const W2: usize = 15;
pub const H0: usize = 0;
pub const SUM: usize = 12;
