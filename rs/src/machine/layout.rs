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
pub const K_AX1: usize = 3;
pub const K_AX2: usize = 4;
pub const K_HDA: usize = 5;
pub const K_HDB: usize = 6;
pub const K_EQD: usize = 7;
pub const K_PERM: usize = 8;
pub const K_PAD: usize = 9;
pub const KINDS: usize = 10;
/// Kinds that belong to the machine's control flow.
pub const MACHINE: [usize; 7] = [K_EVAL, K_RET, K_AX1, K_AX2, K_HDA, K_HDB, K_EQD];

// ── machine state ────────────────────────────────────────────────────
pub const OBJ: usize = 10;
/// Formula (EVAL), value (RET, EQD), remaining address (AX1), reversed
/// path (AX2).
pub const X: usize = 11;
/// Continuation: id of the top frame, 0 = empty.
pub const K: usize = 12;
pub const D: usize = 13;
pub const CYC: usize = 14;
pub const ALLOC: usize = 15;

// ── flags 16..31: EVAL opcodes / RET frame kinds / PERM jobs ─────────
pub const FLAG0: usize = 16;
pub const FLAGS: usize = 16;

/// EVAL opcode flags (offset from `FLAG0`), with the nox tag and cost.
pub const OPS: [(usize, u64, u64); 11] = [
    (0, 0, 1),   // axis
    (1, 1, 1),   // quote
    (2, 2, 1),   // compose
    (3, 3, 1),   // cons
    (4, 4, 1),   // branch
    (5, 5, 1),   // add
    (6, 6, 1),   // sub
    (7, 7, 1),   // mul
    (8, 8, 64),  // inv
    (9, 9, 1),   // eq
    (10, 15, 25), // hash
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

/// RET frame-kind flags.
pub const F_CONS1: usize = FLAG0;
pub const F_CONS2: usize = FLAG0 + 1;
pub const F_COMP1: usize = FLAG0 + 2;
pub const F_COMP2: usize = FLAG0 + 3;
pub const F_BR: usize = FLAG0 + 4;
pub const F_B1ADD: usize = FLAG0 + 5;
pub const F_B1SUB: usize = FLAG0 + 6;
pub const F_B1MUL: usize = FLAG0 + 7;
pub const F_B1EQ: usize = FLAG0 + 8;
pub const F_B2ADD: usize = FLAG0 + 9;
pub const F_B2SUB: usize = FLAG0 + 10;
pub const F_B2MUL: usize = FLAG0 + 11;
pub const F_B2EQ: usize = FLAG0 + 12;
pub const F_UHASH: usize = FLAG0 + 13;
pub const F_UINV: usize = FLAG0 + 14;
pub const F_TERM: usize = FLAG0 + 15;

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
// RET B2EQ / EQD
pub const Q_KA: usize = WIT; // 1: operand atom
pub const Q_KB: usize = WIT + 1;
pub const Q_EINV: usize = WIT + 2; // atoms: (u − w)·EINV = 1 − IS_EQ
pub const Q_ISEQ: usize = WIT + 3;
pub const Q_DW: usize = WIT + 4; // EQD: Σ diff_k·DW_k = 1 − IS_EQ (4 columns 60..63)
// AX1 / AX2
pub const A_R: usize = WIT; // AX1: reversed path under construction
pub const A_CNT: usize = WIT + 1;
pub const A_CINV: usize = WIT + 2; // (CNT − 31)·CINV = 1
pub const A_BIT: usize = WIT + 3;

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
pub const TAG_CONS1: u64 = 16;
pub const TAG_CONS2: u64 = 17;
pub const TAG_COMP1: u64 = 18;
pub const TAG_COMP2: u64 = 19;
pub const TAG_BR: u64 = 20;
pub const TAG_B1ADD: u64 = 21;
pub const TAG_B1SUB: u64 = 22;
pub const TAG_B1MUL: u64 = 23;
pub const TAG_B1EQ: u64 = 24;
pub const TAG_B2ADD: u64 = 25;
pub const TAG_B2SUB: u64 = 26;
pub const TAG_B2MUL: u64 = 27;
pub const TAG_B2EQ: u64 = 28;
pub const TAG_UHASH: u64 = 29;
pub const TAG_UINV: u64 = 30;

/// Frame tag of each RET frame flag (`F_TERM` has none).
pub const FRAME_TAGS: [(usize, u64); 15] = [
    (F_CONS1, TAG_CONS1),
    (F_CONS2, TAG_CONS2),
    (F_COMP1, TAG_COMP1),
    (F_COMP2, TAG_COMP2),
    (F_BR, TAG_BR),
    (F_B1ADD, TAG_B1ADD),
    (F_B1SUB, TAG_B1SUB),
    (F_B1MUL, TAG_B1MUL),
    (F_B1EQ, TAG_B1EQ),
    (F_B2ADD, TAG_B2ADD),
    (F_B2SUB, TAG_B2SUB),
    (F_B2MUL, TAG_B2MUL),
    (F_B2EQ, TAG_B2EQ),
    (F_UHASH, TAG_UHASH),
    (F_UINV, TAG_UINV),
];

/// Native depth limit (`nox::reduce`'s `MAX_DEPTH`): an evaluation at
/// depth `D > 1000` is a `Malformed` error.
pub const MAX_DEPTH: u64 = 1000;
/// Axis addresses below `2^32` (at most 31 navigation levels) only.
pub const AXIS_LEVELS: u64 = 31;

/// Phase-2 columns: four slot inverses (Fp3) and the running sum (Fp3).
pub const W2: usize = 15;
pub const H0: usize = 0;
pub const SUM: usize = 12;
