//! Column layout of the recursion circuit (`specs/recursion.md` § circuit).
//!
//! Four row kinds share 49 phase-1 columns (the 50th of the word is taken
//! by the nox machine's phase 2) and 54 phase-2 columns:
//!
//! - **ARITH**: four gates `out = qm·x·(y + qs·z) + qa·x + qb·y + qc·z + qk`
//!   over Fp3 (12 columns each: x, y, z, out);
//! - **PERM** (4 rows per hemera permutation): row 0 the input `x` and the
//!   states after rounds 0, 1; row 1 after rounds 2, 3 and the 16 partial
//!   rounds' inverses; row 2 after rounds 20–22; row 3 the output, a
//!   Merkle root to compare and the next node's direction bit;
//! - **BITS** (4 rows per canonical 64-bit decomposition, 16 bits a row);
//! - padding.
//!
//! Every row has [`SLOTS`] memory slots: a slot reads or writes one value
//! at a fixed address (a preprocessed column) and its signed multiplicity
//! (`+1` a read, `−reads` a write, `0` unused) enters a logUp running sum
//! over `(address, value)` fingerprints (phase 2). Column 48 is `live`,
//! constant over the trace: 0 only in the base step, where every
//! assertion is off.

/// Phase-1 columns of the circuit.
pub const V1: usize = 49;
/// Memory slots per row.
pub const SLOTS: usize = 17;
/// Phase-2 columns: an Fp3 inverse per slot and the running sum.
pub const V2: usize = 3 * SLOTS + 3;
pub const SUM: usize = 3 * SLOTS;

/// The `live` column.
pub const LIVE: usize = 48;

// ARITH
pub const GATES: usize = 4;
pub fn gate_x(g: usize) -> usize {
    12 * g
}
pub fn gate_y(g: usize) -> usize {
    12 * g + 3
}
pub fn gate_z(g: usize) -> usize {
    12 * g + 6
}
pub fn gate_out(g: usize) -> usize {
    12 * g + 9
}

// PERM
pub const PX: usize = 0; // row 0: input
pub const PY1: usize = 16;
pub const PY2: usize = 32;
pub const PY3: usize = 0; // row 1
pub const PY4: usize = 16;
pub const PW: usize = 32;
pub const PY5: usize = 0; // row 2
pub const PY6: usize = 16;
pub const PY7: usize = 32;
pub const PY8: usize = 0; // row 3
pub const PRT: usize = 16;
pub const PBIT: usize = 20;

// BITS
pub const BITS_ROW: usize = 16;
pub const BACC: usize = 16;
pub const BVAL: usize = 17;
pub const BLO: usize = 18;
pub const BMINV: usize = 19;
pub const BMAX: usize = 20;

/// Preprocessed (public) columns.
pub mod pre {
    pub const ARITH: usize = 0;
    /// BITS phases 0..4.
    pub const BITS: usize = 1;
    /// PERM phases 0..4.
    pub const PERM: usize = 5;
    /// The row has memory slots (their inverse constraints apply).
    pub const MEM: usize = 9;
    pub const ADDR: usize = 10;
    pub const E: usize = ADDR + super::SLOTS;
    /// A slot of a PERM row 0 / row 3 covering lanes `j..j+3` as one Fp3.
    pub const WIDE: usize = E + super::SLOTS;
    pub const WIDES: usize = 7;
    pub const GATE: usize = WIDE + WIDES;
    pub const GATE_COLS: usize = 8;
    pub const QM: usize = 0;
    pub const QS: usize = 1;
    pub const QA: usize = 2;
    pub const QB: usize = 3;
    pub const QC: usize = 4;
    pub const QK: usize = 5;
    pub const QCOMP: usize = 6;
    pub const QASSERT: usize = 7;
    pub fn gate(g: usize, k: usize) -> usize {
        GATE + g * GATE_COLS + k
    }
    /// Flags on the row *before* a permutation block, describing its input.
    pub const CONT: usize = GATE + super::GATES * GATE_COLS;
    pub const FRESH: usize = CONT + 1;
    pub const TAGV: usize = CONT + 2;
    pub const NODE: usize = CONT + 3;
    pub const KEEP: usize = CONT + 4;
    pub const ZERO: usize = KEEP + super::super::super::perm::RATE;
    pub const ROOTCHK: usize = ZERO + super::super::super::perm::RATE;
    /// The row whose output (lanes 0..4) is the step's public input.
    pub const OUT: usize = ROOTCHK + 1;
    pub const COUNT: usize = OUT + 1;
    /// `log2` of the padded count (the column variables of the public claim).
    pub const LOG: usize = 7;
}

/// Public-input columns (the step's state digest at the `OUT` row).
pub const PIN: usize = 4;

const _: () = assert!(pre::COUNT <= 1 << pre::LOG);
const _: () = assert!(V2 <= 64);
