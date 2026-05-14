// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! CCS instance construction from nox execution traces.

pub mod patterns;
pub mod selector;
pub mod verifier_steps;

pub use patterns::build_step_ccs;
pub use selector::constraint_eval;
pub use verifier_steps::{eq_step, verifier_steps};

use nebu::Goldilocks;
use nox::TraceRow;

use crate::types::{CCSInstance, CCSWitness};

/// z-index of register r at row t.
pub const fn reg_t(r: usize) -> usize { r }

/// z-index of register r at row t+1.
pub const fn reg_t1(r: usize) -> usize { r + 16 }

/// z-index of the constant 1.
pub const CONST_IDX: usize = 32;

/// Length of the witness vector z (before padding).
pub const Z_LEN: usize = 33;

/// Build a one-row sparse matrix that selects z[col] with coefficient 1.
pub fn select_matrix(col: usize) -> crate::types::SparseMatrix {
    let mut m = crate::types::SparseMatrix::new(1, Z_LEN);
    m.set(0, col, Goldilocks::ONE);
    m
}

/// Build z from two consecutive trace rows.
///
/// z = [r0_t, ..., r15_t, r0_{t+1}, ..., r15_{t+1}, 1]  (33 elements)
pub fn witness_from_rows(row_t: &TraceRow, row_t1: &TraceRow) -> CCSWitness {
    let mut z = Vec::with_capacity(Z_LEN);
    for &v in row_t.r.iter() {
        z.push(Goldilocks::new(v).canonicalize());
    }
    for &v in row_t1.r.iter() {
        z.push(Goldilocks::new(v).canonicalize());
    }
    z.push(Goldilocks::ONE);
    CCSWitness { z }
}

/// Build all per-step (CCSInstance, CCSWitness) pairs from a trace.
///
/// For a trace of N rows: produces N-1 pairs (each pair covers rows t, t+1).
pub fn build_ccs_from_trace(trace: &[TraceRow]) -> Vec<(CCSInstance, CCSWitness)> {
    if trace.len() < 2 {
        return Vec::new();
    }
    trace.windows(2)
        .map(|w| {
            let pattern_tag = w[0].r[0] as u8;
            let instance = build_step_ccs(pattern_tag);
            let witness = witness_from_rows(&w[0], &w[1]);
            (instance, witness)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox::TraceRow;

    fn row(r: [u64; 16]) -> TraceRow {
        TraceRow { r }
    }

    #[test]
    fn witness_has_correct_length() {
        let mut r = [0u64; 16];
        let t = row(r);
        r[0] = 1;
        let t1 = row(r);
        let w = witness_from_rows(&t, &t1);
        assert_eq!(w.z.len(), Z_LEN);
        assert_eq!(w.z[Z_LEN - 1], Goldilocks::ONE);
    }

    #[test]
    fn build_from_two_row_trace_gives_one_step() {
        let rows = vec![TraceRow::default(), TraceRow::default()];
        let steps = build_ccs_from_trace(&rows);
        assert_eq!(steps.len(), 1);
    }
}
