// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! CCS instance construction from nox execution traces.

pub mod particle;
pub mod patterns;
pub mod selector;
pub mod verifier_steps;

pub use particle::{build_hash_steps_from_trace, HashAux, Z_LEN_HASH};
pub use patterns::build_step_ccs;
pub use selector::constraint_eval;
pub use verifier_steps::{eq_step, verifier_steps};

use nebu::Goldilocks;
use nox::TraceRow;

use lens::{Commitment, Opening};

use crate::types::{CCSInstance, CCSWitness, CommitError};

/// All data the prover supplies to verify one axis opening outside the main fold.
pub struct AxisOpening {
    /// 32-byte Lens commitment to the object noun polynomial.
    pub commitment: Commitment,
    /// Evaluation point: binary decomposition of axis address as Goldilocks elements.
    pub point: Vec<Goldilocks>,
    /// Claimed polynomial value at that point.
    pub value: Goldilocks,
    /// Brakedown tensor opening proof.
    pub opening: Opening,
}

/// All data the prover supplies to verify one BBG look opening (pattern 17).
///
/// Identical structure to `AxisOpening`; kept separate so callers cannot
/// confuse axis (noun-tree) and look (BBG dimension) proofs.
pub struct LookOpening {
    /// Brakedown commitment to the BBG dimension polynomial.
    pub commitment: Commitment,
    /// Evaluation point: Goldilocks elements derived from the BBG dimension key.
    pub point: Vec<Goldilocks>,
    /// Claimed polynomial value at that point.
    pub value: Goldilocks,
    /// Brakedown tensor opening proof.
    pub opening: Opening,
    /// Four 64-bit limbs of the BBG root = H(commit(BBG_poly) ‖ A ‖ N).
    /// Limb i matches trace register: r[4]=limb0, r[11]=limb1, r[12]=limb2, r[13]=limb3.
    pub bbg_root: [Goldilocks; 4],
}

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
    for &v in row_t.r().iter() {
        z.push(Goldilocks::new(v).canonicalize());
    }
    for &v in row_t1.r().iter() {
        z.push(Goldilocks::new(v).canonicalize());
    }
    z.push(Goldilocks::ONE);
    CCSWitness { z }
}

/// Build all per-step (CCSInstance, CCSWitness) pairs from a trace.
///
/// For a trace of N rows: produces N-1 pairs (each pair covers rows t, t+1).
/// Multi-row patterns (10–15) apply their intra-block constraint only when
/// both rows carry the same tag; boundary pairs (tag changes) use trivial_ccs.
pub fn build_ccs_from_trace(trace: &[TraceRow]) -> Vec<(CCSInstance, CCSWitness)> {
    if trace.len() < 2 {
        return Vec::new();
    }
    trace.windows(2)
        .map(|w| {
            let tag_t  = u8::try_from(w[0].r()[0]).unwrap_or(255);
            let tag_t1 = u8::try_from(w[1].r()[0]).unwrap_or(255);
            let instance = if is_multi_row(tag_t) && tag_t != tag_t1 {
                patterns::trivial_ccs()
            } else {
                build_step_ccs(tag_t)
            };
            let witness = witness_from_rows(&w[0], &w[1]);
            (instance, witness)
        })
        .collect()
}

/// Returns true for patterns that emit multiple consecutive trace rows.
fn is_multi_row(tag: u8) -> bool {
    matches!(tag, 10..=15)
}

/// Build the verifier_steps() sequence for every axis row in the trace.
///
/// Scans the trace for rows with tag 0 (axis). For each, calls verifier_steps()
/// using the matching entry in `openings` (parallel slice, same order as axis
/// rows in the trace). Returns a flat Vec of (CCSInstance, CCSWitness) pairs
/// with VZ_LEN=3, ready to fold into a separate axis accumulator.
///
/// Returns `Err(CommitError::TraceOverflow)` if `openings` has fewer entries
/// than axis rows in the trace.
pub fn build_axis_steps_from_trace(
    trace: &[TraceRow],
    openings: &[AxisOpening],
) -> Result<Vec<(CCSInstance, CCSWitness)>, CommitError> {
    let mut steps = Vec::new();
    let mut opening_idx = 0;
    for row in trace {
        if row.r()[0] == 0 {
            let ao = openings.get(opening_idx).ok_or(CommitError::TraceOverflow)?;
            steps.extend(verifier_steps(&ao.commitment, &ao.point, ao.value, &ao.opening));
            opening_idx += 1;
        }
    }
    Ok(steps)
}

/// Build the verifier_steps() sequence for every look row in the trace.
///
/// Scans the trace for rows with tag 17 (look). For each, calls verifier_steps()
/// using the matching entry in `openings` (parallel slice, same order as look
/// rows in the trace). Returns a flat Vec of (CCSInstance, CCSWitness) pairs
/// with VZ_LEN=3, ready to fold into a separate look accumulator.
///
/// Returns `Err(CommitError::TraceOverflow)` if `openings` has fewer entries
/// than look rows in the trace.
pub fn build_look_steps_from_trace(
    trace: &[TraceRow],
    openings: &[LookOpening],
) -> Result<Vec<(CCSInstance, CCSWitness)>, CommitError> {
    let mut steps = Vec::new();
    let mut opening_idx = 0;
    for row in trace {
        if row.r()[0] == 17 {
            let lo = openings.get(opening_idx).ok_or(CommitError::TraceOverflow)?;
            steps.extend(verifier_steps(&lo.commitment, &lo.point, lo.value, &lo.opening));
            // bind the 4 BBG root limbs to what nox recorded in the trace
            steps.push(eq_step(lo.bbg_root[0], Goldilocks::new(row.r()[4])));
            steps.push(eq_step(lo.bbg_root[1], Goldilocks::new(row.r()[11])));
            steps.push(eq_step(lo.bbg_root[2], Goldilocks::new(row.r()[12])));
            steps.push(eq_step(lo.bbg_root[3], Goldilocks::new(row.r()[13])));
            // TODO(pattern-15): H(lo.commitment || A_commit || N_commit) == lo.bbg_root
            opening_idx += 1;
        }
    }
    Ok(steps)
}

/// Reconstruct the Lens evaluation point from an axis address stored in r[5].
///
/// The evaluation point is the binary representation of the address, one bit
/// per dimension, LSB first, as Goldilocks field elements. The address must be
/// ≥ 1 (axis(s, 0) is hash introspection, not a polynomial opening).
pub fn axis_eval_point(addr: u64) -> Vec<Goldilocks> {
    if addr <= 1 {
        return vec![];
    }
    // Strip the leading 1 bit (binary path from root uses bits below MSB).
    let bits = 63 - addr.leading_zeros();
    (0..bits)
        .map(|i| {
            if (addr >> i) & 1 == 1 { Goldilocks::ONE } else { Goldilocks::ZERO }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nox::TraceRow;
    use lens::brakedown::{Brakedown, MultilinearPoly};
    use lens::{Lens, Transcript as LensTranscript};

    #[test]
    fn witness_has_correct_length() {
        let t  = TraceRow::default();
        let t1 = TraceRow::default();
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

    #[test]
    fn axis_eval_point_addr_2_is_one_bit() {
        // addr=2 (binary 10): path uses 1 bit (the leading 1 is stripped).
        let pt = axis_eval_point(2);
        assert_eq!(pt.len(), 1);
        assert_eq!(pt[0], Goldilocks::ZERO); // bit 0 of 2 = 0
    }

    #[test]
    fn axis_eval_point_addr_3_is_one_bit() {
        // addr=3 (binary 11): 1 bit below MSB = bit 0 = 1
        let pt = axis_eval_point(3);
        assert_eq!(pt.len(), 1);
        assert_eq!(pt[0], Goldilocks::ONE);
    }

    #[test]
    fn axis_eval_point_addr_5_is_two_bits() {
        // addr=5 (binary 101): bits 0..1 below MSB = [1, 0]
        let pt = axis_eval_point(5);
        assert_eq!(pt.len(), 2);
        assert_eq!(pt[0], Goldilocks::ONE);  // bit 0
        assert_eq!(pt[1], Goldilocks::ZERO); // bit 1
    }

    #[test]
    fn axis_eval_point_addr_0_or_1_empty() {
        assert!(axis_eval_point(0).is_empty());
        assert!(axis_eval_point(1).is_empty());
    }

    #[test]
    fn build_axis_steps_from_trace_empty_trace() {
        // Empty trace → no axis rows → empty axis steps.
        let steps = build_axis_steps_from_trace(&[], &[]).unwrap();
        assert!(steps.is_empty());
    }

    #[test]
    fn build_axis_steps_produces_verifier_steps_for_each_axis_row() {
        // Build a real Brakedown commitment + opening for a 2-var polynomial.
        let poly = MultilinearPoly::new(
            [1u64, 2, 3, 4].iter().map(|&v| Goldilocks::new(v)).collect()
        );
        let commitment = Brakedown::commit(&poly);
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let value = poly.evaluate(&point);
        let opening = {
            let mut lt = LensTranscript::new(b"axis-test");
            Brakedown::open(&poly, &point, &mut lt)
        };

        // Construct a fake trace with one axis row (tag=0) and one non-axis row.
        // Tag 0 is already the default (r[0] = 0). ✓
        // All-zero trace: both rows have tag=0 → 2 axis rows.
        let _trace = vec![TraceRow::default(), TraceRow::default()];
        let ao = AxisOpening { commitment, point, value, opening };
        let openings = [ao];

        // First row tag=0 consumed; second row tag=0 would be consumed too,
        // but we only provided 1 opening — openings[1] would panic.
        // Use a single-row trace to test the 1-opening case.
        let trace_one = vec![TraceRow::default()];
        let steps = build_axis_steps_from_trace(&trace_one, &openings).unwrap();
        // verifier_steps for a 2-var opening: 4 binding + 40 stubs + 1 final = 45
        assert_eq!(steps.len(), 4 + 2 * 20 + 1);
    }
}
