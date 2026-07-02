// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! CCS instance construction from nox execution traces.

pub mod particle;
pub mod patterns;
pub mod selector;
pub mod transcript;
pub mod verifier_steps;

pub use particle::{build_hash_steps_from_trace, HashAux, Z_LEN_HASH};
pub use patterns::build_step_ccs;
pub use selector::constraint_eval;
pub use transcript::build_transcript_steps;
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
    /// Bytes passed to `LensTranscript::new()` when `Brakedown::open` was called.
    pub transcript_seed: Vec<u8>,
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
    /// Bytes passed to `LensTranscript::new()` when `Brakedown::open` was called.
    pub transcript_seed: Vec<u8>,
    /// Four 64-bit limbs of the BBG root = H(commit(BBG_poly) ‖ A ‖ N).
    /// Limb i matches trace register: r[4]=limb0, r[11]=limb1, r[12]=limb2, r[13]=limb3.
    pub bbg_root: [Goldilocks; 4],
    /// BBG namespace for this opening (N in the root hash).
    pub namespace: Goldilocks,
    /// BBG accumulator commitment (A in the root hash). None until BBG design is settled.
    pub a_commit: Option<[Goldilocks; 4]>,
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

/// Build Poseidon2 CCS pairs for the Fiat-Shamir transcript of every axis opening.
///
/// For each axis row in the trace, produces num_vars × 20 × 24 pairs encoding
/// the Poseidon2 permutations inside the Brakedown proximity protocol.
///
/// Returns `Err(CommitError::TraceOverflow)` if `openings` has fewer entries
/// than axis rows in the trace.
pub fn build_axis_transcript_steps(
    trace: &[TraceRow],
    openings: &[AxisOpening],
) -> Result<Vec<(CCSInstance, CCSWitness)>, CommitError> {
    let mut steps = Vec::new();
    let mut opening_idx = 0;
    for row in trace {
        if row.r()[0] == 0 {
            let ao = openings.get(opening_idx).ok_or(CommitError::TraceOverflow)?;
            steps.extend(build_transcript_steps(
                &ao.transcript_seed, &ao.commitment, &ao.opening,
            ));
            opening_idx += 1;
        }
    }
    Ok(steps)
}

/// Build Poseidon2 CCS pairs for the Fiat-Shamir transcript of every look opening.
///
/// For each look row in the trace, produces num_vars × 20 × 24 pairs encoding
/// the Poseidon2 permutations inside the Brakedown proximity protocol.
///
/// Returns `Err(CommitError::TraceOverflow)` if `openings` has fewer entries
/// than look rows in the trace.
pub fn build_look_transcript_steps(
    trace: &[TraceRow],
    openings: &[LookOpening],
) -> Result<Vec<(CCSInstance, CCSWitness)>, CommitError> {
    let mut steps = Vec::new();
    let mut opening_idx = 0;
    for row in trace {
        if row.r()[0] == 17 {
            let lo = openings.get(opening_idx).ok_or(CommitError::TraceOverflow)?;
            steps.extend(build_transcript_steps(
                &lo.transcript_seed, &lo.commitment, &lo.opening,
            ));
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

/// Convert a `BrakedownLookProvider`'s recorded openings into zheng `LookOpening` structs.
///
/// Call after `nox::reduce()` and before `zheng::commit()`. Drains all accumulated
/// openings from the provider (subsequent calls return empty).
///
/// For each recorded `(namespace, key, value)`:
/// - Decomposes `key` (direct index into `poly.evals`) into the MSB-first
///   multilinear evaluation point over {0,1}^k.
/// - Generates a Brakedown tensor opening proof.
/// - Extracts the 4-limb BBG root from the commitment bytes, matching the
///   limbs written into trace registers r[4], r[11], r[12], r[13] by look.rs.
pub fn look_openings_from_provider(
    provider: &nox::BrakedownLookProvider,
) -> Vec<LookOpening> {
    use lens::brakedown::Brakedown;
    use lens::{Lens, Transcript as LensTranscript};

    let poly = provider.poly();
    let commitment = *provider.commitment();
    let nox_openings = provider.drain_openings();

    let k = poly.evals.len().trailing_zeros() as usize;

    let cb = commitment.as_bytes();
    let bbg_root = [
        look_commitment_limb(cb, 0),
        look_commitment_limb(cb, 1),
        look_commitment_limb(cb, 2),
        look_commitment_limb(cb, 3),
    ];

    nox_openings.into_iter().map(|nox_op| {
        let idx = nox_op.key.as_u64() as usize;
        // LSB-first binary decomposition: point[j] = bit j of idx.
        // Brakedown folds pairs (evals[2i], evals[2i+1]) using bit 0 first —
        // same convention as axis_eval_point and lens/brakedown opening.
        let point: Vec<Goldilocks> = (0..k)
            .map(|j| {
                if (idx >> j) & 1 == 1 { Goldilocks::ONE } else { Goldilocks::ZERO }
            })
            .collect();
        // Deterministic transcript seed per (commitment, namespace, key): prevents
        // Fiat-Shamir reuse across different openings of the same polynomial.
        let seed = {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&nox_op.key.as_u64().to_le_bytes());
            s[8..16].copy_from_slice(&nox_op.namespace.as_u64().to_le_bytes());
            s[16..].copy_from_slice(&cb[0..16]);
            s
        };
        let mut lt = LensTranscript::new(&seed);
        let opening = Brakedown::open(poly, &point, &mut lt);

        LookOpening {
            commitment,
            point,
            value: nox_op.value,
            opening,
            transcript_seed: seed.to_vec(),
            bbg_root,
            namespace: nox_op.namespace,
            a_commit: None,
        }
    }).collect()
}

fn look_commitment_limb(bytes: &[u8], k: usize) -> Goldilocks {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[k * 8..k * 8 + 8]);
    Goldilocks::new(u64::from_le_bytes(buf))
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
        let ao = AxisOpening {
            commitment, point, value, opening,
            transcript_seed: b"axis-test".to_vec(),
        };
        let openings = [ao];

        // Use a single-row trace to test the 1-opening case.
        let trace_one = vec![TraceRow::default()];
        let steps = build_axis_steps_from_trace(&trace_one, &openings).unwrap();
        // verifier_steps for a 2-var opening: 4 binding + 1 final = 5
        assert_eq!(steps.len(), 5);
    }

    #[test]
    fn look_openings_from_provider_correct_value_and_count() {
        use nox::{BrakedownLookProvider, LookProvider};
        use lens::brakedown::MultilinearPoly;
        use crate::ccs::selector::is_satisfied;

        // 4-element polynomial: evals[0..3] = 10, 20, 30, 40
        let evals: Vec<Goldilocks> = [10u64, 20, 30, 40].iter().map(|&v| Goldilocks::new(v)).collect();
        let provider = BrakedownLookProvider::new(MultilinearPoly::new(evals));

        // Simulate two look calls (key=0 and key=2)
        let _ = provider.look(provider.commitment_field(), Goldilocks::ZERO, Goldilocks::new(0));
        let _ = provider.look(provider.commitment_field(), Goldilocks::ZERO, Goldilocks::new(2));

        let openings = look_openings_from_provider(&provider);
        assert_eq!(openings.len(), 2);

        // key=0 → value=10, LSB-first point=[0,0]
        assert_eq!(openings[0].value, Goldilocks::new(10));
        assert_eq!(openings[0].point, vec![Goldilocks::ZERO, Goldilocks::ZERO]);

        // key=2 (binary 10) → value=30, LSB-first point=[0,1] (bit0=0, bit1=1)
        assert_eq!(openings[1].value, Goldilocks::new(30));
        assert_eq!(openings[1].point, vec![Goldilocks::ZERO, Goldilocks::ONE]);

        // bbg_root limb 0 matches commitment_field
        assert_eq!(openings[0].bbg_root[0], provider.commitment_field());

        // All verifier steps must be satisfied for both openings
        for lo in &openings {
            let steps = verifier_steps(&lo.commitment, &lo.point, lo.value, &lo.opening);
            for (i, (inst, wit)) in steps.iter().enumerate() {
                assert!(is_satisfied(inst, wit), "opening step {i} not satisfied");
            }
        }

        // Second call returns empty (provider was drained)
        assert!(look_openings_from_provider(&provider).is_empty());
    }
}
