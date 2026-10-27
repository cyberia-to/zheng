// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Poseidon2 squeeze-row primitives and legacy Tensor transcript replay.
//!
//! The fixed-query legacy replay is not the current Lens systematic-v2
//! transcript and does not authenticate an opening. `TensorMerkle` is explicitly
//! unsupported here; the public trace commit API refuses recursive openings.

use nebu::Goldilocks;

use hemera::{Hasher, ROUNDS_TOTAL};
use hemera::field::Goldilocks as HGoldilocks;
use hemera::trace::{FullRoundWitnesses, RoundVisitor};

use lens::{Commitment, Opening};

use crate::ccs::universal::poseidon_witness;
use crate::types::CCSWitness;

/// Historical Tensor transcript query count; not the current Lens parameter.
const NUM_QUERIES: usize = 20;

/// Replay the historical Tensor transcript into universal squeeze rows.
///
/// For a `k`-variable opening, produces `k × 20 × 24` rows:
/// - 24 rows per squeeze (one per Poseidon2 round)
/// - 20 squeezes per Brakedown folding round
/// - `k` folding rounds
///
/// This historical data sequence is deterministic from `opening.round_commitments`.
/// It must not be used to claim verification of a current `Brakedown::open` result.
///
/// Returns empty vec if `opening` is not `Opening::Tensor`.
pub fn build_transcript_steps(
    transcript_seed: &[u8],
    commitment: &Commitment,
    opening: &Opening,
) -> Vec<CCSWitness> {
    let Opening::Tensor { round_commitments, .. } = opening else {
        return vec![];
    };

    let total = round_commitments.len() * NUM_QUERIES * ROUNDS_TOTAL;
    let mut steps = Vec::with_capacity(total);

    // Replay verifier transcript: new hasher seeded with domain, then absorb commitment.
    let mut hasher = Hasher::new();
    hasher.update(transcript_seed);
    hasher.update(commitment.as_bytes());

    for rc in round_commitments {
        hasher.update(rc.as_bytes());

        for _ in 0..NUM_QUERIES {
            // Clone hasher before squeeze to record per-round states.
            let snap = hasher.clone();
            let mut visitor = SqueezeVisitor::new();
            snap.finalize_traced(&mut visitor);

            steps.extend(squeeze_rows(&visitor));

            // Advance transcript: finalize + re-seed (mirroring Transcript::squeeze).
            let hash = hasher.finalize();
            hasher = Hasher::new();
            hasher.update(hash.as_bytes());
        }
    }

    steps
}

/// The 24 universal rows of one Poseidon2 permutation: transition k → k+1
/// for k = 0..23, the last pair closing on the final state (round index 24
/// is the squeeze sentinel, as in a trace hash block).
pub(crate) fn squeeze_rows(visitor: &SqueezeVisitor) -> Vec<CCSWitness> {
    let states = &visitor.states;
    (0..ROUNDS_TOTAL)
        .map(|k| {
            let next = if k + 1 < ROUNDS_TOTAL { &states[k + 1] } else { &states[ROUNDS_TOTAL - 1] };
            poseidon_witness(&states[k], next, k)
        })
        .collect()
}

/// Collects post-round states from a Poseidon2 permutation.
pub(crate) struct SqueezeVisitor {
    states: Vec<[Goldilocks; 16]>,
}

impl SqueezeVisitor {
    pub(crate) fn new() -> Self {
        Self { states: Vec::with_capacity(ROUNDS_TOTAL) }
    }
}

fn hstate(s: &[HGoldilocks; 16]) -> [Goldilocks; 16] {
    core::array::from_fn(|i| Goldilocks::new(s[i].as_canonical_u64()))
}

impl RoundVisitor for SqueezeVisitor {
    fn full_round(&mut self, _index: u8, state: &[HGoldilocks; 16], _witnesses: &FullRoundWitnesses) {
        self.states.push(hstate(state));
    }

    fn partial_round(&mut self, _index: u8, state: &[HGoldilocks; 16], _sbox_out: HGoldilocks) {
        self.states.push(hstate(state));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::selector::is_satisfied;
    use crate::ccs::universal::universal_ccs;
    use lens::brakedown::{Brakedown, MultilinearPoly};
    use lens::{Lens, Transcript as LensTranscript};

    fn g(v: u64) -> Goldilocks { Goldilocks::new(v) }

    fn small_poly() -> MultilinearPoly<Goldilocks> {
        MultilinearPoly::new(vec![g(1), g(2), g(3), g(4)])
    }

    fn open_at(poly: &MultilinearPoly<Goldilocks>, point: &[Goldilocks]) -> (Commitment, Opening) {
        let commitment = Brakedown::commit(poly);
        let mut lt = LensTranscript::new(b"transcript-steps-test");
        let opening = Brakedown::open(poly, point, &mut lt);
        (commitment, opening)
    }

    #[test]
    fn a_real_poseidon_squeeze_produces_satisfied_universal_rows() {
        let mut hasher = Hasher::new();
        hasher.update(b"real squeeze primitive regression");
        let mut visitor = SqueezeVisitor::new();
        hasher.finalize_traced(&mut visitor);
        let rows = squeeze_rows(&visitor);
        assert_eq!(rows.len(), ROUNDS_TOTAL);
        for (i, witness) in rows.iter().enumerate() {
            assert!(is_satisfied(universal_ccs(), witness), "squeeze row {i}");
        }
    }

    #[test]
    fn current_authenticated_opening_has_no_legacy_transcript_rows() {
        let poly = small_poly();
        let point = vec![Goldilocks::ZERO, Goldilocks::ONE];
        let (commitment, opening) = open_at(&poly, &point);
        assert!(matches!(opening, Opening::TensorMerkle { .. }));
        assert!(build_transcript_steps(b"transcript-steps-test", &commitment, &opening).is_empty());
    }

    #[test]
    fn transcript_steps_empty_for_non_tensor_opening() {
        let commitment = Brakedown::commit(&small_poly());
        let opening = Opening::Folding {
            round_commitments: vec![],
            merkle_paths: vec![],
            final_value: vec![],
        };
        let steps = build_transcript_steps(b"seed", &commitment, &opening);
        assert!(steps.is_empty());
    }
}
