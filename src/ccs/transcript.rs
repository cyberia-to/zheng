// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Fiat-Shamir transcript verification as Poseidon2 CCS instances.
//!
//! Each `transcript.squeeze()` in a Brakedown opening is one Poseidon2
//! permutation (24 rounds). `build_transcript_steps` replays the transcript
//! using raw hemera and produces one `(CCSInstance, CCSWitness)` pair per
//! round of each squeeze.
//!
//! Uses Z_LEN_HASH=50 / num_rows=16, identical to pattern-15 hash steps,
//! so all transcript steps fold into the hash accumulator.

use nebu::Goldilocks;

use hemera::{Hasher, ROUNDS_TOTAL};
use hemera::field::Goldilocks as HGoldilocks;
use hemera::trace::{FullRoundWitnesses, RoundVisitor};

use lens::{Commitment, Opening};

use crate::types::{CCSInstance, CCSWitness};
use crate::ccs::particle::{
    partial_round_ccs, trivial_hash_ccs, Z_LEN_HASH,
    IDX_CONST, IDX_CAP_K, IDX_CAP_K1, IDX_Y, sk, sk1,
};

/// Number of proximity queries per Brakedown round, matching lens NUM_QUERIES.
const NUM_QUERIES: usize = 20;

/// Replay the Brakedown transcript and produce Poseidon2 CCS pairs for each squeeze.
///
/// For a `k`-variable opening, produces `k × 20 × 24` pairs:
/// - 24 CCS pairs per squeeze (one per Poseidon2 round)
/// - 20 squeezes per Brakedown folding round
/// - `k` folding rounds
///
/// `transcript_seed` is the bytes passed to `lens::Transcript::new()` when
/// `Brakedown::open` was called. The verifier's transcript absorbs the same
/// data sequence, making the replay deterministic from `opening.round_commitments`.
///
/// Returns empty vec if `opening` is not `Opening::Tensor`.
pub fn build_transcript_steps(
    transcript_seed: &[u8],
    commitment: &Commitment,
    opening: &Opening,
) -> Vec<(CCSInstance, CCSWitness)> {
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

            // Build 24 CCS pairs from the 24 round transitions.
            steps.extend(squeeze_ccs_pairs(&visitor));

            // Advance transcript: finalize + re-seed (mirroring Transcript::squeeze).
            let hash = hasher.finalize();
            hasher = Hasher::new();
            hasher.update(hash.as_bytes());
        }
    }

    steps
}

/// Produces 24 (CCSInstance, CCSWitness) pairs for one Poseidon2 permutation.
///
/// Uses partial_round_ccs for rounds k ∈ 3..19 (the 16 partial rounds).
/// Uses trivial_hash_ccs for the 8 full rounds.
fn squeeze_ccs_pairs(visitor: &SqueezeVisitor) -> Vec<(CCSInstance, CCSWitness)> {
    let mut pairs = Vec::with_capacity(ROUNDS_TOTAL);
    let states = &visitor.states;
    let ys = &visitor.y_values;

    for k in 0..ROUNDS_TOTAL {
        let state_k  = states[k];
        let state_k1 = if k + 1 < ROUNDS_TOTAL { states[k + 1] } else { states[ROUNDS_TOTAL - 1] };
        let y        = if k + 1 < ROUNDS_TOTAL { ys[k + 1] } else { Goldilocks::ZERO };

        let instance = if (3..19).contains(&k) {
            partial_round_ccs(k)
        } else {
            trivial_hash_ccs()
        };
        let witness = squeeze_witness(&state_k, &state_k1, y);
        pairs.push((instance, witness));
    }
    pairs
}

/// Build the Z_LEN_HASH=50 witness z-vector from two consecutive Poseidon2 states.
fn squeeze_witness(
    state_k: &[Goldilocks; 16],
    state_k1: &[Goldilocks; 16],
    y: Goldilocks,
) -> CCSWitness {
    let mut z = vec![Goldilocks::ZERO; Z_LEN_HASH];
    z[IDX_CONST] = Goldilocks::ONE;
    for i in 0..8 { z[sk(i)]  = state_k[i]; }
    for i in 0..8 { z[sk1(i)] = state_k1[i]; }
    for j in 0..8 { z[IDX_CAP_K  + j] = state_k[8 + j]; }
    for j in 0..8 { z[IDX_CAP_K1 + j] = state_k1[8 + j]; }
    z[IDX_Y] = y;
    CCSWitness { z }
}

/// Collects post-round states and S-box inverses from a Poseidon2 permutation.
struct SqueezeVisitor {
    states:   Vec<[Goldilocks; 16]>,
    y_values: Vec<Goldilocks>,
}

impl SqueezeVisitor {
    fn new() -> Self {
        Self {
            states:   Vec::with_capacity(ROUNDS_TOTAL),
            y_values: Vec::with_capacity(ROUNDS_TOTAL),
        }
    }
}

fn hg(x: HGoldilocks) -> Goldilocks { Goldilocks::new(x.as_canonical_u64()) }

fn hstate(s: &[HGoldilocks; 16]) -> [Goldilocks; 16] {
    core::array::from_fn(|i| hg(s[i]))
}

impl RoundVisitor for SqueezeVisitor {
    fn full_round(
        &mut self,
        _index: u8,
        state: &[HGoldilocks; 16],
        _witnesses: &FullRoundWitnesses,
    ) {
        self.states.push(hstate(state));
        self.y_values.push(Goldilocks::ZERO);
    }

    fn partial_round(&mut self, _index: u8, state: &[HGoldilocks; 16], sbox_out: HGoldilocks) {
        self.states.push(hstate(state));
        self.y_values.push(hg(sbox_out));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::selector::is_satisfied;
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
    fn transcript_steps_count_two_vars() {
        let poly = small_poly();
        let point = vec![Goldilocks::ZERO, Goldilocks::ZERO];
        let (commitment, opening) = open_at(&poly, &point);
        let steps = build_transcript_steps(b"transcript-steps-test", &commitment, &opening);
        // 2 vars × 20 queries × 24 rounds = 960
        assert_eq!(steps.len(), 2 * NUM_QUERIES * ROUNDS_TOTAL);
    }

    #[test]
    fn all_transcript_steps_satisfied_on_real_opening() {
        let poly = small_poly();
        let point = vec![Goldilocks::ZERO, Goldilocks::ONE];
        let (commitment, opening) = open_at(&poly, &point);
        let steps = build_transcript_steps(b"transcript-steps-test", &commitment, &opening);
        assert!(!steps.is_empty());
        for (i, (inst, wit)) in steps.iter().enumerate() {
            assert!(is_satisfied(inst, wit), "transcript step {i} not satisfied");
        }
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
