// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Poseidon2 hash blocks (nox pattern 15): the prover hint and the sponge
//! replay that recovers the capacity columns the trace omits.
//!
//! Each hash block is 25 trace rows (24 round rows + 1 squeeze row). The
//! round transitions are constrained by the universal step instance
//! (`universal.rs`, rows 48..64 under the π gate) — this module supplies
//! what those rows need beyond the registers: `state_k[8..16]` and
//! `state_{k+1}[8..16]`, replayed from the claimed rate with
//! [`hemera::StepSponge`].

use nebu::Goldilocks;

use hemera::field::Goldilocks as HGold;

/// Prover-supplied auxiliary data for one Poseidon2 hash block.
///
/// `rate` is the 8-element rate input: the 4-element structural digest padded
/// to 8 with zeros. Passed to `StepSponge::absorb` to replay the permutation
/// and recover the capacity elements not stored in the trace.
pub struct HashAux {
    pub rate: [Goldilocks; 8],
}

/// Replay the sponge from `rate`: the 24 post-round states of the block.
pub fn replay_states(rate: &[Goldilocks; 8]) -> Vec<[Goldilocks; 16]> {
    let mut rate_h = [HGold::ZERO; 8];
    for (j, r) in rate.iter().enumerate() {
        rate_h[j] = HGold::new(r.canonicalize().as_u64());
    }
    hemera::StepSponge::absorb(&rate_h)
        .map(|s| core::array::from_fn(|j| Goldilocks::new(s[j].as_canonical_u64())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::selector::is_satisfied;
    use crate::ccs::universal::{poseidon_witness, universal_ccs, NUM_PARTIAL, PARTIAL_FIRST};

    fn zero_rate_states() -> Vec<[Goldilocks; 16]> {
        replay_states(&[Goldilocks::ZERO; 8])
    }

    #[test]
    fn replay_yields_24_states() {
        assert_eq!(zero_rate_states().len(), 24);
    }

    #[test]
    fn universal_row_satisfied_by_all_real_partial_rounds() {
        let states = zero_rate_states();
        let u = universal_ccs();
        for k in PARTIAL_FIRST..PARTIAL_FIRST + NUM_PARTIAL {
            let w = poseidon_witness(&states[k], &states[k + 1], k);
            assert!(is_satisfied(u, &w), "partial round k={k} unsatisfied");
        }
    }

    #[test]
    fn universal_row_satisfied_by_all_real_full_rounds() {
        let states = zero_rate_states();
        let u = universal_ccs();
        for k in (0..PARTIAL_FIRST).chain(PARTIAL_FIRST + NUM_PARTIAL..23) {
            let w = poseidon_witness(&states[k], &states[k + 1], k);
            assert!(is_satisfied(u, &w), "full round k={k} unsatisfied");
        }
    }

    #[test]
    fn universal_row_rejects_wrong_next_state() {
        let states = zero_rate_states();
        let k = 5usize;
        let w = poseidon_witness(&states[k], &states[k + 3], k);
        assert!(!is_satisfied(universal_ccs(), &w), "skipping 3 rounds must not satisfy round {k}");
    }

    /// Relaxed completeness at m=64: a witness that does NOT satisfy the
    /// instance, proved against its honest per-row error vector, must
    /// verify. Before the e_claim pairing fix the verifier weighted
    /// error_evals with reversed tau/row-bit pairing and rejected every such
    /// proof at outer round 0.
    #[test]
    fn partial_round_relaxed_nonzero_error_roundtrip() {
        use crate::ccs::selector::constraint_eval;
        use crate::spartan::prover::SpartanProver;
        use crate::spartan::verifier::SpartanVerifier;
        use crate::transcript::Transcript;

        let states = zero_rate_states();
        let k = 5usize;
        let witness = poseidon_witness(&states[k], &states[k + 3], k);
        let ccs = universal_ccs();
        let error_evals = constraint_eval(ccs, &witness);
        assert!(error_evals.iter().any(|&e| e != Goldilocks::ZERO), "precondition: unsatisfied");

        let mut pt = Transcript::new();
        let proof = SpartanProver::prove(ccs, &witness, &mut pt);
        let mut vt = Transcript::new();
        let r = SpartanVerifier::verify(ccs, &proof, &error_evals, &mut vt);
        assert!(r.is_ok(), "relaxed proof with honest nonzero error must verify: {r:?}");
    }

    #[test]
    fn partial_round_spartan_prove_verify() {
        use crate::spartan::prover::SpartanProver;
        use crate::spartan::verifier::SpartanVerifier;
        use crate::transcript::Transcript;

        let states = zero_rate_states();
        let k = 7usize;
        let witness = poseidon_witness(&states[k], &states[k + 1], k);
        let ccs = universal_ccs();
        assert!(is_satisfied(ccs, &witness), "precondition: witness must satisfy");

        let mut pt = Transcript::new();
        let proof = SpartanProver::prove(ccs, &witness, &mut pt);
        let mut vt = Transcript::new();
        let zero = vec![Goldilocks::ZERO; ccs.num_rows];
        assert!(
            SpartanVerifier::verify(ccs, &proof, &zero, &mut vt).is_ok(),
            "Spartan verify failed for partial round k={k}"
        );
    }
}
