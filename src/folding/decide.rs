// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! HyperNova decider: SuperSpartan proof on the accumulated CCS instance.

use crate::spartan::prover::SpartanProver;
use crate::transcript::Transcript;
use crate::types::{Accumulator, DecideError, Proof, ProofParams};

/// Run the SuperSpartan decider on the accumulated CCS.
///
/// Produces a proof that the accumulated folded witness satisfies the
/// accumulated CCS instance. This is the O(1)-cost step that converts
/// N fold operations into one verifiable proof.
pub fn decide(
    acc: &Accumulator,
    _params: &ProofParams,
) -> Result<Proof, DecideError> {
    if acc.step_count == 0 {
        return Err(DecideError::EmptyAccumulator);
    }

    let mut transcript = Transcript::new_recursive();

    // Absorb the accumulator's public data before proving.
    transcript.absorb(acc.witness_commitment.as_bytes());
    transcript.absorb(&acc.error_term.as_u64().to_le_bytes());
    transcript.absorb(&acc.step_count.to_le_bytes());

    let proof = SpartanProver::prove(
        &acc.committed_instance,
        &acc.folded_witness,
        &mut transcript,
    );

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nebu::Goldilocks;
    use crate::ccs::patterns::build_step_ccs;
    use crate::ccs::{reg_t, reg_t1, CONST_IDX, Z_LEN};
    use crate::folding::fold::fold_step;
    use crate::spartan::verifier::SpartanVerifier;
    use crate::types::{CCSWitness, Statement};

    fn make_witness(r3: u64, r4: u64, r5_t1: u64) -> CCSWitness {
        let mut z = vec![Goldilocks::ZERO; Z_LEN];
        z[CONST_IDX] = Goldilocks::ONE;
        z[reg_t(3)] = Goldilocks::new(r3);
        z[reg_t(4)] = Goldilocks::new(r4);
        z[reg_t1(5)] = Goldilocks::new(r5_t1);
        CCSWitness { z }
    }

    fn zero_accumulator(instance: &crate::types::CCSInstance) -> Accumulator {
        use lens::brakedown::Brakedown;
        let z = vec![Goldilocks::ZERO; 64];
        Accumulator {
            committed_instance: instance.clone(),
            folded_witness: CCSWitness { z: z.clone() },
            witness_commitment: Brakedown::commit_raw(&z),
            error_term: Goldilocks::ZERO,
            step_count: 0,
        }
    }

    #[test]
    fn decide_empty_accumulator_errors() {
        let instance = build_step_ccs(5);
        let acc = zero_accumulator(&instance);
        assert!(decide(&acc, &ProofParams::default()).is_err());
    }

    #[test]
    fn fold_then_decide_produces_valid_proof() {
        let instance = build_step_ccs(5); // add pattern
        let witness = make_witness(5, 3, 8); // 5+3=8 ✓
        let mut acc = zero_accumulator(&instance);
        let mut t = Transcript::new();
        fold_step(&mut acc, &instance, &witness, &mut t).unwrap();

        let proof = decide(&acc, &ProofParams::default()).unwrap();

        // Verify the proof against the folded instance.
        let mut vt = Transcript::new_recursive();
        vt.absorb(acc.witness_commitment.as_bytes());
        vt.absorb(&acc.error_term.as_u64().to_le_bytes());
        vt.absorb(&acc.step_count.to_le_bytes());
        let stmt = Statement {
            program_hash: [0u8; 32],
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
            focus_bound: 0,
        };
        assert!(SpartanVerifier::verify(&acc.committed_instance, &stmt, &proof, &mut vt).is_ok());
    }
}
