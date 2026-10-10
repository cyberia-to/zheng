// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! SuperSpartan prover over a lens PCS: commit the witness, run the IOP
//! (`spartan::iop`) with Goldilocks challenges, open the PCS.

use nebu::Goldilocks;

#[cfg(feature = "legacy")]
use lens::brakedown::Brakedown;
use lens::{Lens, MultilinearPoly, Transcript as LensTranscript};

use crate::multilinear::pad_to_power_of_two;
use crate::spartan::iop;
use crate::transcript::Transcript;
use crate::types::{CCSInstance, CCSWitness, Proof};

/// SuperSpartan prover for CCS instances (any number of constraint rows).
pub struct SpartanProver;

impl SpartanProver {
    /// Prove with Brakedown — the retired PCS of the legacy path.
    #[cfg(feature = "legacy")]
    pub fn prove(
        instance: &CCSInstance,
        witness: &CCSWitness,
        transcript: &mut Transcript,
    ) -> Proof {
        Self::prove_using::<Brakedown>(instance, witness, transcript)
    }

    /// Prove using an explicitly selected PCS. Callers must bind the protocol
    /// and PCS identity in their transcript and respect its disclosure model.
    /// Challenges are Goldilocks: the lens PCS opens at base-field points.
    pub fn prove_using<P: Lens<Goldilocks>>(
        instance: &CCSInstance,
        witness: &CCSWitness,
        transcript: &mut Transcript,
    ) -> Proof {
        let mut z_padded = witness.z.clone();
        pad_to_power_of_two(&mut z_padded, 64);
        let z_poly = MultilinearPoly::new(z_padded.clone());
        let commitment = P::commit(&z_poly);
        transcript.absorb_commitment(&commitment);

        let (iop, point) = iop::prove::<Goldilocks>(instance, &z_padded, transcript);
        transcript.absorb_eval(iop.eval_value);

        // Brakedown uses LSB-first; sumcheck MSB-first. Reverse to reconcile.
        let pcs_point: Vec<Goldilocks> = point.iter().copied().rev().collect();
        let seed = transcript.squeeze_hash();
        let mut lt = LensTranscript::new(&seed);
        let pcs_opening = P::open(&z_poly, &pcs_point, &mut lt);

        Proof {
            commitment,
            matrix_evals: iop.matrix_evals,
            outer_sumcheck_polys: iop.outer_sumcheck_polys,
            sumcheck_polys: iop.sumcheck_polys,
            eval_value: iop.eval_value,
            pcs_opening,
        }
    }
}

#[cfg(all(test, feature = "legacy"))]
mod tests {
    use super::*;
    use crate::ccs::reg_t;
    use crate::ccs::universal::{test_witness, universal_ccs};
    use crate::spartan::verifier::SpartanVerifier;
    use crate::transcript::Transcript;

    #[test]
    fn prove_verify_add_pattern() {
        // add row: r4=5, r5=3, r6=8
        let witness = test_witness(&[(reg_t(0), 5), (reg_t(4), 5), (reg_t(5), 3), (reg_t(6), 8)]);
        let instance = universal_ccs();

        let mut pt = Transcript::new_v1();
        let proof = SpartanProver::prove(instance, &witness, &mut pt);

        let mut vt = Transcript::new_v1();
        let zero = vec![Goldilocks::ZERO; instance.num_rows];
        let result = SpartanVerifier::verify(instance, &proof, &zero, &mut vt);
        assert!(result.is_ok(), "verify failed: {result:?}");
    }

    #[test]
    fn prove_verify_mul_pattern() {
        // mul row: r4=6, r5=7, r6=42
        let witness = test_witness(&[(reg_t(0), 7), (reg_t(4), 6), (reg_t(5), 7), (reg_t(6), 42)]);
        let instance = universal_ccs();

        let mut pt = Transcript::new_v1();
        let proof = SpartanProver::prove(instance, &witness, &mut pt);

        let mut vt = Transcript::new_v1();
        let zero = vec![Goldilocks::ZERO; instance.num_rows];
        assert!(SpartanVerifier::verify(instance, &proof, &zero, &mut vt).is_ok());
    }
}
