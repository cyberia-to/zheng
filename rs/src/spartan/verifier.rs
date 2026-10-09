// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! SuperSpartan verifier over a lens PCS: the IOP (`spartan::iop`) with
//! Goldilocks challenges, then the PCS opening.

use nebu::Goldilocks;

#[cfg(feature = "legacy")]
use lens::brakedown::Brakedown;
use lens::{Lens, Transcript as LensTranscript};

use crate::spartan::iop;
use crate::transcript::Transcript;
use crate::types::{CCSInstance, Proof, VerifyError};

/// SuperSpartan verifier for CCS instances (any number of constraint rows).
pub struct SpartanVerifier;

impl SpartanVerifier {
    /// Verify with Brakedown — the retired PCS of the legacy path. The
    /// transcript must already carry the statement and accumulator data.
    #[cfg(feature = "legacy")]
    pub fn verify(
        instance: &CCSInstance,
        proof: &Proof,
        error_evals: &[Goldilocks],
        transcript: &mut Transcript,
    ) -> Result<(), VerifyError> {
        Self::verify_using::<Brakedown>(instance, proof, error_evals, transcript)
    }

    /// Verify with the PCS fixed by the caller's protocol, never by proof data.
    /// The inner round count is the proof's own; callers that fix dimensions
    /// check `proof.sumcheck_polys.len()` first (`execution::proof`).
    pub fn verify_using<P: Lens<Goldilocks>>(
        instance: &CCSInstance,
        proof: &Proof,
        error_evals: &[Goldilocks],
        transcript: &mut Transcript,
    ) -> Result<(), VerifyError> {
        transcript.absorb_commitment(&proof.commitment);
        let parts = iop::IopProof {
            matrix_evals: proof.matrix_evals.clone(),
            outer_sumcheck_polys: proof.outer_sumcheck_polys.clone(),
            sumcheck_polys: proof.sumcheck_polys.clone(),
            eval_value: proof.eval_value,
        };
        let point = iop::verify::<Goldilocks>(
            instance,
            &parts,
            error_evals,
            proof.sumcheck_polys.len(),
            transcript,
        )?;

        let pcs_point: Vec<Goldilocks> = point.iter().copied().rev().collect();
        transcript.absorb_eval(proof.eval_value);
        let seed = transcript.squeeze_hash();
        let mut lt = LensTranscript::new(&seed);
        if !P::verify(
            &proof.commitment,
            &pcs_point,
            proof.eval_value,
            &proof.pcs_opening,
            &mut lt,
        ) {
            return Err(VerifyError::LensFailed);
        }
        Ok(())
    }
}
