//! The scheme and parameters each size class ships with, decided by the
//! bake-off recorded in `audit/succinct-profile-2026-10.md`: the smallest
//! proof with ≥ 128 proven bits per class (small: `ℓ ≤ 16`; large: above).

use super::{SuccinctProof, Whir, WhirParams, protocol};
use crate::envelope::AnySuccinct;
use crate::execution::{ExecutionNoun, ExecutionStatement};

/// Largest committed size of the small class, in variables.
pub const SMALL_MAX_VARS: usize = 16;

/// Parameters of the small class (`ℓ ≤ 16`).
pub fn small_params() -> WhirParams {
    WhirParams {
        log_inv_rate: 4,
        folding_factor: 4,
        pow_bits: 16,
        ..WhirParams::default()
    }
}

/// Parameters of the large class (`ℓ > 16`).
pub fn large_params() -> WhirParams {
    WhirParams {
        log_inv_rate: 4,
        folding_factor: 4,
        pow_bits: 16,
        ..WhirParams::default()
    }
}

/// The parameters for a witness of `vars` committed variables.
pub fn params_for(vars: usize) -> WhirParams {
    if vars <= SMALL_MAX_VARS {
        small_params()
    } else {
        large_params()
    }
}

/// Prove a public execution with the scheme and parameters of its class.
pub fn prove_default(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
) -> Result<(ExecutionStatement, AnySuccinct), String> {
    let (statement, relation, witness, public) =
        crate::execution::statement::prepare(program, input, budget)?;
    let pins = super::with_constant(public);
    let vars = protocol::Layout::new(&relation.instance, &pins)?.vars;
    let proof: SuccinctProof<Whir> = protocol::prove(
        &params_for(vars),
        &relation.instance,
        &witness.z,
        &pins,
        &statement.transcript_bytes(),
    )?;
    Ok((statement, proof.into()))
}
