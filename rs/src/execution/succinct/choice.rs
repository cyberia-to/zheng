//! The scheme and parameters the succinct profile ships with, decided by
//! the bake-off recorded in `audit/succinct-profile-2026-10.md`: per size
//! class (small `ℓ ≤ 16`, large `ℓ > 16`) the smallest proof with ≥ 128
//! proven bits. Both classes chose the same configuration — WHIR, rate
//! 1/64, folding factor 4, 24 grinding bits, Johnson decoding, final
//! polynomial ≤ 2^8 — smallest on hash.tri, the 11-hash chain and the
//! synthetic relations at 2^16 and 2^20. Grinding 24 bits costs prover
//! time (seconds to ~1.5 minutes per proof, measured there).

use super::{SuccinctProof, Whir, WhirParams, protocol};
use crate::envelope::AnySuccinct;
use crate::execution::{ExecutionNoun, ExecutionStatement};

/// Largest committed size of the small class, in variables.
pub const SMALL_MAX_VARS: usize = 16;

/// The parameters for a witness of `vars` committed variables. Both classes
/// chose the same configuration (module documentation); the size stays an
/// argument so a class can diverge without changing callers.
pub fn params_for(_vars: usize) -> WhirParams {
    WhirParams {
        log_inv_rate: 6,
        folding_factor: 4,
        pow_bits: 24,
        ..WhirParams::default()
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
    let vk = crate::execution::VerifyingKey::new(statement.program_key(), relation);
    let vars = protocol::Layout::new(&vk.relation().instance, &pins)?.vars;
    let proof: SuccinctProof<Whir> = protocol::prove(
        &params_for(vars),
        &vk.relation().instance,
        &witness.z,
        &pins,
        &super::keyed_statement(&vk, &statement.transcript_bytes()),
    )?;
    Ok((statement, proof.into()))
}
