//! The scheme and parameters the succinct profile ships with, decided by
//! the bake-off recorded in `audit/succinct-profile-2026-10.md`: per size
//! class (small `ℓ ≤ 16`, large `ℓ > 16`) the smallest proof with ≥ 128
//! proven bits. Both classes chose the same configuration — WHIR, rate
//! 1/64, folding factor 4, 24 grinding bits, Johnson decoding, final
//! polynomial ≤ 2^8 — smallest on hash.tri, the 11-hash chain and the
//! synthetic relations at 2^16 and 2^20. Grinding 24 bits costs prover
//! time (seconds to ~1.5 minutes per proof, measured there).
//!
//! [`params_for`] keeps that configuration: the machine, IVC and wrap
//! profiles derive their keys from it. The one-relation profile proves on
//! user devices within the ≤ 1 s gate and ships [`device_params`] instead
//! (soft3 `audit/proof-latency-2026-10.md`): per committed size, the fastest
//! prover whose proof stays ≤ 64 KB at ≥ 128 proven bits — 16 grinding bits
//! (112 bits without grinding) wherever 64 KB allows, more only where the
//! size needs it.

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

/// The one-relation profile's parameters for `vars` committed variables:
/// rate 1/64, folding 4 up to 2^16 (5 above: fewer, cheaper rounds),
/// grinding 16 bits up to 2^17, 22 at 2^18 and 24 beyond — the least
/// grinding that keeps the proof ≤ 64 KB (above 2^18 no setting does).
pub fn device_params(vars: usize) -> WhirParams {
    let (folding_factor, pow_bits) = match vars {
        0..=16 => (4, 16),
        17 => (5, 16),
        18 => (5, 22),
        _ => (5, 24),
    };
    WhirParams {
        log_inv_rate: 6,
        folding_factor,
        pow_bits,
        ..WhirParams::default()
    }
}

/// Prove a public execution with the one-relation profile's parameters
/// ([`device_params`]).
pub fn prove_default(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
) -> Result<(ExecutionStatement, AnySuccinct), String> {
    prove_with(program, input, budget, device_params)
}

/// Prove a public execution with the parameters `choose` picks for the
/// committed size (in variables) the relation turns out to have. The
/// verifier reads the parameters from the proof and admits them only at
/// ≥ 128 proven bits, so any admitted choice verifies.
pub fn prove_with(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    choose: impl Fn(usize) -> WhirParams,
) -> Result<(ExecutionStatement, AnySuccinct), String> {
    let lap = crate::laps::timer("prove_default");
    let (statement, relation, witness, public) =
        crate::execution::statement::prepare(program, input, budget)?;
    lap("relation + witness");
    let pins = super::with_constant(public);
    let vk = crate::execution::VerifyingKey::new(statement.program_key(), relation);
    lap("verifying key");
    let vars = protocol::Layout::new(&vk.relation().instance, &pins)?.vars;
    let proof: SuccinctProof<Whir> = protocol::prove(
        &choose(vars),
        &vk.relation().instance,
        &witness.z,
        &pins,
        &super::keyed_statement(&vk, &statement.transcript_bytes()),
    )?;
    Ok((statement, proof.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every size the profile admits carries ≥ 128 proven bits with the
    /// shipped grinding, and the grinding never carries more than its own
    /// bits (the bound without it is stated in the audit).
    #[test]
    fn device_parameters_meet_the_ledger_at_every_size() {
        // the relation cap (MAX_RELATION = 2^20) bounds the committed size
        for vars in 1..=20 {
            let p = device_params(vars);
            let bits = super::super::admit::<Whir>(&p, vars).unwrap();
            let cfg = lens::rspcs::WhirConfig::derive(&p, vars).unwrap();
            let bare = cfg.security_bits_without_grinding();
            assert!(bits >= 128.0, "2^{vars}: {bits}");
            assert!(
                bare >= 128.0 - f64::from(p.pow_bits) - 1e-9,
                "2^{vars}: bare {bare}"
            );
        }
    }
}
