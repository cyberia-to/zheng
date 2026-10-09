//! The succinct profile (envelope profile 1): the same public statements as
//! public v3 and state v3, with the witness committed instead of disclosed.
//!
//! The verifier derives the relation exactly as v3 does — it recompiles the
//! CCS from the program and the subject shape and pins `z[0] = 1`, the
//! inputs, the outputs, the cost and (for state statements) every read —
//! then checks a Spartan IOP over Fp3 challenges and one opening of the
//! committed free half of the witness. See `protocol` for the layout and the
//! protocol, `pcs` for the schemes and the policy, `specs/execution.md`
//! § succinct and `specs/soundness.md` for the bound.

mod choice;
mod pcs;
mod protocol;

pub use protocol::{SuccinctProof, prove as prove_relation, verify as verify_relation};
pub use choice::{SMALL_MAX_VARS, large_params, params_for, prove_default, small_params};
pub use pcs::{MIN_SECURITY_BITS, SuccinctPcs, admit};
/// The schemes and their parameters, so callers need not depend on lens.
pub use lens::rspcs::whir::Decoding;
pub use lens::{MultilinearPcs, TensorRs, TensorRsParams, Whir, WhirParams};

use super::state::{self, StateStatement};
use super::{ExecutionNoun, ExecutionStatement};
use nebu::Goldilocks;

/// Identifies the succinct profile inside an artifact.
pub const FORMAT: &str = "zheng-nox-succinct-execution-v1";

fn with_constant(public: Vec<(usize, Goldilocks)>) -> Vec<(usize, Goldilocks)> {
    core::iter::once((0, Goldilocks::ONE)).chain(public).collect()
}

/// Run `program` on `input` within `budget` and prove the execution with a
/// committed witness.
pub fn prove<P: SuccinctPcs>(
    params: &P::Params,
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
) -> Result<(ExecutionStatement, SuccinctProof<P>), String> {
    let (statement, relation, witness, public) = super::statement::prepare(program, input, budget)?;
    let proof = protocol::prove::<P>(
        params,
        &relation.instance,
        &witness.z,
        &with_constant(public),
        &statement.transcript_bytes(),
    )?;
    Ok((statement, proof))
}

/// Derive the relation from `statement` and verify `proof` against it.
pub fn verify<P: SuccinctPcs>(
    statement: &ExecutionStatement,
    proof: &SuccinctProof<P>,
) -> Result<(), String> {
    let relation = statement.relation()?;
    let public = statement.bindings(&relation)?;
    protocol::verify::<P>(
        &relation.instance,
        &with_constant(public),
        &statement.transcript_bytes(),
        proof,
    )
}

/// Prove an authenticated-state execution with a committed witness. The
/// lookup callback MUST answer from `state_root`.
#[allow(clippy::too_many_arguments)]
pub fn prove_state<P: SuccinctPcs>(
    params: &P::Params,
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    state_root: [u64; 4],
    root_in_subject: bool,
    context: [u8; 32],
    lookup: &mut dyn FnMut(u64, u64) -> Option<u64>,
) -> Result<(StateStatement, SuccinctProof<P>), String> {
    let (statement, relation, witness, public) = state::prepare(
        program,
        input,
        budget,
        state_root,
        root_in_subject,
        context,
        lookup,
    )?;
    let proof = protocol::prove::<P>(
        params,
        &relation.instance,
        &witness.z,
        &with_constant(public),
        &statement.transcript_bytes(),
    )?;
    Ok((statement, proof))
}

/// Verify a succinct state proof. The callback MUST answer from a state
/// certificate already verified against `statement.state_root`; it is
/// consulted for every active read before anything else is checked.
pub fn verify_state<P: SuccinctPcs>(
    statement: &StateStatement,
    proof: &SuccinctProof<P>,
    lookup: &mut dyn FnMut(u64, u64) -> Option<u64>,
) -> Result<(), String> {
    let relation = statement.relation()?;
    let public = statement.bindings(&relation, lookup)?;
    protocol::verify::<P>(
        &relation.instance,
        &with_constant(public),
        &statement.transcript_bytes(),
        proof,
    )
}

/// The relation and the pinned coordinates (`(0, 1)` first) a verifier
/// derives from a public execution statement.
pub fn relation_and_pins(
    statement: &ExecutionStatement,
) -> Result<(crate::types::CCSInstance, Vec<(usize, Goldilocks)>), String> {
    let relation = statement.relation()?;
    let public = statement.bindings(&relation)?;
    Ok((relation.instance, with_constant(public)))
}

/// `ℓ`: the variables of the committed half for this relation and pins.
pub fn committed_vars(
    instance: &crate::types::CCSInstance,
    pins: &[(usize, Goldilocks)],
) -> Result<usize, String> {
    protocol::Layout::new(instance, pins).map(|l| l.vars)
}
