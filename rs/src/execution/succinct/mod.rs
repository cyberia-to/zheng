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
pub(crate) mod protocol;

pub use protocol::{SuccinctProof, prove as prove_relation, verify as verify_relation};
pub use choice::{SMALL_MAX_VARS, params_for, prove_default};
pub use pcs::{MIN_SECURITY_BITS, SuccinctPcs, admit};
/// The schemes and their parameters, so callers need not depend on lens.
pub use lens::rspcs::whir::Decoding;
pub use lens::{MultilinearPcs, TensorRs, TensorRsParams, Whir, WhirParams};

use super::state::{self, StateStatement};
use super::state_evidence::StateEvidence;
use super::{ExecutionNoun, ExecutionStatement, VerifyingKey};
use nebu::Goldilocks;

/// Identifies the succinct profile inside an artifact.
pub const FORMAT: &str = "zheng-nox-succinct-execution-v1";

fn with_constant(public: Vec<(usize, Goldilocks)>) -> Vec<(usize, Goldilocks)> {
    core::iter::once((0, Goldilocks::ONE)).chain(public).collect()
}

/// The bytes the transcript absorbs first: the verifying key's digest,
/// then the statement. The proof is bound to the relation it was made for.
pub fn keyed_statement(vk: &VerifyingKey, statement: &[u8]) -> Vec<u8> {
    let mut bytes = b"zheng-vk".to_vec();
    bytes.extend_from_slice(&vk.digest());
    bytes.extend_from_slice(statement);
    bytes
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
    let vk = VerifyingKey::new(statement.program_key(), relation);
    let proof = protocol::prove::<P>(
        params,
        &vk.relation().instance,
        &witness.z,
        &with_constant(public),
        &keyed_statement(&vk, &statement.transcript_bytes()),
    )?;
    Ok((statement, proof))
}

/// Derive the relation from `statement` and verify `proof` against it.
pub fn verify<P: SuccinctPcs>(
    statement: &ExecutionStatement,
    proof: &SuccinctProof<P>,
) -> Result<(), String> {
    verify_with(statement, proof, None)
}

/// [`verify`] with an optional cached key: when given, it must have been
/// derived for this statement's program key (else the proof is rejected)
/// and the relation is not recompiled.
pub fn verify_with<P: SuccinctPcs>(
    statement: &ExecutionStatement,
    proof: &SuccinctProof<P>,
    vk: Option<&VerifyingKey>,
) -> Result<(), String> {
    let vk = statement.keyed(vk)?;
    let public = statement.bindings(vk.relation())?;
    protocol::verify::<P>(
        &vk.relation().instance,
        &with_constant(public),
        &keyed_statement(&vk, &statement.transcript_bytes()),
        proof,
    )
}

/// Prove an authenticated-state execution with a committed witness; the
/// statement's root is the root `evidence` authenticates.
pub fn prove_state<P: SuccinctPcs>(
    params: &P::Params,
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    root_in_subject: bool,
    evidence: &StateEvidence,
) -> Result<(StateStatement, SuccinctProof<P>), String> {
    let (statement, relation, witness, public) =
        state::prepare(program, input, budget, root_in_subject, evidence)?;
    let vk = VerifyingKey::new(statement.program_key(), relation);
    let proof = protocol::prove::<P>(
        params,
        &vk.relation().instance,
        &witness.z,
        &with_constant(public),
        &keyed_statement(&vk, &statement.transcript_bytes()),
    )?;
    Ok((statement, proof))
}

/// Verify a succinct state proof: `evidence` is authenticated under
/// `statement.state_root` and every active read against it before anything
/// else is checked.
pub fn verify_state<P: SuccinctPcs>(
    statement: &StateStatement,
    proof: &SuccinctProof<P>,
    evidence: &StateEvidence,
) -> Result<(), String> {
    verify_state_with(statement, proof, evidence, None)
}

/// [`verify_state`] with an optional cached key (see [`verify_with`]).
pub fn verify_state_with<P: SuccinctPcs>(
    statement: &StateStatement,
    proof: &SuccinctProof<P>,
    evidence: &StateEvidence,
    vk: Option<&VerifyingKey>,
) -> Result<(), String> {
    let (vk, public) = statement.keyed_bindings(evidence, vk)?;
    protocol::verify::<P>(
        &vk.relation().instance,
        &with_constant(public),
        &keyed_statement(&vk, &statement.transcript_bytes()),
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
