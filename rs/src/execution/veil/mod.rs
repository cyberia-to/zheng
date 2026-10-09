//! The zk profile (envelope profile 2, scheme `veil`): the succinct
//! profile's statements with secret inputs, the witness hidden.
//!
//! The statement binds the program, the public inputs, the outputs and the
//! cost; secret inputs and every intermediate value stay with the prover.
//! The protocol is SuperSpartan over Fp3 on the statement's relation plus
//! masking rows (`pad`), both sumchecks masked with Libra polynomials
//! (`libra`), and every committed value — the free witness half and the
//! two masks — under one hiding Reed–Solomon tensor commitment with a
//! zero-knowledge linear test (`hiding`). `protocol` has the transcript.
//!
//! Property proven (`specs/soundness.md` § zk profile): honest-verifier
//! statistical zero knowledge of the interactive protocol with the Merkle
//! leaves modelled as a random oracle, distance at most
//! `ε_v + ε_ρ + q_H·2^-256` with `ε_v = types·log m / p` (the masking rows'
//! weights, `pad`), `ε_ρ = 2/|Fp3|`; the Fiat–Shamir transform of the
//! public-coin protocol with salted leaves is then zero knowledge in the
//! random-oracle model (Ben-Sasson, Chiesa, Spooner, "Interactive Oracle
//! Proofs", TCC 2016-B, eprint 2016/116: the BCS transformation preserves
//! honest-verifier zero knowledge when leaves are salted). Knowledge
//! soundness is the succinct profile's argument with the masks folded in;
//! the ledger counts every term. The prover is not constant time.

mod coins;
pub(crate) mod hiding;
mod libra;
mod pad;
mod protocol;
mod wire;

#[cfg(test)]
pub(super) mod tests;
#[cfg(test)]
mod zk_tests;

pub use hiding::HidingParams;
pub use protocol::MIN_SECURITY_BITS;
pub use wire::{MAGIC, MAX_BYTES};

use super::VerifyingKey;
use super::private::PrivateStatement;
use crate::types::{CCSInstance, CCSWitness};
use coins::Coins;
use nebu::Goldilocks;
use protocol::Setup;
use wire::Parsed;

/// Identifies the zk scheme inside an artifact.
pub const FORMAT: &str = "zheng-nox-veil-execution-v1";

/// Opaque proof bytes; parsed by the verifier against the relation it
/// derives, never by shape fields of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VeilProof {
    bytes: Vec<u8>,
}

impl VeilProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Admission only: magic and size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_BYTES || !bytes.starts_with(MAGIC) {
            return Err("veil: not a proof".into());
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

fn with_constant(public: &[(usize, Goldilocks)]) -> Vec<(usize, Goldilocks)> {
    core::iter::once((0, Goldilocks::ONE)).chain(public.iter().copied()).collect()
}

/// Prove the exact supplied relation and public coordinates (`(0, 1)` is
/// added) with fresh OS randomness — the interface of `zk::prove`.
pub fn prove_relation(
    instance: &CCSInstance,
    witness: &CCSWitness,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
) -> Result<VeilProof, String> {
    prove_relation_with(&HidingParams::default(), instance, witness, statement, public, &mut Coins::os()?)
}

pub(crate) fn prove_relation_with(
    params: &HidingParams,
    instance: &CCSInstance,
    witness: &CCSWitness,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
    coins: &mut Coins,
) -> Result<VeilProof, String> {
    if !instance.is_satisfied_by(witness) {
        return Err("veil: witness does not satisfy the relation".into());
    }
    let parsed = protocol::prove(params, instance, &witness.z, &with_constant(public), statement, coins)?;
    Ok(VeilProof {
        bytes: parsed.to_bytes(),
    })
}

/// Verify against a relation and public coordinates the caller derived.
pub fn verify_relation(
    instance: &CCSInstance,
    proof: &VeilProof,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
) -> Result<(), String> {
    let setup = Setup::new(instance, &with_constant(public))?;
    let parsed = Parsed::from_bytes(&proof.bytes, setup.shape())?;
    protocol::verify(&setup, statement, &parsed)
}

/// Run `program` on public `input` and `secret` input within `budget` and
/// prove the execution in zero knowledge. The statement carries the public
/// values only; the transcript absorbs the verifying key's digest and the
/// statement's bytes.
pub fn prove(
    program: &super::ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
) -> Result<(PrivateStatement, VeilProof), String> {
    prove_bound(program, input, secret, budget, &PrivateStatement::transcript_bytes)
}

/// [`prove`] with the statement bytes chosen by the caller (`bind`), e.g.
/// with a context; the verifying key's digest is prefixed.
pub fn prove_bound(
    program: &super::ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
    bind: &dyn Fn(&PrivateStatement) -> Vec<u8>,
) -> Result<(PrivateStatement, VeilProof), String> {
    let (statement, prepared, witness) =
        super::private::prepare_execution(program, input, secret, budget)?;
    let vk = VerifyingKey::new(statement.execution.program_key(), prepared.relation);
    let public: Vec<(usize, Goldilocks)> =
        prepared.public_coordinates.iter().map(|&(i, v)| (i, Goldilocks::new(v))).collect();
    let witness = CCSWitness {
        z: witness.into_iter().map(Goldilocks::new).collect(),
    };
    let bytes = super::succinct::keyed_statement(&vk, &bind(&statement));
    let proof = prove_relation(&vk.relation().instance, &witness, &bytes, &public)?;
    Ok((statement, proof))
}

/// Verify an execution proof; see [`verify_with`].
pub fn verify(statement: &PrivateStatement, proof: &VeilProof) -> Result<(), String> {
    verify_with(statement, proof, None)
}

/// Verify an execution proof with an optional cached key (rejected unless
/// derived for this statement's program key).
pub fn verify_with(
    statement: &PrivateStatement,
    proof: &VeilProof,
    vk: Option<&VerifyingKey>,
) -> Result<(), String> {
    verify_bound(statement, proof, vk, &statement.transcript_bytes())
}

/// Verify against caller-chosen statement bytes (see [`prove_bound`]).
pub fn verify_bound(
    statement: &PrivateStatement,
    proof: &VeilProof,
    vk: Option<&VerifyingKey>,
    bound: &[u8],
) -> Result<(), String> {
    let vk = statement.execution.keyed(vk)?;
    let public = statement.execution.bindings(vk.relation())?;
    let bytes = super::succinct::keyed_statement(&vk, bound);
    verify_relation(&vk.relation().instance, proof, &bytes, &public)
}
