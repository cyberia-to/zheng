//! veil-W: the zk profile with a WHIR opening (research, gate G1 of soft3
//! `proposals/privacy-frozen.md`; `docs/explanation/zk-small.md`).
//!
//! Spartan is veil's — masking rows, Libra masks on both sumchecks — and
//! every committed value sits in one base-field vector `c` (`layout`):
//! the free witness, the Libra masks and a uniform block `r` at the top
//! slots. The opening is lens's zero-knowledge WHIR opening: WHIR on
//! `h = c + β·g` with a uniform mask word `g` constant on folding cosets
//! and salted round-0 leaves, so every message after the first fold is a
//! function of a uniform word, and the round-0 messages are masked by
//! `r` (the masking lemma, `docs/explanation/zk-small.md` § the design;
//! ledger row `specs/soundness.md` § zk rows).

mod layout;
mod protocol;
mod wire;
pub mod inspect;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod zk_tests;

pub use wire::{MAGIC, MAX_BYTES};

use lens::WhirParams;
use nebu::Goldilocks;

use super::coins::Coins;
use super::protocol::Setup;
use super::with_constant;
use crate::execution::VerifyingKey;
use crate::execution::private::PrivateStatement;
use crate::types::{CCSInstance, CCSWitness};
use layout::Slots;
use protocol::Parts;

/// Bits a veil-W proof must carry: proven, grinding included.
pub const MIN_SECURITY_BITS: f64 = 128.0;

/// A veil-W proof: opaque bytes, parsed only against the relation the
/// verifier derives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallProof {
    bytes: Vec<u8>,
}

impl SmallProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_BYTES || !bytes.starts_with(MAGIC) {
            return Err("veil-W: not a proof".into());
        }
        Ok(Self { bytes: bytes.to_vec() })
    }
}

/// Bits of the whole proof at `params` for this relation: the opening's
/// terms (lens `zk_terms`) and the masked Spartan IOP's (veil's).
pub(crate) fn bits(params: &WhirParams, s: &Setup) -> Result<f64, String> {
    let slots = Slots::derive(s, params)?;
    let open = lens::rspcs::whir::zk::zk_security_bits(params, slots.n);
    let t = s.instance.matrices.len();
    // veil's Spartan terms (`report`), plus one for μ
    let terms = s.log_m * s.degree + s.log_m + 1 + 2 * s.layout.vars + 1 + (t - 1) + 1 + 1;
    let p3 = 3.0 * (nebu::field::P as f64).log2();
    Ok(open.min(p3 - (terms as f64).log2()))
}

/// Admit a parameter set: in the verifier's range and ≥ 128 proven bits.
pub(crate) fn admit(params: &WhirParams, s: &Setup) -> Result<f64, String> {
    if !<lens::Whir as crate::execution::succinct::SuccinctPcs>::in_range(params) {
        return Err("veil-W: parameters outside the verifier's range".into());
    }
    let b = bits(params, s)?;
    if b < MIN_SECURITY_BITS {
        return Err(format!("veil-W: {b:.2} proven bits, policy requires {MIN_SECURITY_BITS}"));
    }
    Ok(b)
}

/// The device parameters at the committed size the layout lands on: the
/// succinct profile's `device_params(n)`, `n` the least size that fits.
pub(crate) fn choose(s: &Setup) -> Result<(WhirParams, Slots), String> {
    let mut n = s.layout.vars;
    loop {
        let p = crate::execution::succinct::device_params(n);
        let slots = Slots::derive(s, &p)?;
        if slots.n == n {
            return Ok((p, slots));
        }
        if slots.n < n {
            // the smaller size fits under its own parameters too
            let p2 = crate::execution::succinct::device_params(slots.n);
            if Slots::derive(s, &p2)?.n == slots.n {
                return Ok((p2, slots));
            }
        }
        n = slots.n.max(n + 1);
    }
}

/// The committed size and the masking block of a relation (inspection).
pub fn shape(instance: &CCSInstance, public: &[(usize, Goldilocks)]) -> Result<(usize, usize, usize), String> {
    let s = Setup::compact(instance, &with_constant(public))?;
    let (_, slots) = choose(&s)?;
    Ok((slots.n, slots.block(), slots.used))
}

pub(crate) fn prove_relation_with(
    instance: &CCSInstance,
    witness: &CCSWitness,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
    coins: &Coins,
) -> Result<SmallProof, String> {
    if !instance.is_satisfied_by(witness) {
        return Err("veil-W: witness does not satisfy the relation".into());
    }
    let pins = with_constant(public);
    if witness.z.len() != instance.num_cols || pins.iter().any(|&(i, v)| witness.z[i] != v) {
        return Err("veil-W: witness disagrees with the statement".into());
    }
    let s = Setup::compact(instance, &pins)?;
    let (params, slots) = choose(&s)?;
    admit(&params, &s)?;
    let relabelled = s.layout.instance(&s.instance);
    let z = s.ext.witness(&witness.z, s.instance.num_cols, coins);
    let mut zp = vec![Goldilocks::ZERO; relabelled.num_cols];
    for (col, slot) in s.layout.map.iter().enumerate() {
        if let Some(x) = slot {
            zp[*x] = z[col];
        }
    }
    let parts = protocol::prove(&params, &s, &slots, &relabelled, &zp, statement, coins)?;
    Ok(SmallProof { bytes: parts.to_bytes() })
}

/// Prove the supplied relation and public coordinates (`(0, 1)` added)
/// with fresh OS randomness.
pub fn prove_relation(
    instance: &CCSInstance,
    witness: &CCSWitness,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
) -> Result<SmallProof, String> {
    prove_relation_with(instance, witness, statement, public, &Coins::os()?)
}

/// Verify against a relation and public coordinates the caller derived.
pub fn verify_relation(
    instance: &CCSInstance,
    proof: &SmallProof,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
) -> Result<(), String> {
    let s = Setup::compact(instance, &with_constant(public))?;
    let parts = Parts::from_bytes(&proof.bytes, s.shape())?;
    protocol::verify(&s, statement, &parts)
}

/// Run `program` on public `input` and `secret` within `budget` and prove
/// the execution with veil-W (the statement and binding are veil's).
pub fn prove(
    program: &crate::execution::ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
) -> Result<(PrivateStatement, SmallProof), String> {
    prove_with_coins(program, input, secret, budget, &Coins::os()?)
}

pub(crate) fn prove_with_coins(
    program: &crate::execution::ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
    coins: &Coins,
) -> Result<(PrivateStatement, SmallProof), String> {
    let (statement, prepared, witness) =
        crate::execution::private::prepare_execution(program, input, secret, budget)?;
    let vk = VerifyingKey::new(statement.execution.program_key(), prepared.relation);
    let public: Vec<(usize, Goldilocks)> =
        prepared.public_coordinates.iter().map(|&(i, v)| (i, Goldilocks::new(v))).collect();
    let witness = CCSWitness { z: witness.into_iter().map(Goldilocks::new).collect() };
    let bytes = crate::execution::succinct::keyed_statement(&vk, &statement.transcript_bytes());
    let proof = prove_relation_with(&vk.relation().instance, &witness, &bytes, &public, coins)?;
    Ok((statement, proof))
}

/// Verify an execution proof.
pub fn verify(statement: &PrivateStatement, proof: &SmallProof) -> Result<(), String> {
    let vk = statement.execution.keyed(None)?;
    let public = statement.execution.bindings(vk.relation())?;
    let bytes = crate::execution::succinct::keyed_statement(&vk, &statement.transcript_bytes());
    verify_relation(&vk.relation().instance, proof, &bytes, &public)
}
