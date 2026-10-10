//! One proof envelope for every zheng profile.
//!
//! ```text
//! magic    8 bytes  "ZHENGPF1"
//! version  u16 LE   VERSION
//! profile  u8       0 public · 1 succinct · 2 zk · 3 state-public · 4 machine
//!                   · 5 recursive · 6 wrapped
//! body              per profile, canonical (see `codec`)
//! ```
//!
//! Bodies:
//!
//! - public (0): execution statement, then the v3 certificate;
//! - succinct (1): PCS id and parameter header, statement kind, the
//!   execution or state statement, then the succinct proof (see `succinct`);
//! - zk (2): scheme byte (1 = linear MPC-in-the-head `ZHMITH01`, 2 =
//!   succinct `veil` `ZHVEIL01`), execution statement, a 32-byte caller
//!   context, then the proof bytes (length-prefixed); the proof's statement
//!   bytes are [`zk_statement_bytes`] (for veil keyed by the verifying
//!   key's digest);
//! - state-public (3): execution statement, state root (4 field limbs),
//!   root-in-subject flag, the reads, then the v3 certificate.
//! - machine (4): WHIR parameters, the machine statement (program, inputs,
//!   output noun, cycles, budget), then the machine proof (see `machine`).
//! - recursive (5): format byte, WHIR parameters (an admitted set), the
//!   machine statement as in profile 4, then the IVC proof, length-prefixed
//!   (see `recursive`).
//! - wrapped (6): format byte, the admitted chain (IVC WHIR header, wrap
//!   levels' headers and modes), the machine statement as in profile 4,
//!   then the final proof, length-prefixed (see `wrapped`).
//!
//! An execution statement is: program tokens (tag 0 + atom, tag 1 = pair),
//! public inputs, public outputs, cycles, budget. A certificate is the free
//! values with no trailing zero. Decoding rejects a wrong magic, an unknown
//! version, an unknown profile, any noncanonical integer, field
//! value or flag, any length beyond its bound, truncation and trailing bytes.

mod body;
pub(crate) mod codec;
mod machine;
pub mod keys;
pub mod recursive;
pub mod wrapped;
mod succinct;
#[cfg(test)]
mod tests;

use crate::execution::private::PrivateStatement;
use crate::execution::state::StateStatement;
use crate::execution::state_evidence::StateEvidence;
use crate::execution::zk::{self, PrivateProof};
use crate::execution::veil::{self, VeilProof};
use crate::execution::{Certificate, ExecutionStatement, verify_certificate};
use core::fmt;

pub use succinct::{AnySuccinct, SuccinctStatement, proof_bytes as succinct_proof_bytes};

pub const MAGIC: &[u8; 8] = b"ZHENGPF1";
pub const VERSION: u16 = 1;
/// Header bytes before the body.
pub const HEADER_BYTES: usize = 11;
/// Upper bound on a whole envelope: the largest zk proof plus statements.
pub const MAX_BYTES: usize = zk::MAX_BYTES + (1 << 20);

/// The profile byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Profile {
    Public = 0,
    /// Committed witness, Spartan over Fp3, one PCS opening.
    Succinct = 1,
    Zk = 2,
    StatePublic = 3,
    /// A nox run of any length: the uniform step relation, accumulation,
    /// one decider.
    Machine = 4,
    /// A nox run of any length proven by IVC: the last step, its
    /// accumulation step and one decider — constant in the steps.
    Recursive = 5,
    /// A nox run of any length proven by IVC, its final verifier proved
    /// by wrap levels: ≤ 64 KB, constant in the steps.
    Wrapped = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    BadMagic,
    UnsupportedVersion(u16),
    UnknownProfile(u8),
    Truncated,
    TrailingBytes,
    NonCanonical,
    TooLarge,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zheng envelope: {self:?}")
    }
}
impl std::error::Error for EnvelopeError {}

/// A decoded envelope. Decoding checks the encoding only; [`Envelope::verify`]
/// checks the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Envelope {
    Public {
        statement: ExecutionStatement,
        certificate: Certificate,
    },
    Zk {
        statement: PrivateStatement,
        context: [u8; 32],
        proof: ZkProof,
    },
    StatePublic {
        statement: StateStatement,
        certificate: Certificate,
    },
    Succinct {
        statement: SuccinctStatement,
        proof: AnySuccinct,
    },
    Machine {
        params: lens::WhirParams,
        statement: crate::machine::MachineStatement,
        proof: Box<crate::machine::MachineProof>,
    },
    Recursive {
        params: lens::WhirParams,
        statement: crate::machine::MachineStatement,
        proof: Box<crate::recursion::ivc::IvcProof>,
    },
    Wrapped {
        statement: crate::machine::MachineStatement,
        proof: Box<crate::recursion::wrap::FinalProof>,
    },
}

/// A zk-profile proof under one of its two schemes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProof {
    /// Linear-size MPC-in-the-head (`execution::zk`): the fallback for
    /// relations the succinct scheme does not admit, and a differential
    /// oracle.
    Mith(PrivateProof),
    /// Succinct zk (`execution::veil`).
    Veil(VeilProof),
}

impl ZkProof {
    /// Wire id of the scheme.
    pub fn scheme(&self) -> u8 {
        match self {
            Self::Mith(_) => 1,
            Self::Veil(_) => 2,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Mith(p) => p.as_bytes(),
            Self::Veil(p) => p.as_bytes(),
        }
    }
}

/// Prove an execution with secret inputs under the succinct zk scheme and
/// wrap it in a profile-2 envelope bound to `context`.
pub fn prove_zk(
    program: &crate::execution::ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
    context: [u8; 32],
) -> Result<Envelope, String> {
    let (statement, proof) =
        veil::prove_bound(program, input, secret, budget, &|s| zk_statement_bytes(s, &context))?;
    Ok(Envelope::Zk {
        statement,
        context,
        proof: ZkProof::Veil(proof),
    })
}

/// The statement bytes a zk-profile proof is made and checked against.
pub fn zk_statement_bytes(statement: &PrivateStatement, context: &[u8; 32]) -> Vec<u8> {
    let mut bytes = b"zheng-envelope-zk-v1".to_vec();
    bytes.extend_from_slice(context);
    bytes.extend(statement.transcript_bytes());
    bytes
}

impl Envelope {
    pub fn profile(&self) -> Profile {
        match self {
            Self::Public { .. } => Profile::Public,
            Self::Zk { .. } => Profile::Zk,
            Self::StatePublic { .. } => Profile::StatePublic,
            Self::Succinct { .. } => Profile::Succinct,
            Self::Machine { .. } => Profile::Machine,
            Self::Recursive { .. } => Profile::Recursive,
            Self::Wrapped { .. } => Profile::Wrapped,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = codec::Writer::default();
        w.raw(MAGIC);
        w.raw(&VERSION.to_le_bytes());
        w.raw(&[self.profile() as u8]);
        body::encode(self, &mut w);
        w.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > MAX_BYTES {
            return Err(EnvelopeError::TooLarge);
        }
        let mut r = codec::Reader::new(bytes);
        if r.raw(8).map_err(|_| EnvelopeError::BadMagic)? != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let version = u16::from_le_bytes([r.byte()?, r.byte()?]);
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let profile = match r.byte()? {
            0 => Profile::Public,
            1 => Profile::Succinct,
            2 => Profile::Zk,
            3 => Profile::StatePublic,
            4 => Profile::Machine,
            5 => Profile::Recursive,
            6 => Profile::Wrapped,
            other => return Err(EnvelopeError::UnknownProfile(other)),
        };
        let envelope = body::decode(profile, &mut r)?;
        r.finish()?;
        Ok(envelope)
    }

    /// Verify the proof against its own statement. The state profiles (3,
    /// 1 with a state statement, 4–6 with a machine statement that reads
    /// state) need `state`: zheng authenticates it under the statement's
    /// root and every read against it; the other profiles never consult
    /// it.
    pub fn verify(&self, state: Option<&StateEvidence>) -> Result<(), String> {
        match self {
            Self::Public {
                statement,
                certificate,
            } => verify_certificate(statement, certificate),
            Self::Zk {
                statement,
                context,
                proof: ZkProof::Veil(proof),
            } => veil::verify_bound(statement, proof, None, &zk_statement_bytes(statement, context)),
            Self::Zk {
                statement,
                context,
                proof: ZkProof::Mith(proof),
            } => {
                let prepared = statement.prepare()?;
                let public: Vec<_> = prepared
                    .public_coordinates
                    .iter()
                    .map(|&(i, v)| (i, nebu::Goldilocks::new(v)))
                    .collect();
                zk::verify(
                    &prepared.relation.instance,
                    proof,
                    &zk_statement_bytes(statement, context),
                    &public,
                )
                .map_err(|e| e.to_string())
            }
            Self::StatePublic {
                statement,
                certificate,
            } => statement.verify_certificate(
                certificate,
                state.ok_or("state envelope: no state evidence")?,
            ),
            Self::Succinct { statement, proof } => succinct::verify(statement, proof, state),
            Self::Machine {
                params,
                statement,
                proof,
            } => crate::machine::verify_with_state(statement, proof, params, state),
            Self::Recursive {
                params,
                statement,
                proof,
            } => recursive::verify(params, statement, proof, state),
            Self::Wrapped { statement, proof } => wrapped::verify(statement, proof, state),
        }
    }
}
