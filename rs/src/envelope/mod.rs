//! One proof envelope for every zheng profile.
//!
//! ```text
//! magic    8 bytes  "ZHENGPF1"
//! version  u16 LE   VERSION
//! profile  u8       0 public · 1 succinct (reserved) · 2 zk · 3 state-public
//! body              per profile, canonical (see `codec`)
//! ```
//!
//! Bodies:
//!
//! - public (0): execution statement, then the v3 certificate;
//! - zk (2): execution statement, a 32-byte caller context, then the
//!   `ZHMITH01` proof bytes (length-prefixed); the proof's statement bytes
//!   are [`zk_statement_bytes`];
//! - state-public (3): execution statement, state root (4 field limbs),
//!   32-byte context, root-in-subject flag, the reads, then the v3
//!   certificate.
//!
//! An execution statement is: program tokens (tag 0 + atom, tag 1 = pair),
//! public inputs, public outputs, cycles, budget. A certificate is the free
//! values with no trailing zero. Decoding rejects a wrong magic, an unknown
//! version, an unknown or reserved profile, any noncanonical integer, field
//! value or flag, any length beyond its bound, truncation and trailing bytes.

mod body;
mod codec;
#[cfg(test)]
mod tests;

use crate::execution::private::PrivateStatement;
use crate::execution::state::StateStatement;
use crate::execution::zk::{self, PrivateProof};
use crate::execution::{Certificate, ExecutionStatement, verify_certificate};
use core::fmt;

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
    /// Reserved for the committed-witness profile of phase 2; never decoded.
    Succinct = 1,
    Zk = 2,
    StatePublic = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    BadMagic,
    UnsupportedVersion(u16),
    UnknownProfile(u8),
    ReservedProfile(Profile),
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
        proof: PrivateProof,
    },
    StatePublic {
        statement: StateStatement,
        certificate: Certificate,
    },
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
            1 => return Err(EnvelopeError::ReservedProfile(Profile::Succinct)),
            2 => Profile::Zk,
            3 => Profile::StatePublic,
            other => return Err(EnvelopeError::UnknownProfile(other)),
        };
        let envelope = body::decode(profile, &mut r)?;
        r.finish()?;
        Ok(envelope)
    }

    /// Verify the proof against its own statement. `lookup` answers state
    /// reads for the state-public profile and MUST come from a state
    /// certificate already verified under that statement's root; the other
    /// profiles never consult it.
    pub fn verify(&self, lookup: &mut dyn FnMut(u64, u64) -> Option<u64>) -> Result<(), String> {
        match self {
            Self::Public {
                statement,
                certificate,
            } => verify_certificate(statement, certificate),
            Self::Zk {
                statement,
                context,
                proof,
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
            } => statement.verify_certificate(certificate, lookup),
        }
    }
}
