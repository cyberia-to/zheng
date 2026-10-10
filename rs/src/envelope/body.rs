//! Profile bodies of the envelope.
use super::codec::{Reader, Writer};
use super::{Envelope, EnvelopeError as E, Profile};
use crate::execution::private::PrivateStatement;
use crate::execution::state::{MAX_READS, PublicLookup, StateStatement};
use crate::execution::zk::{self, PrivateProof};
use crate::execution::{
    Certificate, ExecutionStatement, MAX_INPUTS, MAX_OUTPUTS, MAX_PROGRAM_NODES, NounToken,
};

/// Free witness positions a certificate may carry: the largest relation the
/// public verifier admits has 2^20 columns.
pub const MAX_FREE: usize = 1 << 20;

pub(super) fn encode(envelope: &Envelope, w: &mut Writer) {
    match envelope {
        Envelope::Public {
            statement,
            certificate,
        } => {
            execution(statement, w);
            free(certificate, w);
        }
        Envelope::Zk {
            statement,
            context,
            proof,
        } => {
            execution(&statement.execution, w);
            w.raw(context);
            w.len(proof.as_bytes().len());
            w.raw(proof.as_bytes());
        }
        Envelope::StatePublic {
            statement,
            certificate,
        } => {
            execution(&statement.execution, w);
            for limb in statement.state_root {
                w.varint(limb);
            }
            w.raw(&statement.context);
            w.bool(statement.root_in_subject);
            w.len(statement.reads.len());
            for read in &statement.reads {
                w.bool(read.active);
                for v in [read.namespace, read.key, read.value] {
                    w.varint(v);
                }
            }
            free(certificate, w);
        }
    }
}

pub(super) fn decode(profile: Profile, r: &mut Reader) -> Result<Envelope, E> {
    match profile {
        Profile::Public => Ok(Envelope::Public {
            statement: read_execution(r)?,
            certificate: read_free(r)?,
        }),
        Profile::Zk => {
            let execution = read_execution(r)?;
            let context = read_context(r)?;
            let n = r.len(zk::MAX_BYTES, 1)?;
            let proof = PrivateProof::from_bytes(r.raw(n)?).map_err(|_| E::NonCanonical)?;
            Ok(Envelope::Zk {
                statement: PrivateStatement { execution },
                context,
                proof,
            })
        }
        Profile::StatePublic => {
            let execution = read_execution(r)?;
            let mut state_root = [0u64; 4];
            for limb in &mut state_root {
                *limb = r.field()?;
            }
            let context = read_context(r)?;
            let root_in_subject = r.bool()?;
            let n = r.len(MAX_READS, 4)?;
            let mut reads = Vec::with_capacity(n);
            for _ in 0..n {
                let active = r.bool()?;
                let (namespace, key, value) = (r.field()?, r.field()?, r.field()?);
                if !active && (namespace, key, value) != (0, 0, 0) {
                    return Err(E::NonCanonical);
                }
                reads.push(PublicLookup {
                    active,
                    namespace,
                    key,
                    value,
                });
            }
            Ok(Envelope::StatePublic {
                statement: StateStatement {
                    execution,
                    state_root,
                    context,
                    root_in_subject,
                    reads,
                },
                certificate: read_free(r)?,
            })
        }
        Profile::Succinct => Err(E::ReservedProfile(Profile::Succinct)),
    }
}

pub(super) fn execution(s: &ExecutionStatement, w: &mut Writer) {
    w.len(s.program.len());
    for token in &s.program {
        match token {
            NounToken::Atom(v) => {
                w.bool(false);
                w.varint(*v);
            }
            NounToken::Pair => w.bool(true),
        }
    }
    for values in [&s.public_input, &s.public_output] {
        w.len(values.len());
        for &v in values {
            w.varint(v);
        }
    }
    w.varint(s.cycles);
    w.varint(s.budget);
}

fn read_execution(r: &mut Reader) -> Result<ExecutionStatement, E> {
    let n = r.len(MAX_PROGRAM_NODES, 1)?;
    let mut program = Vec::with_capacity(n);
    for _ in 0..n {
        program.push(if r.bool()? {
            NounToken::Pair
        } else {
            NounToken::Atom(r.field()?)
        });
    }
    let public_input = r.fields(MAX_INPUTS)?;
    let public_output = r.fields(MAX_OUTPUTS)?;
    let cycles = r.field()?;
    let budget = r.field()?;
    if cycles > budget {
        return Err(E::NonCanonical);
    }
    Ok(ExecutionStatement {
        program,
        public_input,
        public_output,
        cycles,
        budget,
    })
}

fn free(c: &Certificate, w: &mut Writer) {
    w.len(c.free.len());
    for &v in &c.free {
        w.varint(v);
    }
}

fn read_free(r: &mut Reader) -> Result<Certificate, E> {
    let free = r.fields(MAX_FREE)?;
    if free.last() == Some(&0) {
        return Err(E::NonCanonical);
    }
    Ok(Certificate { free })
}

fn read_context(r: &mut Reader) -> Result<[u8; 32], E> {
    let mut context = [0u8; 32];
    context.copy_from_slice(r.raw(32)?);
    Ok(context)
}
