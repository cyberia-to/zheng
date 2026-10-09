//! Profile 4 (machine) body: a nox run of any length proven by the
//! uniform step relation, its words accumulated and decided once.
//!
//! ```text
//! params     8 B      WHIR header (policy: ≥ 128 proven bits)
//! statement           program tokens, inputs, output tokens, cycles, budget
//! proof               the rest: `MachineProof::to_bytes`
//! ```
//!
//! Tokens: `len`, then per token `bool pair`, an atom as a canonical field
//! varint. Lengths are bounded by `machine::statement::MAX_TOKENS` and
//! `MAX_INPUTS`.

use lens::{Whir, WhirParams};

use super::codec::{Reader, Writer};
use super::{Envelope, EnvelopeError as E};
use crate::execution::NounToken;
use crate::execution::succinct::SuccinctPcs;
use crate::machine::statement::{MAX_INPUTS, MAX_TOKENS};
use crate::machine::{MachineProof, MachineStatement};

fn tokens(ts: &[NounToken], w: &mut Writer) {
    w.len(ts.len());
    for t in ts {
        match t {
            NounToken::Atom(v) => {
                w.bool(false);
                w.varint(*v);
            }
            NounToken::Pair => w.bool(true),
        }
    }
}

fn read_tokens(r: &mut Reader) -> Result<Vec<NounToken>, E> {
    let n = r.len(MAX_TOKENS, 1)?;
    (0..n)
        .map(|_| Ok(if r.bool()? { NounToken::Pair } else { NounToken::Atom(r.field()?) }))
        .collect()
}

/// The machine statement (profiles 4 and 5).
pub(super) fn statement(st: &MachineStatement, w: &mut Writer) {
    tokens(&st.program, w);
    w.len(st.input.len());
    for &v in &st.input {
        w.varint(v);
    }
    tokens(&st.output, w);
    w.varint(st.cycles);
    w.varint(st.budget);
}

pub(super) fn read_statement(r: &mut Reader) -> Result<MachineStatement, E> {
    let program = read_tokens(r)?;
    let input = r.fields(MAX_INPUTS)?;
    let output = read_tokens(r)?;
    let cycles = r.field()?;
    let budget = r.field()?;
    if cycles > budget {
        return Err(E::NonCanonical);
    }
    Ok(MachineStatement {
        program,
        input,
        output,
        cycles,
        budget,
    })
}

pub(super) fn encode(params: &WhirParams, st: &MachineStatement, proof: &MachineProof, w: &mut Writer) {
    w.raw(&params.header());
    statement(st, w);
    w.raw(&proof.to_bytes());
}

pub(super) fn decode(r: &mut Reader) -> Result<Envelope, E> {
    let params = Whir::params_from_header(r.raw(8)?).map_err(|_| E::NonCanonical)?;
    let statement = read_statement(r)?;
    let proof = MachineProof::from_bytes(r.raw(r.remaining())?).map_err(|_| E::NonCanonical)?;
    Ok(Envelope::Machine {
        params,
        statement,
        proof: Box::new(proof),
    })
}
