//! Profile 4 (machine) body: a nox run of any length proven by the
//! uniform step relation, its words accumulated and decided once.
//!
//! ```text
//! params     8 B      WHIR header (policy: ≥ 128 proven bits)
//! statement           program tokens, inputs, output tokens, cycles, budget,
//!                     state (bool; root 4 fields, reads: len, (ns, key, value)…)
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
use crate::machine::statement::{MAX_INPUTS, MAX_READS, MAX_TOKENS};
use crate::machine::{MachineProof, MachineState, MachineStatement};

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

pub(super) fn encode(params: &WhirParams, st: &MachineStatement, proof: &MachineProof, w: &mut Writer) {
    w.raw(&params.header());
    tokens(&st.program, w);
    w.len(st.input.len());
    for &v in &st.input {
        w.varint(v);
    }
    tokens(&st.output, w);
    w.varint(st.cycles);
    w.varint(st.budget);
    w.bool(st.state.is_some());
    if let Some(state) = &st.state {
        for v in state.root {
            w.varint(v);
        }
        w.len(state.reads.len());
        for &(n, k, v) in &state.reads {
            w.varint(n);
            w.varint(k);
            w.varint(v);
        }
    }
    w.raw(&proof.to_bytes());
}

pub(super) fn decode(r: &mut Reader) -> Result<Envelope, E> {
    let params = Whir::params_from_header(r.raw(8)?).map_err(|_| E::NonCanonical)?;
    let program = read_tokens(r)?;
    let input = r.fields(MAX_INPUTS)?;
    let output = read_tokens(r)?;
    let cycles = r.field()?;
    let budget = r.field()?;
    if cycles > budget {
        return Err(E::NonCanonical);
    }
    let state = if r.bool()? {
        let root = [r.field()?, r.field()?, r.field()?, r.field()?];
        let n = r.len(MAX_READS, 3)?;
        let reads = (0..n)
            .map(|_| Ok((r.field()?, r.field()?, r.field()?)))
            .collect::<Result<_, E>>()?;
        Some(MachineState { root, reads })
    } else {
        None
    };
    let proof = MachineProof::from_bytes(r.raw(r.remaining())?).map_err(|_| E::NonCanonical)?;
    Ok(Envelope::Machine {
        params,
        statement: MachineStatement {
            program,
            input,
            output,
            cycles,
            budget,
            state,
        },
        proof: Box::new(proof),
    })
}
