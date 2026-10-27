//! Profile 4 (machine) body: a nox run of any length proven by the
//! uniform step relation, its words accumulated and decided once.
//!
//! ```text
//! format     u8       MACHINE_FORMAT
//! params     8 B      WHIR header (policy: ≥ 128 proven bits)
//! statement  32 B     the program's digest (`machine::program_digest`),
//!                     then inputs, output tokens, cycles, budget, state
//!                     (bool; root 4 fields, reads: len, (ns, key, value)…)
//! proof               the rest: `MachineProof::to_bytes`
//! ```
//!
//! The statement of profiles 4–6 binds the program by its digest; the
//! verifier is given the program out of band (`Envelope::verify_program`,
//! `Envelope::from_bytes_for` refuses another program's envelope before
//! the proof is parsed). Tokens: `len`, then per token `bool pair`, an
//! atom as a canonical field varint. Lengths are bounded by
//! `machine::statement::MAX_TOKENS` and `MAX_INPUTS`.

use lens::{Whir, WhirParams};

use super::codec::{Reader, Writer};
use super::{Envelope, EnvelopeError as E};
use crate::execution::NounToken;
use crate::execution::succinct::SuccinctPcs;
use crate::machine::statement::{MAX_INPUTS, MAX_READS, MAX_TOKENS};
use crate::machine::{MachineProof, MachinePublic, MachineState};

/// Version of the profile-4 body (2: the program bound by its digest).
pub const MACHINE_FORMAT: u8 = 2;

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

/// The machine statement (profiles 4–6).
pub(super) fn statement(st: &MachinePublic, w: &mut Writer) {
    w.raw(&st.program);
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
}

/// Read a statement; with `expect`, a program digest other than the
/// expected one is refused here, before anything after the statement.
pub(super) fn read_statement(r: &mut Reader, expect: Option<&[u8; 32]>) -> Result<MachinePublic, E> {
    let program: [u8; 32] = r.raw(32)?.try_into().expect("32 bytes");
    if expect.is_some_and(|d| *d != program) {
        return Err(E::ProgramMismatch);
    }
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
    Ok(MachinePublic {
        program,
        input,
        output,
        cycles,
        budget,
        state,
    })
}

pub(super) fn encode(params: &WhirParams, st: &MachinePublic, proof: &MachineProof, w: &mut Writer) {
    w.raw(&[MACHINE_FORMAT]);
    w.raw(&params.header());
    statement(st, w);
    w.raw(&proof.to_bytes());
}

pub(super) fn decode(r: &mut Reader, expect: Option<&[u8; 32]>) -> Result<Envelope, E> {
    if r.byte()? != MACHINE_FORMAT {
        return Err(E::NonCanonical);
    }
    let params = Whir::params_from_header(r.raw(8)?).map_err(|_| E::NonCanonical)?;
    let statement = read_statement(r, expect)?;
    let proof = MachineProof::from_bytes(r.raw(r.remaining())?).map_err(|_| E::NonCanonical)?;
    Ok(Envelope::Machine {
        params,
        statement,
        proof: Box::new(proof),
    })
}
