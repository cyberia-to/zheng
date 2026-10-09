//! The nox machine: one uniform step relation for nox reductions of any
//! length (`specs/machine.md`).
//!
//! A run is a trace of 64-column rows — init entries, one row per machine
//! step (dispatch, return, axis level, hash_data, pair equality), and
//! 32-row blocks of hemera permutations computing noun digests — with a
//! write-once memory (nouns, continuation frames, digests) checked by a
//! logUp argument. The row relation is the same for every program: the
//! verifier key is the constraint structure; a program enters through the
//! statement's public columns and constants. [`prove`] runs nox, builds
//! the trace, proves the AIR, accumulates its two committed words and
//! decides the accumulator with one WHIR opening; [`verify`] derives the
//! AIR from the statement and checks all three parts.

pub mod air;
mod control;
mod control_eval;
mod control_ret;
mod exec;
pub mod hemera;
pub mod layout;
mod memory;
mod perm;
mod phase2;
mod run;
mod run_eq;
mod slots;
pub mod statement;
mod trace;

#[cfg(test)]
mod tests;

pub use exec::MachineError;
pub use statement::MachineStatement;

use lens::{Transcript, WhirParams};

use crate::accumulate::{self, AccConfig, AccProof, DeciderProof};
use crate::air::{self as uair, AirProof, Trace};
use crate::execution::ExecutionNoun;
use air::{Constants, Machine};
use exec::Builder;
use run::Digests;

/// A machine proof: trace geometry, the AIR messages, one accumulation
/// step over its two committed words, and the decider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineProof {
    pub log_rows: u32,
    /// First row of the permutation region.
    pub start: u64,
    pub air: AirProof,
    pub acc: AccProof,
    pub decider: DeciderProof,
}

/// Largest trace this implementation proves (`2^MAX_LOG_ROWS` rows).
pub const MAX_LOG_ROWS: u32 = 22;

/// The run of a statement: trace, region start and the statement.
pub struct Run {
    pub statement: MachineStatement,
    pub trace: Trace,
    pub start: usize,
    pub machine: Machine,
}

/// Run `program` on `input` natively and build the machine trace.
pub fn execute(program: &ExecutionNoun, input: &[u64], budget: u64) -> Result<Run, MachineError> {
    let mut st = MachineStatement {
        program: statement::tokens(program),
        input: input.to_vec(),
        output: vec![],
        cycles: 0,
        budget,
    };
    let derived = st.init().map_err(|_| MachineError::Native("statement"))?;
    let tables = hemera::Tables::default();
    let mut b = Builder::default();
    trace::init_rows(&mut b, &derived.entries);
    let mut dg = Digests::default();
    let (result, cycles) = run::run(&mut b, &mut dg, &tables, derived.fml0, derived.obj0, budget)?;
    st.cycles = cycles;
    st.output = statement::tokens(&noun_of(&b, result));
    let (trace, start, _) = trace::finish(b, &mut dg, &tables);
    let constants = Constants {
        fml0: derived.fml0,
        obj0: derived.obj0,
        p: derived.entries.len() as u64,
        output: statement::digest(&statement::parse(&st.output).expect("own output")),
        cycles,
    };
    let machine = Machine::new(constants, &statement::init_columns(&derived.entries), start);
    Ok(Run {
        statement: st,
        trace,
        start,
        machine,
    })
}

fn noun_of(b: &Builder, id: u64) -> ExecutionNoun {
    match b.entry(id) {
        Some(exec::Entry::Atom(v)) => ExecutionNoun::Atom(v),
        Some(exec::Entry::Pair(l, r)) => {
            ExecutionNoun::Pair(Box::new(noun_of(b, l)), Box::new(noun_of(b, r)))
        }
        _ => unreachable!("result is a noun"),
    }
}

fn transcript(st: &MachineStatement, log_rows: u32, start: u64) -> Transcript {
    let mut t = Transcript::new(b"zheng-machine-v1");
    let bytes = st.bytes();
    t.absorb_u64(bytes.len() as u64);
    t.absorb(&bytes);
    t.absorb_u64(u64::from(log_rows));
    t.absorb_u64(start);
    t
}

fn acc_config(whir: &WhirParams, log_rows: u32) -> Result<AccConfig, String> {
    let vars = log_rows as usize + layout::W1.trailing_zeros() as usize;
    AccConfig::derive(whir, vars, 2, 2)
}

/// Prove a run.
pub fn prove_run(run: &Run, whir: &WhirParams) -> Result<MachineProof, String> {
    let rows = run.trace.rows();
    let log_rows = rows.trailing_zeros();
    if log_rows > MAX_LOG_ROWS {
        return Err(format!("machine: 2^{log_rows} rows > 2^{MAX_LOG_ROWS}"));
    }
    let cfg = acc_config(whir, log_rows)?;
    let mut t = transcript(&run.statement, log_rows, run.start as u64);
    let (air, words) = uair::prove(
        &run.machine,
        whir,
        &run.trace,
        |ch| phase2::build(&run.machine, &run.trace, ch),
        &mut t,
    )?;
    accumulate::bind(&mut t, &cfg);
    let inputs: Vec<&accumulate::Witnessed> = words.iter().collect();
    let (accw, acc) = accumulate::accumulate(&cfg, &inputs, &mut t)?;
    let decider = accumulate::decide(&cfg, &accw, &mut t)?;
    Ok(MachineProof {
        log_rows,
        start: run.start as u64,
        air,
        acc,
        decider,
    })
}

/// Run and prove.
pub fn prove(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    whir: &WhirParams,
) -> Result<(MachineStatement, MachineProof), String> {
    let run = execute(program, input, budget).map_err(|e| format!("machine: {e:?}"))?;
    let proof = prove_run(&run, whir)?;
    Ok((run.statement, proof))
}

/// Verify a machine proof against its statement (WHIR parameters are the
/// proof's, admitted by the 128-bit policy).
pub fn verify(st: &MachineStatement, proof: &MachineProof, whir: &WhirParams) -> Result<(), String> {
    let derived = st.derive()?;
    let (n, start) = (proof.log_rows, proof.start as usize);
    if n > MAX_LOG_ROWS
        || n < 6
        || !start.is_multiple_of(layout::BLOCK)
        || start <= derived.entries.len()
        || start >= 1 << n
    {
        return Err("machine: geometry".into());
    }
    crate::execution::succinct::admit::<lens::Whir>(whir, n as usize + 6)?;
    let constants = Constants {
        fml0: derived.fml0,
        obj0: derived.obj0,
        p: derived.entries.len() as u64,
        output: derived.output,
        cycles: st.cycles,
    };
    let machine = Machine::new(constants, &statement::init_columns(&derived.entries), start);
    let cfg = acc_config(whir, n)?;
    let mut t = transcript(st, n, proof.start);
    let insts = uair::verify(&machine, n as usize, &proof.air, &mut t)?;
    accumulate::bind(&mut t, &cfg);
    let refs: Vec<&accumulate::Instance> = insts.iter().collect();
    let acc = accumulate::verify_step(&cfg, &refs, &proof.acc, &mut t)?;
    accumulate::verify_decider(&cfg, &acc, &proof.decider, &mut t)
}
