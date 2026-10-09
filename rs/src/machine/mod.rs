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

use lens::{MultilinearPcs, Transcript, WhirParams};

use crate::accumulate::{self, AccConfig, AccProof, DeciderProof};
use crate::air::{self as uair, AirProof, Trace};
use crate::execution::ExecutionNoun;
use air::{Constants, Machine};
use exec::Builder;
use run::Digests;

/// A machine proof: trace geometry, the AIR messages of every segment,
/// one accumulation step per segment over its two committed words, and the
/// decider of the last accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineProof {
    /// `log2` of a segment's rows.
    pub log_rows: u32,
    /// First row of the permutation region (global).
    pub start: u64,
    pub air: AirProof,
    pub accs: Vec<AccProof>,
    pub decider: DeciderProof,
}

impl MachineProof {
    /// `u8 log_rows · u64 start · AirProof · u32 S · S × AccProof · DeciderProof`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = lens::rspcs::wire::Writer::default();
        w.u8(self.log_rows as u8);
        w.u64(self.start);
        self.air.write(&mut w);
        w.u32(self.accs.len());
        for a in &self.accs {
            a.write(&mut w);
        }
        self.decider.write(&mut w, true);
        w.buf
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut r = lens::rspcs::wire::Reader::new(bytes);
        let e = |e: lens::PcsError| format!("machine proof: {e}");
        let log_rows = u32::from(r.u8().map_err(e)?);
        let start = r.u64().map_err(e)?;
        let air = AirProof::read(&mut r).map_err(e)?;
        let s = r.count(64).map_err(e)?;
        let accs = (0..s)
            .map(|_| AccProof::read(&mut r))
            .collect::<Result<_, _>>()
            .map_err(e)?;
        let (decider, ext) = DeciderProof::read(&mut r).map_err(e)?;
        r.finish().map_err(e)?;
        if !ext {
            return Err("machine proof: decider of a base word".into());
        }
        Ok(Self {
            log_rows,
            start,
            air,
            accs,
            decider,
        })
    }
    pub fn air_bytes(&self) -> usize {
        self.air.to_bytes().len()
    }
    pub fn acc_bytes(&self) -> usize {
        self.accs.iter().map(|a| a.to_bytes().len()).sum()
    }
    pub fn decider_bytes(&self) -> usize {
        let mut w = lens::rspcs::wire::Writer::default();
        self.decider.write(&mut w, true);
        w.buf.len()
    }
}

/// Largest segment this implementation proves (`2^MAX_LOG_ROWS` rows).
pub const MAX_LOG_ROWS: u32 = 18;
/// Default segment size for long runs.
pub const SEGMENT_LOG_ROWS: u32 = 14;

/// The run of a statement: the global trace, its geometry, the statement.
pub struct Run {
    pub statement: MachineStatement,
    pub trace: Trace,
    pub start: usize,
    pub seg_log: u32,
    pub constants: Constants,
    pub init: Vec<(u64, u64, u64)>,
}

impl Run {
    pub fn segments(&self) -> usize {
        self.trace.rows() >> self.seg_log
    }
    /// Segment `i`'s rows.
    pub fn segment(&self, i: usize) -> Trace {
        let len = (1usize << self.seg_log) * layout::W1;
        Trace {
            width: layout::W1,
            cells: self.trace.cells[i * len..(i + 1) * len].to_vec(),
        }
    }
    /// Segment `i`'s AIR.
    pub fn machine(&self, i: usize) -> Machine {
        let rows = 1usize << self.seg_log;
        Machine::new(self.constants.clone(), &self.init, self.start, i * rows, rows)
    }
}

/// Run `program` on `input` natively and build the machine trace, in
/// segments of at most `2^seg_max` rows.
pub fn execute_with(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    seg_max: u32,
) -> Result<Run, MachineError> {
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
    let (trace, start, seg_log) = trace::finish(b, &mut dg, &tables, seg_max);
    let constants = Constants {
        fml0: derived.fml0,
        obj0: derived.obj0,
        p: derived.entries.len() as u64,
        output: statement::digest(&statement::parse(&st.output).expect("own output")),
        cycles,
    };
    Ok(Run {
        statement: st,
        trace,
        start,
        seg_log,
        constants,
        init: statement::init_columns(&derived.entries),
    })
}

/// [`execute_with`] at the default segment size.
pub fn execute(program: &ExecutionNoun, input: &[u64], budget: u64) -> Result<Run, MachineError> {
    execute_with(program, input, budget, SEGMENT_LOG_ROWS)
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

/// Accumulation over `2^log_rows`-row segments: words of
/// `log_rows + log2(W1)` variables, up to three inputs (the accumulator and
/// a segment's two words, each with its OOD answers, its own claim and the
/// previous segment's boundary claim).
pub fn acc_config(whir: &WhirParams, log_rows: u32) -> Result<AccConfig, String> {
    let vars = log_rows as usize + layout::W1.trailing_zeros() as usize;
    let word = accumulate::fresh_ood(whir, vars)? + 2;
    let probe = AccConfig::derive(whir, vars, 3, 2 * word)?;
    AccConfig::derive(whir, vars, 3, probe.acc_claims() + 2 * word)
}

fn timer() -> impl Fn(&str) {
    let on = std::env::var_os("ZHENG_TIMING").is_some();
    let clock = std::time::Instant::now();
    move |what: &str| {
        if on {
            eprintln!("  {what}: {:.1} ms", clock.elapsed().as_secs_f64() * 1e3);
        }
    }
}

/// Prove a run.
pub fn prove_run(run: &Run, whir: &WhirParams) -> Result<MachineProof, String> {
    let n = run.seg_log;
    if n > MAX_LOG_ROWS {
        return Err(format!("machine: 2^{n}-row segments > 2^{MAX_LOG_ROWS}"));
    }
    let lap = timer();
    let cfg = acc_config(whir, n)?;
    let segs = run.segments();
    let machines: Vec<Machine> = (0..segs).map(|i| run.machine(i)).collect();
    let w1s: Vec<Trace> = (0..segs).map(|i| run.segment(i)).collect();
    let mut t = transcript(&run.statement, n, run.start as u64);
    let mut carry = nebu::Fp3::ZERO;
    let (air, w2s, words) = uair::prove(
        &machines,
        whir,
        &w1s,
        |i, ch| {
            let (w2, out) = phase2::build(&machines[i], &w1s[i], ch, carry);
            carry = out;
            w2
        },
        &mut t,
    )?;
    lap("air");
    accumulate::bind(&mut t, &cfg);
    let wp = layout::W1;
    let mut acc: Option<accumulate::Witnessed> = None;
    let mut accs = Vec::with_capacity(segs);
    for (i, pair) in words.into_iter().enumerate() {
        let [i1, i2] = pair;
        let d1 = lens::Whir::commit(whir, &w1s[i].column_major(wp)).1;
        let d2 = lens::Whir::commit(whir, &w2s[i].column_major(wp)).1;
        let x1 = accumulate::Witnessed { instance: i1, data: d1 };
        let x2 = accumulate::Witnessed { instance: i2, data: d2 };
        let mut inputs: Vec<&accumulate::Witnessed> = acc.iter().collect();
        inputs.push(&x1);
        inputs.push(&x2);
        let (next, proof) = accumulate::accumulate(&cfg, &inputs, &mut t)?;
        acc = Some(next);
        accs.push(proof);
    }
    lap("accumulate");
    let decider = accumulate::decide(&cfg, acc.as_ref().expect("a segment"), &mut t)?;
    lap("decide");
    Ok(MachineProof {
        log_rows: n,
        start: run.start as u64,
        air,
        accs,
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

/// Verify a machine proof against its statement under `whir` (admitted by
/// the 128-bit policy).
pub fn verify(st: &MachineStatement, proof: &MachineProof, whir: &WhirParams) -> Result<(), String> {
    let derived = st.derive()?;
    let (n, start) = (proof.log_rows, proof.start as usize);
    let segs = proof.air.segments.len();
    let rows = 1usize << n;
    if !(6..=MAX_LOG_ROWS).contains(&n)
        || segs == 0
        || proof.accs.len() != segs
        || !start.is_multiple_of(layout::BLOCK)
        || start <= derived.entries.len()
        || start + layout::BLOCK > segs * rows
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
    let init = statement::init_columns(&derived.entries);
    let machines: Vec<Machine> = (0..segs)
        .map(|i| Machine::new(constants.clone(), &init, start, i * rows, rows))
        .collect();
    let cfg = acc_config(whir, n)?;
    let mut t = transcript(st, n, proof.start);
    let words = uair::verify(&machines, whir, n as usize, &proof.air, &mut t)?;
    accumulate::bind(&mut t, &cfg);
    let mut acc: Option<accumulate::Instance> = None;
    for (pair, step) in words.iter().zip(&proof.accs) {
        let mut inputs: Vec<&accumulate::Instance> = acc.iter().collect();
        inputs.extend(pair.iter());
        acc = Some(accumulate::verify_step(&cfg, &inputs, step, &mut t)?);
    }
    accumulate::verify_decider(&cfg, acc.as_ref().expect("a segment"), &proof.decider, &mut t)
}
