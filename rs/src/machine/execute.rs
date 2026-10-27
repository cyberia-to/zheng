//! The native run of a statement: init rows, the run loop, the trace.

use super::exec::{Builder, Hints, MachineError};
use super::run::{self, Digests};
use super::{
    Constants, MachineState, MachineStatement, Run, SEGMENT_LOG_ROWS, hemera, run_ops, statement,
    trace,
};
use crate::execution::ExecutionNoun;

/// Run `program` on `input` natively and build the machine trace, in
/// segments of at most `2^seg_max` rows.
pub fn execute_with(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    seg_max: u32,
) -> Result<Run, MachineError> {
    execute_hinted(program, input, budget, seg_max, &Hints::default())
}

/// Run and build the trace in segments of exactly `2^seg_log` rows (the
/// recursion profile's fixed step size).
pub fn execute_exact(program: &ExecutionNoun, input: &[u64], budget: u64, seg_log: u32) -> Result<Run, MachineError> {
    execute_sized(program, input, budget, seg_log, seg_log, &Hints::default())
}

/// [`execute_with`] at the default segment size.
pub fn execute(program: &ExecutionNoun, input: &[u64], budget: u64) -> Result<Run, MachineError> {
    execute_with(program, input, budget, SEGMENT_LOG_ROWS)
}

/// [`execute_with`] with call witnesses and the state `look` reads. The
/// evidence is authenticated under its root before the run; a run that
/// reads state is executed twice (the first run finds the reads the init
/// region must carry).
pub fn execute_hinted(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    seg_max: u32,
    hints: &Hints<'_>,
) -> Result<Run, MachineError> {
    execute_sized(program, input, budget, 0, seg_max, hints)
}

/// Segments of one power of two of at least `2^seg_min` rows, or a
/// multiple of `2^seg_max` rows.
fn execute_sized(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    seg_min: u32,
    seg_max: u32,
    hints: &Hints<'_>,
) -> Result<Run, MachineError> {
    let auth = match hints.state {
        Some((evidence, root)) => Some(
            evidence
                .authenticate(root)
                .map_err(|_| MachineError::Native("state evidence"))?,
        ),
        None => None,
    };
    let mut reads: Vec<(u64, u64, u64)> = Vec::new();
    for _ in 0..2 {
        let mut st = MachineStatement {
            program: statement::tokens(program),
            input: input.to_vec(),
            output: vec![],
            cycles: 0,
            budget,
            state: hints
                .state
                .filter(|_| !reads.is_empty())
                .map(|(_, root)| MachineState {
                    root,
                    reads: reads.clone(),
                }),
        };
        let derived = st.init().map_err(|_| MachineError::Native("statement"))?;
        let tables = hemera::Tables::default();
        let mut b = Builder::default();
        trace::init_rows(&mut b, &derived.entries);
        let nouns = derived.entries.len() - reads.len();
        let mut ctx = run_ops::Ctx {
            hints: *hints,
            auth,
            root: hints.state.map_or([0; 4], |(_, r)| r),
            state_ids: reads
                .iter()
                .enumerate()
                .map(|(i, &(n, k, _))| ((n, k), (nouns + i + 1) as u64))
                .collect(),
            reads: Vec::new(),
            missing: false,
        };
        let mut dg = Digests::default();
        let (result, cycles) = run::run(
            &mut b,
            &mut dg,
            &tables,
            &mut ctx,
            derived.fml0,
            derived.obj0,
            budget,
        )?;
        if ctx.missing {
            reads = ctx.reads;
            continue;
        }
        st.cycles = cycles;
        st.output = statement::tokens(&run_ops::noun_of(&b, result));
        let (trace, start, seg_log) = trace::finish(b, &mut dg, &tables, seg_min, seg_max);
        let constants = Constants {
            fml0: derived.fml0,
            obj0: derived.obj0,
            p: derived.entries.len() as u64,
            output: statement::digest(&statement::parse(&st.output).expect("own output")),
            cycles,
            root: derived.root,
        };
        return Ok(Run {
            statement: st,
            trace,
            start,
            seg_log,
            constants,
            init: statement::init_columns(&derived.entries),
        });
    }
    Err(MachineError::Native("state reads changed between runs"))
}
