//! Incrementally verifiable nox runs: prove every segment as one step
//! whose circuit verifies the previous step, keep only the last step, and
//! decide its accumulator once (`specs/recursion.md` § IVC).
//!
//! ```text
//! run       nox, trace in segments of exactly 2^n rows
//! pre       commit every segment's nox phase 1 (word a) → chain D;
//!           (α, β) = H(statement, D); nox phase 2 for every segment
//! step i    circuit: verify step i−1 from state_{i−1} (base step: none) →
//!           state_i, public input H(state_i); prove segment i ‖ circuit
//! proof     state_{S−1}, step S−1's proof, the decider of its accumulator
//!           and of the circuit key's claim
//! verify    the final verifier (`finalv`) natively: step S−1 → state_S;
//!           state_S is final (context, chain, step count, cyclic
//!           boundary), the deferred constraint claim holds, the decider
//!           accepts; then the deferred nox-public claim against the
//!           statement's columns
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use lens::WhirParams;
use nebu::{Fp3, Goldilocks};

use super::circuit::air::CircuitAir;
use super::circuit::builder::Builder;
use super::circuit::trace::{self, Pre};
use super::decide::{self, Decider, KeyWords};
use super::finalv::{self, Publics};
use super::ops::{Native, Ops};
use super::params::Params;
use super::perm::tag;
use super::program;
use super::prove::{self, AccData, StepInput, pbar_nox, pbar_v};
use super::relation::{G_POINT, Relation, WORD};
use super::sponge::Sponge;
use super::state::{self, CtxParts, State, ZeroWord};
use super::step::{self, StepProof};
use super::whir;
use super::word::{Digest, Word};
use crate::air::Public;
use crate::air::num::{Graph, record};
use crate::execution::ExecutionNoun;
use crate::machine::air::{Constants, Machine};
use crate::machine::layout::BLOCK;
use crate::machine::{self, MachineStatement, Run, statement};

/// A recursive proof of a nox run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IvcProof {
    pub log_rows: u32,
    pub start: u64,
    pub segments: u64,
    /// The chain of pre-committed roots.
    pub chain: Digest,
    /// The state the last step started from.
    pub state: State,
    pub step: StepProof,
    pub decider: Decider,
}

/// The circuit's key at one parameter set.
pub struct Key {
    pub params: Params,
    pub pre: Pre,
    /// The key's nonzero entries per column (`P̄_V` evaluations).
    pub sparse: Vec<Vec<(u32, Fp3)>>,
    /// The key as two committed 64-column words (the decider opens them).
    pub kw: KeyWords,
    /// Whether a key entry leaves the base field.
    pub key_ext: bool,
    /// The decider's batched opening: accumulator, two key words.
    pub dcfg: whir::Config,
    /// The step relation's constraint polynomial `G` as a graph over the
    /// point, the run's challenges and the statement constants.
    pub g: Graph,
}

fn layout(p: &Params, air: &CircuitAir) -> Result<(Pre, usize), String> {
    let mut b = Builder::new(false);
    let live = b.live_var();
    let parts = CtxParts { statement: [Goldilocks::ZERO; 4], chain: [Goldilocks::ZERO; 4], g0: Fp3::ZERO, pn0: Fp3::ZERO, pv0: Fp3::ZERO };
    program::run(&mut b, p, live, &program::dummy_state(p), &program::dummy_proof(p), &parts, |b, c| b.set_output(c));
    let (_, pre, out) = trace::generate(&b, air, p.n)?;
    Ok((pre, out))
}

/// Derive (or fetch) the key of `(whir, n)`.
pub fn key(whir: &WhirParams, n: usize) -> Result<Arc<Key>, String> {
    type Cache = Mutex<HashMap<([u8; 8], usize), Arc<Key>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(k) = cache.lock().expect("key cache").get(&(whir.header(), n)) {
        return Ok(k.clone());
    }
    let mut p = Params::new(whir, n)?;
    let air = CircuitAir::default();
    let (_, out) = layout(&p, &air)?;
    p.out_row = out;
    let (pre, out2) = layout(&p, &air)?;
    if out2 != out {
        return Err("recursion: the circuit layout moved".into());
    }
    let sparse = pre
        .cols
        .iter()
        .map(|c| c.iter().enumerate().filter(|(_, v)| **v != Fp3::ZERO).map(|(i, &v)| (i as u32, v)).collect())
        .collect();
    let (kw, key_ext) = KeyWords::commit(p.cfg.layout, p.n, &pre);
    let dcfg = whir::Config::derive(&p.whir, p.vars, &[1, 2], p.cfg.acc_claims() + 2)?;
    let g = g_graph(&p);
    let k = Arc::new(Key { params: p, pre, sparse, kw, key_ext, dcfg, g });
    cache.lock().expect("key cache").insert((whir.header(), n), k.clone());
    Ok(k)
}

/// `G` recorded once: inputs are the deferred point, the run's challenges
/// and the statement constants (its structure is the statement's for no
/// statement).
fn g_graph(p: &Params) -> Graph {
    use crate::machine::air::{KCONSTS, KConst};
    let constants = Constants { fml0: 0, obj0: 0, p: 0, output: [Goldilocks::ZERO; 4], cycles: 0, root: [Goldilocks::ZERO; 4] };
    let rel = Relation::new(Machine::new(constants, &[], 1 << p.n, 0, 1 << p.n), [Fp3::ZERO; 2]);
    record(G_POINT + 2 + KCONSTS, |i| {
        let (pt, rest) = i.split_at(G_POINT);
        vec![rel.g_with(pt, &[rest[0], rest[1]], &KConst::from_slice(&rest[2..]))]
    })
}

/// The statement and the trace geometry, hashed.
pub fn statement_digest(st: &MachineStatement, n: usize, start: u64, segments: u64) -> Digest {
    let mut o = Native::new();
    let mut sp = Sponge::new(&mut o, tag::CTX + 16);
    let bytes = st.bytes();
    let base = |v: u64| Fp3::from_base(Goldilocks::new(v));
    sp.absorb(&mut o, base(bytes.len() as u64));
    for c in bytes.chunks(4) {
        let mut b = [0u8; 4];
        b[..c.len()].copy_from_slice(c);
        sp.absorb(&mut o, base(u64::from(u32::from_le_bytes(b))));
    }
    for v in [n as u64, start, segments] {
        sp.absorb(&mut o, base(v));
    }
    core::array::from_fn(|_| sp.squeeze(&mut o).c0)
}

/// The run's memory challenges, after every pre-committed root.
pub fn run_challenges(sd: Digest, chain: Digest) -> [Fp3; 2] {
    let mut o = Native::new();
    let mut sp = Sponge::new(&mut o, tag::CTX + 17);
    for v in sd.iter().chain(&chain) {
        sp.absorb(&mut o, Fp3::from_base(*v));
    }
    [sp.squeeze_ext(&mut o), sp.squeeze_ext(&mut o)]
}

fn digest_vals(d: &[Fp3; 4]) -> Digest {
    [d[0].c0, d[1].c0, d[2].c0, d[3].c0]
}

/// The context's parts for a run.
fn parts(p: &Params, key: &[Vec<(u32, Fp3)>], rel: &Relation, global: &[Public], sd: Digest, chain: Digest) -> CtxParts {
    CtxParts {
        statement: sd,
        chain,
        g0: rel.g(&vec![Fp3::ZERO; G_POINT]),
        pn0: pbar_nox(global, &vec![Fp3::ZERO; p.dims.pn], p.n),
        pv0: pbar_v(key, &vec![Fp3::ZERO; p.dims.pv], p.n),
    }
}

/// Run `program` and prove it recursively in steps of `2^n` rows.
pub fn prove(program: &ExecutionNoun, input: &[u64], budget: u64, whir: &WhirParams, n: u32) -> Result<(MachineStatement, IvcProof), String> {
    let run = machine::execute_exact(program, input, budget, n).map_err(|e| format!("machine: {e:?}"))?;
    let proof = prove_run(&run, whir)?;
    Ok((run.statement, proof))
}

fn timer() -> impl Fn(&str) {
    timer_pub("  ")
}

/// `ZHENG_TIMING` laps (cumulative milliseconds).
pub fn timer_pub(indent: &'static str) -> impl Fn(&str) {
    let on = std::env::var_os("ZHENG_TIMING").is_some();
    let clock = std::time::Instant::now();
    move |what: &str| {
        if on {
            eprintln!("{indent}{what}: {:.1} ms", clock.elapsed().as_secs_f64() * 1e3);
        }
    }
}

fn nox_row0(seg: &crate::air::Trace, n2: &crate::air::Trace) -> Vec<Goldilocks> {
    seg.row(0).iter().chain(n2.row(0)).copied().collect()
}

/// Prove a run whose segments are the key's step size.
pub fn prove_run(run: &Run, whir: &WhirParams) -> Result<IvcProof, String> {
    let lap = timer();
    let n = run.seg_log as usize;
    let k = key(whir, n)?;
    let p = &k.params;
    let air = CircuitAir::default();
    let segs = run.segments();
    let layout = p.cfg.layout;
    // pre-commit every segment's nox phase 1
    let mut chain = [Goldilocks::ZERO; 4];
    let mut ood_a = Vec::with_capacity(segs);
    for i in 0..segs {
        let w = Word::commit_base(layout, &run.segment(i).column_major(WORD));
        let mut o = Native::new();
        let root = w.root().map(Fp3::from_base);
        let z = step::pre_points(&mut o, root, p.fresh);
        let ys: Vec<Fp3> = z.iter().map(|&z| w.univariate(z)).collect();
        chain = digest_vals(&step::chain_next(&mut o, chain.map(Fp3::from_base), root, &ys));
        ood_a.push(ys);
    }
    lap("pre-commit");
    let sd = statement_digest(&run.statement, n, run.start as u64, segs as u64);
    let ch = run_challenges(sd, chain);
    let global = Machine::new(run.constants.clone(), &run.init, run.start, 0, segs << n).publics;
    let rels: Vec<Relation> = (0..segs).map(|i| Relation::new(run.machine(i), ch)).collect();
    let ctx_parts = parts(p, &k.sparse, &rels[0], &global, sd, chain);
    let mut carry = Fp3::ZERO;
    let mut n2s = Vec::with_capacity(segs);
    for (i, rel) in rels.iter().enumerate() {
        let (w2, out) = machine::phase2_build(&rel.machine, &run.segment(i), &ch, carry);
        carry = out;
        n2s.push(w2);
    }
    let mut acc = AccData::Zero(ZeroWord::new(&layout));
    let mut prev: Option<(State, StepProof)> = None;
    let mut last_state = None;
    for i in 0..segs {
        let (st_prev, pf_prev) = match &prev {
            Some((s, f)) => (s.clone(), f.clone()),
            None => (program::dummy_state(p), program::dummy_proof(p)),
        };
        let mut b = Builder::new(i > 0);
        let live = b.live_var();
        let (out, h) = program::run(&mut b, p, live, &st_prev, &pf_prev, &ctx_parts, |b, c| b.set_output(c));
        b.finish()?;
        let st: State = state::StateV::from_items(&p.dims, &out.items().iter().map(|&(v, _)| b.value(v)).collect::<Vec<_>>());
        let x = digest_vals(&h.map(|v| b.value(v)));
        lap(&format!("circuit {i}"));
        let (v1, pre, out_row) = trace::generate(&b, &air, n)?;
        if out_row != p.out_row || pre.cols != k.pre.cols {
            return Err("recursion: the circuit's layout differs from its key".into());
        }
        drop(pre);
        let seg = run.segment(i);
        let word_a = Word::commit_base(layout, &seg.column_major(WORD));
        let j = (i + 1) % segs;
        let b_out = nox_row0(&run.segment(j), &n2s[j]);
        let input = StepInput {
            rel: &rels[i],
            global: &global,
            n1: &seg,
            n2: &n2s[i],
            word_a: &word_a,
            ood_a: &ood_a[i],
            b_out: &b_out,
            v1: &v1,
            key: &k.pre,
            sparse: &k.sparse,
        };
        let (pf, data, _) = prove::prove(p, &input, &st, x, &acc)?;
        // the prover checks its own step
        let mut o = Native::batched();
        let next = step::verify(&mut o, p, &st, x.map(Fp3::from_base), &pf);
        o.finish().map_err(|e| format!("step {i}: {e}"))?;
        acc = data;
        last_state = Some(next);
        prev = Some((st, pf));
        lap(&format!("step {i}"));
    }
    let (state, step) = prev.expect("a segment");
    let fin = last_state.expect("a segment");
    let AccData::Word(word) = acc else { return Err("recursion: the last accumulator".into()) };
    let decider = decide::prove(&k.dcfg, &word, &fin.acc, &fin.pv, &k.kw, n)?;
    lap("decide");
    Ok(IvcProof { log_rows: n as u32, start: run.start as u64, segments: segs as u64, chain, state, step, decider })
}

/// The statement-side work of a verification: everything that depends on
/// the statement and the proof's header only (reused across proofs of the
/// same run).
pub struct Prepared {
    pub key: Arc<Key>,
    pub header: (u32, u64, u64, Digest),
    /// The final verifier's public values.
    pub publics: Publics<Fp3>,
    /// The run's nox public columns (the deferred nox-public claim).
    pub global: Vec<Public>,
}

/// Prepare the verification of proofs of `st` with this header.
pub fn prepare(st: &MachineStatement, whir: &WhirParams, log_rows: u32, start: u64, segments: u64, chain: Digest) -> Result<Prepared, String> {
    let n = log_rows as usize;
    if !(10..=20).contains(&n) {
        return Err("recursion: step size".into());
    }
    let key = key(whir, n)?;
    let derived = st.derive()?;
    let (segs, st_row) = (segments as usize, start as usize);
    if segs == 0 || segs > 1 << 32 || !st_row.is_multiple_of(BLOCK) || st_row <= derived.entries.len() || st_row + BLOCK > segs << n {
        return Err("recursion: geometry".into());
    }
    let constants = Constants {
        fml0: derived.fml0,
        obj0: derived.obj0,
        p: derived.entries.len() as u64,
        output: derived.output,
        cycles: st.cycles,
        root: derived.root,
    };
    let init = statement::init_columns(&derived.entries);
    let sd = statement_digest(st, n, start, segments);
    let ch = run_challenges(sd, chain);
    let global = Machine::new(constants.clone(), &init, st_row, 0, segs << n).publics;
    let rel = Relation::new(Machine::new(constants.clone(), &init, st_row, 0, 1 << n), ch);
    let ctx = state::ctx_native(&parts(&key.params, &key.sparse, &rel, &global, sd, chain));
    let base = |d: Digest| d.map(Fp3::from_base);
    let publics = Publics {
        ctx: base(ctx),
        chain: base(chain),
        segments: Fp3::from_base(Goldilocks::new(segments)),
        ch,
        k: constants.lift(),
    };
    Ok(Prepared { key, header: (log_rows, start, segments, chain), publics, global })
}

/// Verify a recursive proof of `st` under `whir`.
pub fn verify(st: &MachineStatement, proof: &IvcProof, whir: &WhirParams) -> Result<(), String> {
    let prep = prepare(st, whir, proof.log_rows, proof.start, proof.segments, proof.chain)?;
    verify_prepared(&prep, proof)
}

/// Shapes of a proof's state, step and decider under `key`.
pub fn check_shapes(key: &Key, proof: &IvcProof) -> Result<(), String> {
    let p = &key.params;
    step::check_shape(p, &proof.step)?;
    decide::check_shape(&key.dcfg, &proof.decider)?;
    let s = &proof.state;
    let shape_ok = s.b_first.len() == p.dims.boundary
        && s.b_last.len() == p.dims.boundary
        && s.acc.rho.len() == p.dims.vars
        && s.acc.ood.len() == p.dims.ood
        && s.acc.spot.len() == p.dims.spot
        && s.g.point.len() == p.dims.g
        && s.pn.point.len() == p.dims.pn
        && s.pv.point.len() == p.dims.pv
        && state::is_canonical(s);
    if shape_ok { Ok(()) } else { Err("recursion: state shape".into()) }
}

/// Verify against a preparation whose header must be the proof's: the
/// final verifier natively, then the deferred nox-public claim.
pub fn verify_prepared(prep: &Prepared, proof: &IvcProof) -> Result<(), String> {
    verify_claim(prep, proof).map(|_| ())
}

/// [`verify_prepared`], returning the deferred nox-public claim it checked
/// (a wrap binds it in its public input).
pub fn verify_claim(prep: &Prepared, proof: &IvcProof) -> Result<state::ClaimV<Fp3>, String> {
    let lap = timer();
    if prep.header != (proof.log_rows, proof.start, proof.segments, proof.chain) {
        return Err("recursion: header".into());
    }
    let k = &prep.key;
    check_shapes(k, proof)?;
    lap("setup");
    let mut o = Native::batched();
    let pubs = finalv::constants(&mut o, &prep.publics);
    let pn = finalv::run(&mut o, k, &pubs, &proof.state, &proof.step, &proof.decider);
    o.finish()?;
    lap("final verifier");
    if pbar_nox(&prep.global, &pn.point, k.params.n) != pn.value {
        return Err("recursion: deferred nox publics".into());
    }
    lap("nox publics");
    Ok(pn)
}
