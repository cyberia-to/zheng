//! Succinct-profile bake-off: TensorRs vs WHIR on the same fixtures, the
//! same zheng transcript and the same Spartan IOP; then the size levers on
//! a chosen configuration.
//!
//! ```text
//! cargo run --release -p zheng --example succinct_bakeoff -- bakeoff [reps]
//! cargo run --release -p zheng --example succinct_bakeoff -- levers [reps]
//! cargo run --release -p zheng --example succinct_bakeoff -- combos [reps]
//! ```
//!
//! Columns: `n` = 2^ℓ committed (free) witness slots; `rows` = CCS rows;
//! `proof B` = PCS id + params + root + Spartan + opening (the statement
//! excluded); `envelope B` = the whole ZHENGPF1 envelope (program fixtures
//! only); `spartan B` / `opening B` split the proof; `prove ms` = relation +
//! witness + commit + IOP + opening; `verify ms` = statement → relation →
//! IOP → opening (the full public API); `vfy-rel ms` = the same with the
//! relation already compiled; `pcs vfy ms` = the opening alone (lens verify
//! at the same size, parameters and point shape); `pcs bits` = lens's
//! proven bound; `total bits` = −log2(ε_spartan + ε_pcs). Median of `reps`.
#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;

use common::{ADD, HASH, hash_chain, parse, synthetic};
use nebu::{Fp3, Goldilocks};
use zheng::envelope::{AnySuccinct, Envelope, SuccinctStatement, succinct_proof_bytes};
use zheng::execution::succinct::{
    self, SuccinctPcs, SuccinctProof, TensorRs, TensorRsParams, Whir, WhirParams,
};
use zheng::execution::{ExecutionNoun, ExecutionStatement};
use zheng::types::CCSInstance;

pub(crate) enum Fixture {
    Program(&'static str, ExecutionNoun, Vec<u64>),
    Synthetic(u32),
}

impl Fixture {
    fn name(&self) -> String {
        match self {
            Fixture::Program(n, _, _) => (*n).into(),
            Fixture::Synthetic(k) => format!("synthetic 2^{k}"),
        }
    }
}

pub(crate) struct Row {
    fixture: String,
    pcs: String,
    vars: usize,
    rows: usize,
    proof: usize,
    envelope: Option<usize>,
    spartan: usize,
    opening: usize,
    prove: f64,
    verify: f64,
    verify_rel: f64,
    pcs_verify: f64,
    pcs_bits: f64,
    total_bits: f64,
    extra: String,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn log2_add(a: f64, b: f64) -> f64 {
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    hi + (1.0 + (lo - hi).exp2()).log2()
}

/// −log2 of the Spartan IOP error over Fp3 (specs/soundness.md, succinct row):
/// `(log m·(d + 2) + 2·(ℓ + 1) + t − 1) / p³`.
fn spartan_log_err(instance: &CCSInstance, vars: usize) -> f64 {
    let d = instance.multisets.iter().map(Vec::len).max().unwrap_or(1) as f64;
    let log_m = instance.num_rows.trailing_zeros() as f64;
    let t = instance.matrices.len() as f64;
    let terms = log_m * (d + 2.0) + 2.0 * (vars as f64 + 1.0) + t - 1.0;
    terms.log2() - 3.0 * (nebu::field::P as f64).log2()
}

/// The opening alone: lens commit/open/verify at the same size and params.
fn pcs_verify_ms<Pc: SuccinctPcs>(params: &Pc::Params, vars: usize, reps: usize) -> f64 {
    let evals: Vec<Goldilocks> = (0..1u64 << vars).map(|i| Goldilocks::new(i * 7 + 1)).collect();
    let point: Vec<Fp3> = (0..vars)
        .map(|i| Fp3::new(Goldilocks::new(3 + i as u64), Goldilocks::new(5), Goldilocks::new(i as u64)))
        .collect();
    let (root, data) = Pc::commit(params, &evals);
    let (value, proof) = Pc::open(params, &data, &point, &mut lens::Transcript::new(b"bench"));
    median(
        (0..reps)
            .map(|_| {
                let t = Instant::now();
                Pc::verify(params, &root, vars, &point, value, &proof, &mut lens::Transcript::new(b"bench"))
                    .unwrap();
                ms(t)
            })
            .collect(),
    )
}

fn sizes<Pc: SuccinctPcs>(p: &SuccinctProof<Pc>) -> (usize, usize) {
    let fp3 = 24;
    let spartan = (p.matrix_evals.len()
        + p.outer.rounds.iter().map(Vec::len).sum::<usize>()
        + p.inner.rounds.iter().map(Vec::len).sum::<usize>()
        + 1)
        * fp3;
    (spartan, Pc::proof_body(&p.opening).len())
}

pub(crate) fn run<Pc: SuccinctPcs>(
    label: &str,
    params: Pc::Params,
    fx: &Fixture,
    reps: usize,
    extra: impl Fn(&SuccinctProof<Pc>, usize) -> String,
) -> Option<Row>
where
    SuccinctProof<Pc>: Into<AnySuccinct>,
{
    let mut prove = Vec::new();
    let mut verify = Vec::new();
    let mut verify_rel = Vec::new();
    let (instance, pins, stmt, proof, envelope);
    match fx {
        Fixture::Program(_, program, input) => {
            let mut last: Option<(ExecutionStatement, SuccinctProof<Pc>)> = None;
            for _ in 0..reps {
                let t = Instant::now();
                match succinct::prove::<Pc>(&params, program, input, 1_000_000) {
                    Ok(r) => last = Some(r),
                    Err(e) => {
                        eprintln!("{label} {}: {e}", fx.name());
                        return None;
                    }
                }
                prove.push(ms(t));
            }
            let (statement, p) = last.unwrap();
            for _ in 0..reps {
                let t = Instant::now();
                succinct::verify(&statement, &p).unwrap();
                verify.push(ms(t));
            }
            let e = Envelope::Succinct {
                statement: SuccinctStatement::Execution(statement.clone()),
                proof: p.clone().into(),
            };
            envelope = Some(e.to_bytes().len());
            let (rel, pub_) = relation_of(&statement);
            instance = rel;
            pins = pub_;
            let vk = zheng::execution::VerifyingKey::for_execution(&statement).unwrap();
            stmt = succinct::keyed_statement(&vk, &statement.transcript_bytes());
            proof = p;
        }
        Fixture::Synthetic(k) => {
            let s = synthetic(*k, 3);
            let mut last = None;
            for _ in 0..reps {
                let t = Instant::now();
                match succinct::prove_relation::<Pc>(&params, &s.instance, &s.z, &s.pins, &s.statement) {
                    Ok(p) => last = Some(p),
                    Err(e) => {
                        eprintln!("{label} {}: {e}", fx.name());
                        return None;
                    }
                }
                prove.push(ms(t));
            }
            proof = last.unwrap();
            envelope = None;
            instance = s.instance;
            pins = s.pins;
            stmt = s.statement;
        }
    }
    for _ in 0..reps {
        let t = Instant::now();
        succinct::verify_relation(&instance, &pins, &stmt, &proof).unwrap();
        verify_rel.push(ms(t));
    }
    if verify.is_empty() {
        verify = verify_rel.clone();
    }
    let vars = proof_vars(&instance, &pins);
    let pcs_bits = Pc::security_bits(&proof.params, vars);
    let total_bits = -log2_add(spartan_log_err(&instance, vars), -pcs_bits);
    let (spartan, opening) = sizes(&proof);
    Some(Row {
        fixture: fx.name(),
        pcs: label.into(),
        vars,
        rows: instance.num_rows,
        proof: succinct_proof_bytes(&proof.clone().into()).len(),
        envelope,
        spartan,
        opening,
        prove: median(prove),
        verify: median(verify),
        verify_rel: median(verify_rel),
        pcs_verify: pcs_verify_ms::<Pc>(&proof.params, vars, reps.max(5)),
        pcs_bits,
        total_bits,
        extra: extra(&proof, vars),
    })
}

fn proof_vars(instance: &CCSInstance, pins: &[(usize, Goldilocks)]) -> usize {
    succinct::committed_vars(instance, pins).unwrap()
}

fn relation_of(s: &ExecutionStatement) -> (CCSInstance, Vec<(usize, Goldilocks)>) {
    succinct::relation_and_pins(s).unwrap()
}

pub(crate) fn header() {
    println!(
        "| fixture | pcs | n (committed) | rows | proof B | envelope B | spartan B | opening B | prove ms | verify ms | vfy-rel ms | pcs vfy ms | pcs bits | total bits | notes |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
}

pub(crate) fn print(r: &Row) {
    println!(
        "| {} | {} | 2^{} | 2^{} | {} | {} | {} | {} | {:.1} | {:.3} | {:.3} | {:.3} | {:.2} | {:.2} | {} |",
        r.fixture,
        r.pcs,
        r.vars,
        r.rows.trailing_zeros(),
        r.proof,
        r.envelope.map_or("—".into(), |e| e.to_string()),
        r.spartan,
        r.opening,
        r.prove,
        r.verify,
        r.verify_rel,
        r.pcs_verify,
        r.pcs_bits,
        r.total_bits,
        r.extra
    );
}

fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture::Program("add.tri", parse(ADD), vec![7, 5]),
        Fixture::Program("hash.tri", parse(HASH), vec![7]),
        Fixture::Program("chain-11 (hemera)", hash_chain(11), vec![7]),
        Fixture::Synthetic(10),
        Fixture::Synthetic(14),
        Fixture::Synthetic(16),
        Fixture::Synthetic(18),
        Fixture::Synthetic(20),
    ]
}

pub(crate) fn whir(rate: u8, k: u8, pow: u8) -> WhirParams {
    WhirParams {
        log_inv_rate: rate,
        folding_factor: k,
        pow_bits: pow,
        ..WhirParams::default()
    }
}

fn bakeoff(reps: usize) {
    header();
    for fx in fixtures() {
        for r in [2u8, 4] {
            let p = TensorRsParams { log_inv_rate: r, ..TensorRsParams::default() };
            if let Some(row) = run::<TensorRs>(&format!("TensorRs 1/{}", 1 << r), p, &fx, reps, |_, _| String::new()) {
                print(&row);
            }
        }
        for r in [2u8, 4] {
            for k in [2u8, 3, 4, 5, 6] {
                let label = format!("WHIR 1/{} k={k}", 1 << r);
                if let Some(row) = run::<Whir>(&label, whir(r, k, 16), &fx, reps, |_, _| String::new()) {
                    print(&row);
                }
            }
        }
    }
}

mod levers;

/// The shipped choice (`succinct::params_for`) on every fixture.
fn chosen(reps: usize) {
    header();
    for fx in fixtures() {
        let vars = match &fx {
            Fixture::Synthetic(k) => *k as usize,
            Fixture::Program(_, p, i) => {
                let (s, _) = succinct::prove_default(p, i, 1_000_000).unwrap();
                let (inst, pins) = relation_of(&s);
                proof_vars(&inst, &pins)
            }
        };
        let params = succinct::params_for(vars);
        let label = format!(
            "WHIR 1/{} k={} pow={} fin={} ({})",
            1u32 << params.log_inv_rate,
            params.folding_factor,
            params.pow_bits,
            params.max_final_vars,
            if vars <= succinct::SMALL_MAX_VARS { "small" } else { "large" }
        );
        if let Some(r) = run::<Whir>(&label, params, &fx, reps, levers::describe) {
            print(&r);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let reps = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    match args.get(1).map(String::as_str) {
        Some("levers") => levers::levers(reps),
        Some("combos") => levers::combos(reps),
        Some("grind") => levers::grind(reps, true),
        Some("grind-small") => levers::grind(reps, false),
        Some("chosen") => chosen(reps),
        _ => bakeoff(reps),
    }
}
