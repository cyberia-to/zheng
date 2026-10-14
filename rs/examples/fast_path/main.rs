//! Profile 1 (one relation, committed witness) on the user-device path:
//! prove / verify / size / bits per fixture and WHIR parameters, on the
//! backend `ZHENG_BACKEND` names (cpu, metal, webgpu; default cpu).
//!
//! ```text
//! cargo run --release -p zheng --example fast_path -- [fixture…]
//! ```
//!
//! Fixtures: `add.tri`, `hash.tri`, `chain-<n>` (n chained hemera digest
//! hashes), `merkle-<n>` (an n-level Merkle path check), `synthetic-<k>`
//! (a 2^k-row relation in the compiler's shape). Parameters: the shipped
//! `succinct::device_params` unless `FAST_RATE` / `FAST_K` / `FAST_POW` /
//! `FAST_FIN` override them. `FAST_REPS` (default 3) repetitions; the
//! median is reported. `ZHENG_TIMING=1` prints the prover's phases.
//!
//! Columns: `vars` = committed variables ℓ; `rows` = CCS rows; `prove ms`
//! = relation + witness + key + commit + Spartan + opening (the
//! `prove_default` path); `verify ms` = statement → relation → IOP →
//! opening; `bits` = lens's proven bound with grinding; `bare bits` = the
//! same schedule with grinding removed; `grind` = log2 of the expected
//! grinding hashes.

#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;

use zheng::envelope::{Envelope, SuccinctStatement};
use zheng::execution::ExecutionNoun as N;
use zheng::execution::succinct::{self, Whir, WhirParams};
use zheng::machine;

const BUDGET: u64 = 1 << 40;

fn env(name: &str) -> Option<u8> {
    std::env::var(name).ok().and_then(|s| s.parse().ok())
}

fn params(vars: usize) -> WhirParams {
    let base = succinct::device_params(vars);
    WhirParams {
        log_inv_rate: env("FAST_RATE").unwrap_or(base.log_inv_rate),
        folding_factor: env("FAST_K").unwrap_or(base.folding_factor),
        pow_bits: env("FAST_POW").unwrap_or(base.pow_bits),
        max_final_vars: env("FAST_FIN").unwrap_or(base.max_final_vars),
        ..base
    }
}

fn program(name: &str) -> Option<(N, Vec<u64>)> {
    Some(match name {
        "add.tri" => (common::parse(common::ADD), vec![7, 5]),
        "hash.tri" => (common::parse(common::HASH), vec![7]),
        c if c.starts_with("chain-") => (common::hash_chain(c[6..].parse().ok()?), vec![7]),
        m if m.starts_with("merkle-") => {
            let levels: usize = m[7..].parse().ok()?;
            let root = machine::execute(&common::merkle_program(levels, None), &[5], BUDGET).ok()?;
            let r = machine::statement::parse(&root.statement.output).ok()?;
            (common::merkle_program(levels, Some(&r)), vec![5])
        }
        t if t.starts_with("tree-") => (common::tree_program(t[5..].parse().ok()?), vec![3]),
        _ => return None,
    })
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn ledger(p: &WhirParams, vars: usize) -> (f64, f64, f64) {
    let cfg = lens::rspcs::WhirConfig::derive(p, vars).expect("schedule");
    (
        cfg.security_bits(),
        cfg.security_bits_without_grinding(),
        cfg.expected_grinding_hashes().max(1.0).log2(),
    )
}

fn label(p: &WhirParams) -> String {
    format!(
        "1/{} k={} pow={} fin={}",
        1u32 << p.log_inv_rate,
        p.folding_factor,
        p.pow_bits,
        p.max_final_vars
    )
}

fn main() {
    let backend = common::backend();
    let reps = std::env::var("FAST_REPS").ok().and_then(|s| s.parse().ok()).unwrap_or(3usize);
    let names: Vec<String> = std::env::args().skip(1).collect();
    println!(
        "| fixture | backend | params | vars | rows | prove ms | verify ms | envelope B | bits | bare bits | grind log2 |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
    for name in &names {
        if let Some(k) = name.strip_prefix("synthetic-") {
            let k: u32 = k.parse().expect("synthetic-<k>");
            let s = common::synthetic(k, 3);
            let vars = succinct::committed_vars(&s.instance, &s.pins).unwrap();
            let p = params(vars);
            let mut prove = vec![];
            let mut last = None;
            for _ in 0..reps {
                let t = Instant::now();
                last = Some(
                    succinct::prove_relation::<Whir>(&p, &s.instance, &s.z, &s.pins, &s.statement)
                        .expect("prove"),
                );
                prove.push(ms(t));
            }
            let proof = last.unwrap();
            let verify: Vec<f64> = (0..reps)
                .map(|_| {
                    let t = Instant::now();
                    succinct::verify_relation(&s.instance, &s.pins, &s.statement, &proof).expect("verify");
                    ms(t)
                })
                .collect();
            let encoded = zheng::envelope::succinct_proof_bytes(&proof.into());
            if let Ok(dir) = std::env::var("FAST_OUT") {
                std::fs::write(format!("{dir}/{name}.p1.proof"), &encoded).expect("write proof");
            }
            let bytes = encoded.len();
            let (bits, bare, grind) = ledger(&p, vars);
            println!(
                "| {name} | {backend} | {} | {vars} | 2^{} | {:.1} | {:.2} | {bytes} (proof) | {bits:.2} | {bare:.2} | {grind:.1} |",
                label(&p),
                s.instance.num_rows.trailing_zeros(),
                median(prove),
                median(verify)
            );
            continue;
        }
        let Some((prog, input)) = program(name) else {
            eprintln!("unknown fixture {name}");
            continue;
        };
        let chosen = std::cell::Cell::new((0usize, succinct::params_for(0)));
        let choose = |vars: usize| {
            let p = params(vars);
            chosen.set((vars, p));
            p
        };
        let mut prove = vec![];
        let mut last = None;
        for _ in 0..reps {
            let t = Instant::now();
            match succinct::prove_with(&prog, &input, BUDGET, choose) {
                Ok(r) => last = Some(r),
                Err(e) => {
                    println!("| {name} | {backend} | — | — | — | {e} | | | | | |");
                    break;
                }
            }
            prove.push(ms(t));
        }
        let Some((statement, proof)) = last else { continue };
        let (vars, p) = chosen.get();
        let (inst, _) = succinct::relation_and_pins(&statement).unwrap();
        let rows = inst.num_rows;
        let nnz: usize = inst.matrices.iter().map(|m| m.entries.iter().map(Vec::len).sum::<usize>()).sum();
        eprintln!("  {name}: {} columns, {} rows (padded), {nnz} nonzeros", inst.num_cols, rows);
        let envelope = Envelope::Succinct {
            statement: SuccinctStatement::Execution(statement),
            proof,
        };
        let verify: Vec<f64> = (0..reps)
            .map(|_| {
                let t = Instant::now();
                envelope.verify(None).expect("verify");
                ms(t)
            })
            .collect();
        let encoded = envelope.to_bytes();
        if let Ok(dir) = std::env::var("FAST_OUT") {
            std::fs::write(format!("{dir}/{name}.p1.zheng"), &encoded).expect("write envelope");
        }
        let bytes = encoded.len();
        let (bits, bare, grind) = ledger(&p, vars);
        println!(
            "| {name} | {backend} | {} | {vars} | 2^{} | {:.1} | {:.2} | {bytes} | {bits:.2} | {bare:.2} | {grind:.1} |",
            label(&p),
            rows.trailing_zeros(),
            median(prove),
            median(verify)
        );
    }
}
