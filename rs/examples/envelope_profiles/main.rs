//! Measure one fixture under every envelope profile that proves a public
//! nox run: succinct (1), machine (4), recursive (5), wrapped (6).
//! Reports envelope bytes, prove time, and `from_bytes` + `verify` time
//! (the first call — for profiles 5 and 6 it builds the keys — and the
//! median of 5 more).
//!
//! `cargo run --release -p zheng --example envelope_profiles -- [fixture…]`
//! fixtures: add.tri hash.tri merkle-32 tree-<k>. `ZHENG_PROFILES=1,4,5,6`
//! selects (default 1,4,5). `ZHENG_ENVELOPE_DIR=<dir>` writes each envelope
//! to `<dir>/<fixture>.p<profile>.zheng`. `ZHENG_VERIFY=<file>` only
//! decodes and verifies that envelope (a fresh process: cold keys).

#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;
use zheng::envelope::{Envelope, SuccinctStatement, recursive};
use zheng::execution::ExecutionNoun as N;
use zheng::machine;

const BUDGET: u64 = 1 << 40;

fn fixture(name: &str) -> Option<(N, Vec<u64>)> {
    Some(match name {
        "add.tri" => (common::parse(common::ADD), vec![7, 5]),
        "hash.tri" => (common::parse(common::HASH), vec![7]),
        "merkle-32" => {
            let root = machine::execute(&common::merkle_program(32, None), &[5], BUDGET).ok()?;
            let r = machine::statement::parse(&root.statement.output).ok()?;
            (common::merkle_program(32, Some(&r)), vec![5])
        }
        t if t.starts_with("tree-") => (common::tree_program(t[5..].parse().ok()?), vec![3]),
        _ => return None,
    })
}

fn prove(profile: u8, prog: &N, input: &[u64]) -> Result<Envelope, String> {
    match profile {
        1 => {
            let (st, proof) = zheng::execution::succinct::prove_default(prog, input, BUDGET)?;
            Ok(Envelope::Succinct { statement: SuccinctStatement::Execution(st), proof })
        }
        4 => {
            let params = zheng::execution::succinct::params_for(20);
            let (statement, proof) = machine::prove(prog, input, BUDGET, &params)?;
            Ok(Envelope::Machine { params, statement, proof: Box::new(proof) })
        }
        5 => recursive::prove(prog, input, BUDGET, &recursive::params()),
        6 => zheng::envelope::wrapped::prove(prog, input, BUDGET),
        _ => Err(format!("profile {profile}")),
    }
}

fn check(bytes: &[u8]) -> f64 {
    let t = Instant::now();
    Envelope::from_bytes(bytes).expect("decode").verify(None).expect("verify");
    t.elapsed().as_secs_f64() * 1e3
}

fn main() {
    if let Ok(file) = std::env::var("ZHENG_VERIFY") {
        let bytes = std::fs::read(&file).expect("envelope");
        let first = check(&bytes);
        let mut v: Vec<f64> = (0..5).map(|_| check(&bytes)).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("{file}: {} B · profile {} · decode+verify cold {first:.2} ms, warm median {:.2} ms", bytes.len(), bytes[10], v[2]);
        return;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let names = if args.is_empty() { vec!["hash.tri".into(), "merkle-32".into()] } else { args };
    let profiles: Vec<u8> = std::env::var("ZHENG_PROFILES")
        .ok()
        .map(|v| v.split(',').filter_map(|p| p.parse().ok()).collect())
        .unwrap_or_else(|| vec![1, 4, 5]);
    for name in names {
        let (prog, input) = fixture(&name).unwrap_or_else(|| panic!("fixture {name}"));
        for &profile in &profiles {
            let t0 = Instant::now();
            let envelope = match prove(profile, &prog, &input) {
                Ok(e) => e,
                Err(e) => {
                    println!("{name} · profile {profile}: not proven ({e})");
                    continue;
                }
            };
            let t_prove = t0.elapsed().as_secs_f64();
            let bytes = envelope.to_bytes();
            if let Ok(dir) = std::env::var("ZHENG_ENVELOPE_DIR") {
                std::fs::write(format!("{dir}/{name}.p{profile}.zheng"), &bytes).expect("write envelope");
            }
            let first = check(&bytes);
            let mut v: Vec<f64> = (0..5).map(|_| check(&bytes)).collect();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            println!(
                "{name} · profile {profile}: {} B · prove {t_prove:.1} s · decode+verify first {first:.2} ms, median {:.2} ms",
                bytes.len(),
                v[2]
            );
        }
    }
}
