//! Measure the machine: rows, segments, proof bytes, prove and verify
//! time, under the shipped WHIR parameters (or `ZHENG_POW=<bits>`).
//!
//! `cargo run --release -p zheng --example machine_bench -- [fixture…]`
//! fixtures: add.tri hash.tri merkle-32 tree-<k>

#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;
use zheng::execution::ExecutionNoun as N;
use zheng::machine;

fn fixture(name: &str) -> Option<(N, Vec<u64>)> {
    Some(match name {
        "add.tri" => (common::parse(common::ADD), vec![7, 5]),
        "hash.tri" => (common::parse(common::HASH), vec![7]),
        "merkle-32" => {
            let root = machine::execute(&common::merkle_program(32, None), &[5], 1 << 40).ok()?;
            let r = machine::statement::parse(&root.statement.output).ok()?;
            (common::merkle_program(32, Some(&r)), vec![5])
        }
        t if t.starts_with("tree-") => (common::tree_program(t[5..].parse().ok()?), vec![3]),
        _ => return None,
    })
}

fn main() {
    let mut whir = zheng::execution::succinct::params_for(20);
    if let Some(p) = std::env::var("ZHENG_POW").ok().and_then(|v| v.parse().ok()) {
        whir.pow_bits = p;
    }
    if let Some(r) = std::env::var("ZHENG_RATE").ok().and_then(|v| v.parse().ok()) {
        whir.log_inv_rate = r;
    }
    let seg: u32 = std::env::var("ZHENG_SEG").ok().and_then(|v| v.parse().ok()).unwrap_or(machine::SEGMENT_LOG_ROWS);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let names = if args.is_empty() { vec!["add.tri".into(), "hash.tri".into()] } else { args };
    for name in names {
        let (prog, input) = fixture(&name).unwrap_or_else(|| panic!("fixture {name}"));
        let t0 = Instant::now();
        let run = machine::execute_with(&prog, &input, 1 << 40, seg).expect("run");
        let t_run = t0.elapsed();
        let t1 = Instant::now();
        let proof = machine::prove_run(&run, &whir).expect("prove");
        let t_prove = t1.elapsed();
        let bytes = proof.to_bytes();
        let parsed = machine::MachineProof::from_bytes(&bytes).expect("parse");
        let mut v = Vec::new();
        for _ in 0..3 {
            let t2 = Instant::now();
            machine::verify(&run.statement, &parsed, &whir).expect("verify");
            v.push(t2.elapsed().as_secs_f64() * 1e3);
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "{name}: whir 1/{} pow {} · cycles {} · trace {} rows = {} × 2^{} (region from {}) · proof {} B (air {} · acc {} · decider {}) · run {:.0} ms · prove {:.0} ms · verify median {:.2} ms",
            1u32 << whir.log_inv_rate,
            whir.pow_bits,
            run.statement.cycles,
            run.trace.rows(),
            run.segments(),
            run.seg_log,
            run.start,
            bytes.len(),
            proof.air_bytes(),
            proof.acc_bytes(),
            proof.decider_bytes(),
            t_run.as_secs_f64() * 1e3,
            t_prove.as_secs_f64() * 1e3,
            v[1]
        );
    }
}
