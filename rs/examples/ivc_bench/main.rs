//! Measure recursive (IVC) proofs of nox runs: proof bytes, prove and
//! verify time, under the recursion profile's WHIR parameters
//! (`ZHENG_RATE=<log inv rate>`, default 4; `ZHENG_POW=<bits>`, default 24;
//! `ZHENG_STEP=<log rows>`, default 15).
//!
//! `cargo run --release -p zheng --example ivc_bench -- [fixture…]`
//! fixtures: add.tri hash.tri merkle-32 tree-<k> rec-<n>

#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;
use zheng::execution::ExecutionNoun as N;
use zheng::machine;
use zheng::recursion::ivc;

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
        t if t.starts_with("rec-") => (common::rec_program(), vec![t[4..].parse().ok()?]),
        _ => return None,
    })
}

fn env<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn main() {
    let mut whir = zheng::execution::succinct::params_for(20);
    whir.log_inv_rate = env("ZHENG_RATE", 4);
    whir.pow_bits = env("ZHENG_POW", 24);
    let n: u32 = env("ZHENG_STEP", 15);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let names = if args.is_empty() { vec!["add.tri".into()] } else { args };
    let t0 = Instant::now();
    let key = ivc::key(&whir, n as usize).expect("key");
    let p = &key.params;
    eprintln!(
        "key: 2^{n} rows, ℓ {}, rate 1/{}, pow {}, t {} s {} · {:.0} ms",
        p.vars,
        1u32 << whir.log_inv_rate,
        whir.pow_bits,
        p.cfg.queries,
        p.cfg.ood,
        t0.elapsed().as_secs_f64() * 1e3
    );
    for name in names {
        let (prog, input) = fixture(&name).unwrap_or_else(|| panic!("fixture {name}"));
        let t1 = Instant::now();
        let run = machine::execute_exact(&prog, &input, 1 << 40, n).expect("run");
        let t_run = t1.elapsed();
        if std::env::var_os("ZHENG_DRY").is_some() {
            println!("{name}: cycles {} · {} steps of 2^{n}", run.statement.cycles, run.segments());
            continue;
        }
        let t2 = Instant::now();
        let proof = ivc::prove_run(&run, &whir).expect("prove");
        let t_prove = t2.elapsed();
        let bytes = proof.to_bytes(p);
        let parsed = ivc::IvcProof::from_bytes(&bytes, |lr| ivc::key(&whir, lr as usize)).expect("parse");
        assert_eq!(parsed, proof);
        let mut v = Vec::new();
        for _ in 0..5 {
            let t3 = Instant::now();
            ivc::verify(&run.statement, &parsed, &whir).expect("verify");
            v.push(t3.elapsed().as_secs_f64() * 1e3);
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let prep = ivc::prepare(&run.statement, &whir, parsed.log_rows, parsed.start, parsed.segments, parsed.chain).expect("prepare");
        let mut vp = Vec::new();
        for _ in 0..5 {
            let t3 = Instant::now();
            ivc::verify_prepared(&prep, &parsed).expect("verify");
            vp.push(t3.elapsed().as_secs_f64() * 1e3);
        }
        vp.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let segs = run.segments();
        let parts: Vec<String> = proof.sizes(p).iter().map(|(k, v)| format!("{k} {v}")).collect();
        println!("{name}: parts {}", parts.join(" · "));
        println!(
            "{name}: cycles {} · {} steps of 2^{n} rows · proof {} B · run {:.0} ms · prove {:.0} ms ({:.0} ms/step) · verify median {:.2} ms (prepared {:.2} ms)",
            run.statement.cycles,
            segs,
            bytes.len(),
            t_run.as_secs_f64() * 1e3,
            t_prove.as_secs_f64() * 1e3,
            t_prove.as_secs_f64() * 1e3 / segs as f64,
            v[2],
            vp[2]
        );
    }
}
