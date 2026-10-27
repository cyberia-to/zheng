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
//! (a 2^k-row relation in the compiler's shape), `node-merkle-<n>` (an
//! n-level hemera Merkle path through the node jet, `execution::node`).
//! Parameters: the shipped
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
        h if h.starts_with("hash-") => {
            let n: usize = h[5..].parse().ok()?;
            (
                common::hash_inputs(n),
                (0..n as u64).map(|i| 1000 + 7 * i).collect(),
            )
        }
        b if b.starts_with("batch-") => {
            let g: usize = b[6..].parse().ok()?;
            (
                common::hash_batch(g, 8),
                (0..8 * g as u64).map(|i| 3 + 11 * i).collect(),
            )
        }
        c if c.starts_with("chain-") => (common::hash_chain(c[6..].parse().ok()?), vec![7]),
        m if m.starts_with("merkle-") => {
            let levels: usize = m[7..].parse().ok()?;
            let root =
                machine::execute(&common::merkle_program(levels, None), &[5], BUDGET).ok()?;
            let r = machine::statement::parse(&root.statement.output).ok()?;
            (common::merkle_program(levels, Some(&r)), vec![5])
        }
        m if m.starts_with("node-merkle-") => {
            // the same path through the hemera node jet (one permutation a level)
            let levels: usize = m[12..].parse().ok()?;
            let root = zheng::execution::node::digest_noun(common::node_merkle_root(levels, 5));
            (common::node_merkle_program(levels, Some(&root)), vec![5])
        }
        t if t.starts_with("tree-") => (common::tree_program(t[5..].parse().ok()?), vec![3]),
        _ => return None,
    })
}

fn text(n: &N) -> String {
    match n {
        N::Atom(a) => a.to_string(),
        N::Pair(a, b) => format!("[{} {}]", text(a), text(b)),
    }
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
    let reps = std::env::var("FAST_REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3usize);
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
                    succinct::verify_relation(&s.instance, &s.pins, &s.statement, &proof)
                        .expect("verify");
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
        if let Some(inner) = name.strip_prefix("veil-") {
            // zk (envelope profile 2): the same statement with its input
            // secret — [2 [[3 [secret [0 1]]] [1 inner]]] runs `inner` on
            // [secret 0]
            let Some((inner_prog, input)) = program(inner) else {
                eprintln!("unknown fixture {name}");
                continue;
            };
            let secret_op = N::Pair(
                Box::new(N::Atom(16)),
                Box::new(N::Pair(
                    Box::new(N::Pair(Box::new(N::Atom(1)), Box::new(N::Atom(0)))),
                    Box::new(N::Pair(Box::new(N::Atom(1)), Box::new(N::Atom(0)))),
                )),
            );
            let wrap = |a: N, b: N| N::Pair(Box::new(a), Box::new(b));
            let subject = wrap(N::Atom(3), wrap(secret_op, wrap(N::Atom(0), N::Atom(1))));
            let prog = wrap(N::Atom(2), wrap(subject, wrap(N::Atom(1), inner_prog)));
            if let Ok(dir) = std::env::var("FAST_DUMP") {
                // the program and its secret input, for `joy prove --secret`
                std::fs::write(format!("{dir}/{name}.nox"), text(&prog)).expect("dump");
                std::fs::write(format!("{dir}/{name}.secret"), input[0].to_string()).expect("dump");
            }
            let mut prove = vec![];
            let mut last = None;
            for _ in 0..reps {
                let t = Instant::now();
                match zheng::execution::veil::prove(&prog, &[], &input[..1], BUDGET) {
                    Ok(r) => last = Some(r),
                    Err(e) => {
                        println!("| {name} | {backend} | veil | — | — | {e} | | | | | |");
                        break;
                    }
                }
                prove.push(ms(t));
            }
            let Some((statement, proof)) = last else {
                continue;
            };
            if std::env::var_os("FAST_KEY").is_some() {
                // warm: the veil proving key held across proofs
                let t = Instant::now();
                let key = zheng::execution::veil::ProvingKey::new(&prog, 0).expect("veil key");
                let key_ms = ms(t);
                let warm: Vec<f64> = (0..reps)
                    .map(|_| {
                        let t = Instant::now();
                        let (s, p) = zheng::execution::veil::prove_with_key(
                            &key,
                            &prog,
                            &[],
                            &input[..1],
                            BUDGET,
                        )
                        .expect("prove");
                        let took = ms(t);
                        assert_eq!(s, statement);
                        zheng::execution::veil::verify(&s, &p).expect("keyed proof verifies");
                        took
                    })
                    .collect();
                eprintln!(
                    "  {name}: key {key_ms:.1} ms once; warm prove {:.1} ms (median of {reps})",
                    median(warm)
                );
            }
            let verify: Vec<f64> = (0..reps)
                .map(|_| {
                    let t = Instant::now();
                    zheng::execution::veil::verify(&statement, &proof).expect("verify");
                    ms(t)
                })
                .collect();
            println!(
                "| {name} | {backend} | veil (profile 2) | — | — | {:.1} | {:.2} | {} (proof) | — | — | — |",
                median(prove),
                median(verify),
                proof.as_bytes().len()
            );
            continue;
        }
        let Some((prog, input)) = program(name) else {
            eprintln!("unknown fixture {name}");
            continue;
        };
        if let Ok(dir) = std::env::var("FAST_DUMP") {
            // the program as a raw .nox formula and its inputs, for `joy prove`
            std::fs::write(format!("{dir}/{name}.nox"), text(&prog)).expect("dump");
            let csv: Vec<String> = input.iter().map(u64::to_string).collect();
            std::fs::write(format!("{dir}/{name}.inputs"), csv.join(",")).expect("dump");
        }
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
        let Some((statement, proof)) = last else {
            continue;
        };
        let cold_bytes = Envelope::Succinct {
            statement: SuccinctStatement::Execution(statement.clone()),
            proof: proof.clone(),
        }
        .to_bytes();
        if std::env::var_os("FAST_KEY").is_some() {
            // warm: the proving key derived once, then held across proofs
            let t = Instant::now();
            let key = succinct::ProvingKey::new(&prog, input.len()).expect("proving key");
            let key_ms = ms(t);
            let warm: Vec<f64> = (0..reps)
                .map(|_| {
                    let t = Instant::now();
                    let (s, p) = succinct::prove_with_key(&key, &prog, &input, BUDGET, params)
                        .expect("prove");
                    let took = ms(t);
                    assert_eq!(
                        Envelope::Succinct {
                            statement: SuccinctStatement::Execution(s),
                            proof: p
                        }
                        .to_bytes(),
                        cold_bytes,
                        "held-key proof differs"
                    );
                    took
                })
                .collect();
            eprintln!(
                "  {name}: key {key_ms:.1} ms once; warm prove {:.1} ms (median of {reps})",
                median(warm)
            );
        }
        let (vars, p) = chosen.get();
        let (inst, _) = succinct::relation_and_pins(&statement).unwrap();
        let rows = inst.num_rows;
        let nnz: usize = inst
            .matrices
            .iter()
            .map(|m| m.entries.iter().map(Vec::len).sum::<usize>())
            .sum();
        eprintln!(
            "  {name}: {} columns, {} rows (padded), {nnz} nonzeros",
            inst.num_cols, rows
        );
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
