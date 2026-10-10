//! Measure wrap proofs over recursive (IVC) proofs of nox runs.
//!
//! `cargo run --release -p zheng --example wrap_bench -- [fixture…]`
//!
//! IVC parameters as `ivc_bench` (`ZHENG_RATE`, `ZHENG_POW`, `ZHENG_STEP`).
//! `ZHENG_WRAP` lists the wrap levels, innermost first, as
//! `<log inv rate><i|f>[:<pow>[:<fold>]]` (`i`: inner mode, `f`: final
//! mode — only the last level), default `6i,8i:30,8f:30`. `ZHENG_IVC_DIR=<dir>`: store / reuse IVC proofs there
//! (`<fixture>.ivc`).

#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;
use zheng::execution::ExecutionNoun as N;
use zheng::machine;
use zheng::recursion::ivc;
use zheng::recursion::wrap::{self, FinalProof, Inner, Mode, WrapParams};

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

fn levels(base: &lens::WhirParams) -> Vec<WrapParams> {
    let spec: String = env("ZHENG_WRAP", "6i,8i:30,8f:30".to_string());
    spec.split(',')
        .map(|l| {
            let mut parts = l.split(':');
            let head = parts.next().expect("level");
            let (rate, mode) = head.split_at(head.len() - 1);
            let mut whir = *base;
            whir.log_inv_rate = rate.parse().expect("rate");
            if let Some(p) = parts.next() {
                whir.pow_bits = p.parse().expect("pow");
            }
            if let Some(k) = parts.next() {
                whir.folding_factor = k.parse().expect("fold");
            }
            let mode = if mode == "f" { Mode::Final } else { Mode::Inner };
            WrapParams { whir, n: 0, mode }
        })
        .collect()
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn main() {
    let mut whir = zheng::execution::succinct::params_for(20);
    whir.log_inv_rate = env("ZHENG_RATE", 4);
    whir.pow_bits = env("ZHENG_POW", 24);
    let n: u32 = env("ZHENG_STEP", 15);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let names = if args.is_empty() { vec!["add.tri".into()] } else { args };
    let mut wbase = whir;
    wbase.pow_bits = env("ZHENG_WPOW", 24);
    let lv = levels(&wbase);
    let t0 = Instant::now();
    let ikey = ivc::key(&whir, n as usize).expect("key");
    eprintln!("ivc key: {:.0} ms", ms(t0));

    let mut keys = Vec::new();
    for (i, p) in lv.iter().enumerate() {
        let t = Instant::now();
        let k = match keys.last() {
            None => wrap::derive_key_ivc(*p, &ikey),
            Some(prev) => wrap::derive_key_wrap(*p, prev),
        }
        .expect("wrap key");
        let reads = k.wiring.as_ref().map_or(0, |w| w.reads.len());
        let rows = wrap::ledger(&k.params, &k.cfg, k.constraints, reads);
        let (wname, wbits) = rows.iter().fold(("", f64::INFINITY), |a, (nm, b)| if *b < a.1 { (nm.as_str(), *b) } else { a });
        eprintln!("wrap {i} ledger: {} rows, weakest {wname} {wbits:.2} bits", rows.len());
        assert!(wbits >= 128.0, "a ledger row below 128 bits");
        eprintln!(
            "wrap {i} key: circuit {} rows (gates {} bits {} blocks {}) → 2^{} · rate 1/{} pow {} k {} · {:?} · bits {:.2} · {:.0} ms",
            k.rows,
            k.census[0],
            k.census[1],
            k.census[2],
            k.params.n,
            1u32 << p.whir.log_inv_rate,
            p.whir.pow_bits,
            p.whir.folding_factor,
            p.mode,
            k.cfg.security_bits(),
            ms(t)
        );
        keys.push(k);
    }
    if std::env::var_os("ZHENG_KEYS_ONLY").is_some() {
        return;
    }
    for name in names {
        let (prog, input) = fixture(&name).unwrap_or_else(|| panic!("fixture {name}"));
        let run = machine::execute_exact(&prog, &input, 1 << 40, n).expect("run");
        let file = std::env::var("ZHENG_IVC_DIR").ok().map(|d| format!("{d}/{name}.ivc"));
        let stored = file.as_ref().and_then(|f| std::fs::read(f).ok());
        let proof = match stored {
            Some(bytes) => {
                eprintln!("{name}: IVC proof from {}", file.as_ref().unwrap());
                ivc::IvcProof::from_bytes(&bytes, |lr| ivc::key(&whir, lr as usize)).expect("parse")
            }
            None => {
                let t = Instant::now();
                let p = ivc::prove_run(&run, &whir).expect("prove");
                eprintln!("{name}: IVC prove {:.0} ms", ms(t));
                if let Some(f) = &file {
                    std::fs::write(f, p.to_bytes(&ikey)).expect("store");
                }
                p
            }
        };
        let ivc_bytes = proof.to_bytes(&ikey).len();
        let prep = ivc::prepare(&run.statement, &whir, proof.log_rows, proof.start, proof.segments, proof.chain).expect("prepare");
        let t = Instant::now();
        let pn = ivc::verify_claim(&prep, &proof).expect("ivc verify");
        println!("{name}: cycles {} · {} steps · IVC proof {ivc_bytes} B · IVC verify {:.2} ms", run.statement.cycles, run.segments(), ms(t));
        let mut wraps = Vec::new();
        let spec: String = env("ZHENG_WRAP", "6i,8i:30,8f:30".to_string());
        let specs: Vec<&str> = spec.split(',').collect();
        for (i, k) in keys.iter().enumerate() {
            let t = Instant::now();
            // a stored proof of this level (the levels up to it named in the file)
            let wfile = std::env::var("ZHENG_IVC_DIR").ok().map(|d| format!("{d}/{name}.w{i}-{}", specs[..=i].join("_")));
            let stored = wfile.as_ref().and_then(|f| std::fs::read(f).ok());
            let (wp, x, tp) = match stored {
                Some(b) if i + 1 < keys.len() => {
                    let wp = wrap::WrapProof::from_bytes(&b, k).expect("stored wrap");
                    let x = wrap::public_digest_native(&prep.publics, &pn).expect("digest");
                    eprintln!("{name}: wrap {i} from {}", wfile.as_ref().unwrap());
                    (wp, x, f64::NAN)
                }
                _ => {
                    let inner = if i == 0 { Inner::Ivc { key: &ikey, proof: &proof } } else { Inner::Wrap { key: &keys[i - 1], proof: &wraps[i - 1] } };
                    let (wp, x) = wrap::prove(k, &inner, &prep.publics, &pn).expect("wrap prove");
                    let tp = ms(t);
                    if let Some(f) = &wfile {
                        std::fs::write(f, wp.to_bytes(k)).expect("store wrap");
                    }
                    (wp, x, tp)
                }
            };
            let bytes = wp.to_bytes(k);
            let parsed = wrap::WrapProof::from_bytes(&bytes, k).expect("parse");
            assert_eq!(parsed, wp);
            let mut v = Vec::new();
            for _ in 0..5 {
                let t = Instant::now();
                wrap::verify_native(k, x, &parsed).expect("wrap verify");
                v.push(ms(t));
            }
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            println!("{name}: wrap {i}: proof {} B · prove {tp:.0} ms · verify median {:.2} ms", bytes.len(), v[2]);
            wraps.push(parsed);
        }
        let last = keys.last().expect("a level");
        let fp = FinalProof { pn: pn.clone(), wrap: wraps.pop().expect("a wrap") };
        let bytes = fp.to_bytes(last);
        let fp = FinalProof::from_bytes(&bytes, last).expect("parse");
        let mut v = Vec::new();
        for _ in 0..5 {
            let t = Instant::now();
            wrap::verify_final(&prep, last, &fp).expect("final verify");
            v.push(ms(t));
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let parts: Vec<String> = fp.sizes(last).iter().map(|(k, v)| format!("{k} {v}")).collect();
        println!("{name}: FINAL proof {} B ({}) · verify median {:.2} ms (statement prepared)", bytes.len(), parts.join(" · "), v[2]);
        if let Ok(d) = std::env::var("ZHENG_IVC_DIR") {
            std::fs::write(format!("{d}/{name}.final-{}", specs.join("_")), &bytes).expect("store final");
        }
    }
}
