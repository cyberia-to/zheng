//! Time the verifier of a stored outermost (final) proof.
//!
//! `wrap_verify <fixture>` with `ZHENG_IVC_DIR` (the proofs `wrap_bench`
//! stored) and `ZHENG_WRAP` (the levels, as `wrap_bench`). The final
//! level's verifying key is read from `<dir>/final-<levels>.vk` when it
//! exists (else every level's key is derived and the file written).
//! `ZHENG_RUNS` timed verifications (default 21) after the first one of
//! the process, which is reported alone ("cold": the key just loaded, the
//! caches cold); `ZHENG_VERIFY_THREADS` sets the verifier's threads.

#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;
use zheng::machine;
use zheng::recursion::ivc;
use zheng::recursion::perm;
use zheng::recursion::wrap::{self, FinalProof, Mode, WrapKey, WrapParams};

fn fixture(name: &str) -> Option<(zheng::execution::ExecutionNoun, Vec<u64>)> {
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

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn derive(spec: &[&str], whir: &lens::WhirParams, ikey: &ivc::Key) -> WrapKey {
    let mut keys: Vec<WrapKey> = Vec::new();
    for l in spec {
        let mut parts = l.split(':');
        let head = parts.next().expect("level");
        let (rate, mode) = head.split_at(head.len() - 1);
        let mut w = *whir;
        w.log_inv_rate = rate.parse().expect("rate");
        if let Some(p) = parts.next() {
            w.pow_bits = p.parse().expect("pow");
        }
        if let Some(k) = parts.next() {
            w.folding_factor = k.parse().expect("fold");
        }
        let params = WrapParams { whir: w, n: 0, mode: if mode == "f" { Mode::Final } else { Mode::Inner } };
        let k = match keys.last() {
            None => wrap::derive_key_ivc(params, ikey),
            Some(prev) => wrap::derive_key_wrap(params, prev),
        }
        .expect("key");
        keys.push(k);
    }
    keys.pop().expect("a level")
}

fn main() {
    let name: String = std::env::args().nth(1).unwrap_or_else(|| "add.tri".into());
    let (prog, input) = fixture(&name).unwrap_or_else(|| panic!("fixture {name}"));
    let mut whir = zheng::execution::succinct::params_for(20);
    whir.log_inv_rate = 4;
    whir.pow_bits = 24;
    let n = 15u32;
    let dir: String = std::env::var("ZHENG_IVC_DIR").expect("ZHENG_IVC_DIR");
    let spec: String = env("ZHENG_WRAP", "6i,8i,8f:30".to_string());
    let specs: Vec<&str> = spec.split(',').collect();
    let run = machine::execute_exact(&prog, &input, 1 << 40, n).expect("run");
    let ikey = ivc::key(&whir, n as usize).expect("key");
    let vk_file = format!("{dir}/final-{}.vk", specs.join("_"));
    let t = Instant::now();
    let last = match std::fs::read(&vk_file) {
        Ok(b) => {
            let k = WrapKey::from_vk_bytes(&b).expect("verifying key");
            eprintln!("verifying key {vk_file}: {} B, loaded in {:.1} ms", b.len(), ms(t));
            k
        }
        Err(_) => {
            let mut wbase = whir;
            wbase.pow_bits = 24;
            let k = derive(&specs, &wbase, &ikey);
            let b = k.vk_bytes();
            std::fs::write(&vk_file, &b).expect("store key");
            eprintln!("verifying key derived in {:.0} s, stored ({} B)", t.elapsed().as_secs_f64(), b.len());
            let back = WrapKey::from_vk_bytes(&b).expect("reload");
            assert_eq!(back.vk_bytes(), b, "verifying key round trip");
            back
        }
    };
    if let Some(w) = &last.wiring {
        eprintln!(
            "wiring: {} reads ({} cells), {} writes ({} cells); graph {} ops; key {} entries in {} of {} columns used",
            w.reads,
            w.read_cells.len(),
            w.write_at.len() - 1,
            w.write_cells.len(),
            last.gc.len(),
            last.sparse.iter().zip(&last.key_cols).filter(|c| *c.1).map(|c| c.0.len()).sum::<usize>(),
            last.key_cols.iter().filter(|&&u| u).count(),
            last.key_cols.len()
        );
    }
    let bytes = std::fs::read(format!("{dir}/{name}.final-{}", specs.join("_"))).expect("stored final proof");
    let header = FinalProof::from_bytes(&bytes, &last).expect("parse");
    let prep = ivc::prepare(&run.statement, &whir, header.log_rows, header.start, header.segments, header.chain).expect("prepare");
    let threads = std::env::var("ZHENG_VERIFY_THREADS").unwrap_or_else(|_| "all".into());
    // cold: the first verification of the process
    let p0 = perm::count();
    let t = Instant::now();
    let q = FinalProof::from_bytes(&bytes, &last).expect("parse");
    wrap::verify_final(&prep, &last, &q).expect("verify");
    let cold = ms(t);
    let p1 = perm::count();
    let runs: usize = env("ZHENG_RUNS", 21);
    let mut v = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t = Instant::now();
        let q = FinalProof::from_bytes(&bytes, &last).expect("parse");
        wrap::verify_final(&prep, &last, &q).expect("verify");
        v.push(ms(t));
    }
    v.sort_by(|a, b| a.partial_cmp(b).expect("times"));
    println!(
        "{name}: final proof {} B · threads {threads} · verify cold {cold:.3} ms · warm median {:.3} ms (min {:.3}, max {:.3}, {runs} runs) · permutations {} single + {} batched",
        bytes.len(),
        v[runs / 2],
        v[0],
        v[runs - 1],
        p1.0 - p0.0,
        p1.1 - p0.1
    );
}
