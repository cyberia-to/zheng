//! Verify the outermost (final) proof of a fixture from the proofs
//! `wrap_bench` stored, time it, and scan every bit flip of its bytes
//! (each flipped proof parsed and verified; reports how many decoded and
//! how many were accepted — must be 0).
//!
//! `wrap_flip <fixture>` with `ZHENG_IVC_DIR` (the stored proofs) and
//! `ZHENG_WRAP` (the levels, as `wrap_bench`). `ZHENG_FLIP=0` skips the
//! scan; `ZHENG_STRIDE=<k>` scans every k-th bit.

#[path = "../../tests/common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use zheng::machine;
use zheng::recursion::ivc;
use zheng::recursion::wrap::{self, FinalProof, Mode, WrapParams};

fn env<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn main() {
    let name: String = std::env::args().nth(1).unwrap_or_else(|| "add.tri".into());
    let (prog, input) = match name.as_str() {
        "add.tri" => (common::parse(common::ADD), vec![7u64, 5]),
        "hash.tri" => (common::parse(common::HASH), vec![7]),
        "merkle-32" => {
            let root = machine::execute(&common::merkle_program(32, None), &[5], 1 << 40).expect("run");
            let r = machine::statement::parse(&root.statement.output).expect("root");
            (common::merkle_program(32, Some(&r)), vec![5])
        }
        t if t.starts_with("tree-") => (common::tree_program(t[5..].parse().unwrap()), vec![3]),
        t if t.starts_with("rec-") => (common::rec_program(), vec![t[4..].parse().unwrap()]),
        other => panic!("fixture {other}"),
    };
    let mut whir = zheng::execution::succinct::params_for(20);
    whir.log_inv_rate = 4;
    whir.pow_bits = 24;
    let n = 15u32;
    let dir: String = std::env::var("ZHENG_IVC_DIR").expect("ZHENG_IVC_DIR");
    let spec: String = env("ZHENG_WRAP", "6i,8i,8f:30".to_string());
    let specs: Vec<&str> = spec.split(',').collect();
    let run = machine::execute_exact(&prog, &input, 1 << 40, n).expect("run");
    let ikey = ivc::key(&whir, n as usize).expect("key");
    let t = Instant::now();
    let mut keys = Vec::new();
    for l in &specs {
        let mut parts = l.split(':');
        let head = parts.next().expect("level");
        let (rate, mode) = head.split_at(head.len() - 1);
        let mut w = whir;
        w.log_inv_rate = rate.parse().expect("rate");
        if let Some(p) = parts.next() {
            w.pow_bits = p.parse().expect("pow");
        }
        let params = WrapParams { whir: w, n: 0, mode: if mode == "f" { Mode::Final } else { Mode::Inner } };
        let k = match keys.last() {
            None => wrap::derive_key_ivc(params, &ikey),
            Some(prev) => wrap::derive_key_wrap(params, prev),
        }
        .expect("key");
        keys.push(k);
    }
    eprintln!("keys {:.0} s", t.elapsed().as_secs_f64());
    let last = keys.last().expect("a level");
    let ivc_bytes = std::fs::read(format!("{dir}/{name}.ivc")).expect("stored IVC proof");
    let proof = ivc::IvcProof::from_bytes(&ivc_bytes, |lr| ivc::key(&whir, lr as usize)).expect("parse");
    let prep = ivc::prepare(&run.statement, &whir, proof.log_rows, proof.start, proof.segments, proof.chain).expect("prepare");
    let pn = ivc::verify_claim(&prep, &proof).expect("ivc");
    let wb = std::fs::read(format!("{dir}/{name}.w{}-{}", specs.len() - 1, specs.join("_"))).expect("stored final wrap");
    let wp = wrap::WrapProof::from_bytes(&wb, last).expect("parse wrap");
    let fp = FinalProof { log_rows: proof.log_rows, start: proof.start, segments: proof.segments, chain: proof.chain, pn, wrap: wp };
    let bytes = fp.to_bytes(last);
    std::fs::write(format!("{dir}/{name}.final-{}", specs.join("_")), &bytes).expect("store final");
    let parse = |b: &[u8]| FinalProof::from_bytes(b, last);
    wrap::verify_statement(&run.statement, &whir, last, &parse(&bytes).expect("parses")).expect("verifies");
    // verify time: the statement prepared once, and from the statement
    let mut v = Vec::new();
    let mut vs = Vec::new();
    for _ in 0..11 {
        let t = Instant::now();
        let q = parse(&bytes).expect("parse");
        wrap::verify_final(&prep, last, &q).expect("verify");
        v.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        wrap::verify_statement(&run.statement, &whir, last, &q).expect("verify");
        vs.push(t.elapsed().as_secs_f64() * 1e3);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    vs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let parts: Vec<String> = fp.sizes(last).iter().map(|(k, v)| format!("{k} {v}")).collect();
    println!(
        "{name}: final proof {} B ({}) · verify median {:.2} ms (statement prepared), {:.2} ms (from the statement)",
        bytes.len(),
        parts.join(" · "),
        v[5],
        vs[5]
    );
    if std::env::var("ZHENG_FLIP").is_ok_and(|v| v == "0") {
        return;
    }
    let stride: usize = env("ZHENG_STRIDE", 1);
    let bits = bytes.len() * 8;
    let next = AtomicUsize::new(0);
    let (flips, decoded, accepted) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let t0 = Instant::now();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                let mut buf = bytes.clone();
                loop {
                    let k = next.fetch_add(1, Ordering::Relaxed) * stride;
                    if k >= bits {
                        break;
                    }
                    buf[k / 8] ^= 1 << (k % 8);
                    flips.fetch_add(1, Ordering::Relaxed);
                    if let Ok(q) = parse(&buf) {
                        decoded.fetch_add(1, Ordering::Relaxed);
                        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let same = prep.header == (q.log_rows, q.start, q.segments, q.chain);
                            if same { wrap::verify_final(&prep, last, &q).is_ok() } else { wrap::verify_statement(&run.statement, &whir, last, &q).is_ok() }
                        }));
                        match ok {
                            Ok(false) => {}
                            Ok(true) => {
                                accepted.fetch_add(1, Ordering::Relaxed);
                                eprintln!("ACCEPTED flip of bit {k}");
                            }
                            Err(_) => eprintln!("PANIC on flip of bit {k}"),
                        }
                    }
                    buf[k / 8] ^= 1 << (k % 8);
                    let f = flips.load(Ordering::Relaxed);
                    if f % 50_000 == 0 {
                        eprintln!("  {f} flips · {:.0} s", t0.elapsed().as_secs_f64());
                    }
                }
            });
        }
    });
    println!(
        "bit-flip scan: {} bytes · {} flips (stride {stride}) · {} decoded · {} accepted · {:.0} s",
        bytes.len(),
        flips.load(Ordering::Relaxed),
        decoded.load(Ordering::Relaxed),
        accepted.load(Ordering::Relaxed),
        t0.elapsed().as_secs_f64()
    );
}
