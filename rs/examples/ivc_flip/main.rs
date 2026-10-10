//! Bit-flip scan of a full recursive proof: every bit of the encoded
//! proof flipped in turn, parsed and verified; reports how many decoded
//! and how many were accepted (must be 0).
//!
//! `ivc_flip <fixture> [proof file]` — proves the fixture (or reads the
//! proof bytes from the file, written by an earlier run), then scans on
//! all cores. `ZHENG_STRIDE=<k>` scans every k-th bit only.

#[path = "../../tests/common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use zheng::machine;
use zheng::recursion::ivc;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut whir = zheng::execution::succinct::params_for(20);
    whir.log_inv_rate = 4;
    whir.pow_bits = 24;
    let n = 15u32;
    let (prog, input) = match args.first().map(String::as_str).unwrap_or("add.tri") {
        "add.tri" => (common::parse(common::ADD), vec![7u64, 5]),
        t if t.starts_with("tree-") => (common::tree_program(t[5..].parse().unwrap()), vec![3]),
        other => panic!("fixture {other}"),
    };
    let run = machine::execute_exact(&prog, &input, 1 << 40, n).expect("run");
    let key = ivc::key(&whir, n as usize).expect("key");
    let bytes = match args.get(1) {
        Some(path) if std::path::Path::new(path).exists() => std::fs::read(path).expect("read"),
        other => {
            let proof = ivc::prove_run(&run, &whir).expect("prove");
            let b = proof.to_bytes(&key);
            if let Some(path) = other {
                std::fs::write(path, &b).expect("write");
            }
            b
        }
    };
    let parse = |b: &[u8]| ivc::IvcProof::from_bytes(b, |lr| ivc::key(&whir, lr as usize));
    let p = parse(&bytes).expect("honest proof parses");
    ivc::verify(&run.statement, &p, &whir).expect("honest proof verifies");
    let prep = ivc::prepare(&run.statement, &whir, p.log_rows, p.start, p.segments, p.chain).expect("prepare");
    let stride: usize = std::env::var("ZHENG_STRIDE").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
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
                        let same = (q.log_rows, q.start, q.segments, q.chain) == prep.header;
                        let ok = if same { ivc::verify_prepared(&prep, &q).is_ok() } else { ivc::verify(&run.statement, &q, &whir).is_ok() };
                        if ok {
                            accepted.fetch_add(1, Ordering::Relaxed);
                            eprintln!("ACCEPTED flip of bit {k}");
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
