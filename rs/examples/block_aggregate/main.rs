//! Block aggregation (G2): census and timing.
//!
//! ```text
//! cargo run --release -p zheng --features test-hooks --example block_aggregate -- census [levels]
//! ```

#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;

use nebu::Fp3;
use zheng::execution::ExecutionNoun as N;
use zheng::execution::veil::rec::{self, RecKey};
use zheng::recursion::circuit::builder::Builder;
use zheng::recursion::ops::Ops;
use zheng::recursion::perm::tag;
use zheng::recursion::sponge::Sponge;

const BUDGET: u64 = 1 << 40;

/// The SPEND proxy: an n-level hemera Merkle path through the node jet
/// with the leaf secret (veil-node-merkle-n of `fast_path`).
fn veil_program(levels: usize) -> N {
    let root = zheng::execution::node::digest_noun(common::node_merkle_root(levels, 5));
    let inner = common::node_merkle_program(levels, Some(&root));
    let secret_op = N::Pair(
        Box::new(N::Atom(16)),
        Box::new(N::Pair(
            Box::new(N::Pair(Box::new(N::Atom(1)), Box::new(N::Atom(0)))),
            Box::new(N::Pair(Box::new(N::Atom(1)), Box::new(N::Atom(0)))),
        )),
    );
    let wrap = |a: N, b: N| N::Pair(Box::new(a), Box::new(b));
    let subject = wrap(N::Atom(3), wrap(secret_op, wrap(N::Atom(0), N::Atom(1))));
    wrap(N::Atom(2), wrap(subject, wrap(N::Atom(1), inner)))
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn census(levels: usize) {
    let prog = veil_program(levels);
    let t = Instant::now();
    let key = RecKey::new(&prog, 0).expect("key");
    println!("key {:.1} ms: {:?}", ms(t), key.report());
    let t = Instant::now();
    let (st, pf) = rec::prove(&key, &prog, &[], &[5], BUDGET).expect("prove");
    println!("prove {:.1} ms, {} B", ms(t), pf.to_bytes(&key).len());
    let t = Instant::now();
    rec::verify(&key, &st, &pf).expect("verify");
    println!("verify (native, over Ops) {:.1} ms", ms(t));
    let pins = key.statement_pins(&st).unwrap();
    let mut b = Builder::new(true);
    let mut sp = Sponge::new(&mut b, tag::AGG_TX);
    let pv: Vec<_> = pins.iter().map(|&p| sp.absorb_free(&mut b, p)).collect();
    let _ = sp.squeeze(&mut b);
    let g0 = b.gates.len();
    rec::verify::verify(&mut b, &key, &pv, &pf);
    b.finish().expect("circuit accepts");
    let blocks: usize = b.chains.iter().map(|c| c.blocks.len()).sum();
    println!("circuit: gates {} bits {} perm blocks {} rows {}", b.gates.len() - g0, b.bits.len(), blocks, b.rows());
    let _ = Fp3::ZERO;
    let _ = b.value(pv[0]);
}

fn keys(levels: usize, depth: usize) -> zheng::recursion::agg::AggKeys {
    let prog = veil_program(levels);
    let key = std::sync::Arc::new(RecKey::new(&prog, 0).expect("key"));
    let t = Instant::now();
    let k = zheng::recursion::agg::AggKeys::derive(key, depth).expect("keys");
    println!("keys (depth {depth}) {:.1} s", t.elapsed().as_secs_f64());
    for (j, l) in k.levels.iter().enumerate() {
        println!("  level {j}: 2^{} rows ({} used), census {:?}", l.params.n, l.rows, l.census);
    }
    println!("  top: 2^{} ({} used) census {:?}", k.top.params.n, k.top.rows, k.top.census);
    println!("  final: 2^{} ({} used) census {:?}; proof ≤ {} B", k.last.params.n, k.last.rows, k.last.census, k.max_proof_bytes());
    for (name, row, bits) in k.weakest() {
        println!("  ledger {name}: weakest {row} {bits:.2} bits");
    }
    println!("  veil-r: {:?}", k.veil.report());
    k
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// Prove one block of `n` transactions (seeded veil-r proofs, so a block
/// is the same bytes on every backend) and verify it natively.
fn block(n: usize, depth: usize) {
    let backend = common::backend();
    use zheng::recursion::agg::{self, BlockStatement};
    let prog = veil_program(32);
    let k = keys(32, depth);
    let veil = k.veil.clone();
    let t = Instant::now();
    let mut txs = Vec::new();
    let mut proofs = Vec::new();
    let mut tx_ms = Vec::new();
    for i in 0..n {
        let s0 = Instant::now();
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let (s, p) = rec::prove_seeded(&veil, &prog, &[], &[5], BUDGET, seed).expect("tx proof");
        tx_ms.push(ms(s0));
        txs.push(veil.statement_pins(&s).unwrap());
        proofs.push(p);
    }
    let tx_bytes = proofs[0].to_bytes(&veil).len();
    println!("{backend}: {n} tx proofs {:.1} s (median {:.1} ms, {tx_bytes} B each)", t.elapsed().as_secs_f64(), median(tx_ms));
    let st = BlockStatement { txs, fields: [1, 2, 3, 4].map(nebu::Goldilocks::new) };
    let t = Instant::now();
    let (pf, tm) = agg::prove(&k, &st, &proofs).expect("block");
    let total = t.elapsed().as_secs_f64();
    let bytes = pf.to_bytes(&k.last);
    let leaf_sum: f64 = tm.leaves.iter().sum();
    println!(
        "{backend}: block n={n} depth={depth}: prove {total:.1} s = leaves {leaf_sum:.1} s (median {:.2} s) + levels {:?} + top {:.2} s + final {:.2} s; {} B",
        median(tm.leaves.clone()),
        tm.levels.iter().map(|x| (x * 100.0).round() / 100.0).collect::<Vec<_>>(),
        tm.top,
        tm.last,
        bytes.len()
    );
    let v: Vec<f64> = (0..11)
        .map(|_| {
            let t = Instant::now();
            let back = zheng::recursion::wrap::WrapProof::from_bytes(&bytes, &k.last).expect("parse");
            agg::verify(&k, &st, &back).expect("verify");
            ms(t)
        })
        .collect();
    println!("{backend}: verify (parse + statement digests + final level) median {:.2} ms of 11", median(v));
    if let Ok(dir) = std::env::var("ZHENG_BLOCK_OUT") {
        std::fs::write(format!("{dir}/block-{n}-d{depth}-{backend}.bin"), &bytes).expect("write");
    }
}

/// Every single-bit flip of a stored block proof, parsed and verified
/// against its statement on all cores; none may be accepted.
fn flip(file: &str, n: usize, depth: usize) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zheng::recursion::agg::{self, BlockStatement};
    use zheng::recursion::wrap::WrapProof;
    let bytes = std::fs::read(file).expect("block proof");
    let prog = veil_program(32);
    let k = keys(32, depth);
    let (s, _) = rec::prove(&k.veil, &prog, &[], &[5], BUDGET).expect("tx");
    let pins = k.veil.statement_pins(&s).unwrap();
    let st = BlockStatement { txs: vec![pins; n], fields: [1, 2, 3, 4].map(nebu::Goldilocks::new) };
    let honest = WrapProof::from_bytes(&bytes, &k.last).expect("parse");
    agg::verify(&k, &st, &honest).expect("the stored proof verifies");
    let bits = bytes.len() * 8;
    let next = AtomicUsize::new(0);
    let (flips, decoded, accepted, panics) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let t0 = Instant::now();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| {
                let mut buf = bytes.clone();
                loop {
                    let b = next.fetch_add(1, Ordering::Relaxed);
                    if b >= bits {
                        break;
                    }
                    buf[b / 8] ^= 1 << (b % 8);
                    flips.fetch_add(1, Ordering::Relaxed);
                    if let Ok(q) = WrapProof::from_bytes(&buf, &k.last) {
                        decoded.fetch_add(1, Ordering::Relaxed);
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| agg::verify(&k, &st, &q).is_ok())) {
                            Ok(false) => {}
                            Ok(true) => {
                                accepted.fetch_add(1, Ordering::Relaxed);
                                eprintln!("ACCEPTED flip of bit {b}");
                            }
                            Err(_) => {
                                panics.fetch_add(1, Ordering::Relaxed);
                                eprintln!("PANIC on flip of bit {b}");
                            }
                        }
                    }
                    buf[b / 8] ^= 1 << (b % 8);
                    let f = flips.load(Ordering::Relaxed);
                    if f % 50_000 == 0 {
                        eprintln!("  {f} flips · {:.0} s", t0.elapsed().as_secs_f64());
                    }
                }
            });
        }
    });
    println!(
        "bit-flip scan: {} B · {} flips · {} decoded · {} accepted · {} panics · {:.0} s",
        bytes.len(),
        flips.load(Ordering::Relaxed),
        decoded.load(Ordering::Relaxed),
        accepted.load(Ordering::Relaxed),
        panics.load(Ordering::Relaxed),
        t0.elapsed().as_secs_f64()
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("census") => census(args.get(1).and_then(|s| s.parse().ok()).unwrap_or(32)),
        Some("block") => block(
            args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1),
            args.get(2).and_then(|s| s.parse().ok()).unwrap_or(7),
        ),
        Some("flip") => flip(
            &args[1],
            args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1),
            args.get(3).and_then(|s| s.parse().ok()).unwrap_or(7),
        ),
        Some("keys") => {
            keys(32, args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1));
        }
        _ => eprintln!("usage: block_aggregate census [levels] | keys [depth]"),
    }
}
