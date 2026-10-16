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
    k
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("census") => census(args.get(1).and_then(|s| s.parse().ok()).unwrap_or(32)),
        Some("keys") => {
            keys(32, args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1));
        }
        _ => eprintln!("usage: block_aggregate census [levels] | keys [depth]"),
    }
}
