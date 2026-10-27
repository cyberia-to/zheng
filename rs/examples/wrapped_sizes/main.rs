//! Profile-6 envelopes (`envelope::wrapped`) of fixtures: bytes against
//! the hard bound, prove time per backend, verify time (keys cached).
//!
//! `wrapped_sizes [fixture…]` (add.tri, hash.tri, merkle-32, tree-<k>,
//! rec-<n>); `ZHENG_BACKEND=cpu|metal|webgpu|auto` (default auto).

#[path = "../../tests/common/mod.rs"]
mod common;

use std::time::Instant;
use zheng::envelope::{Envelope, wrapped};
use zheng::execution::ExecutionNoun as N;
use zheng::machine;
use zheng::recursion::wrap;

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

fn main() {
    let choice: String = std::env::var("ZHENG_BACKEND").unwrap_or_else(|_| "auto".into());
    let backend = choice.parse::<cyber_lens_gpu::Choice>().and_then(cyber_lens_gpu::install).expect("backend");
    eprintln!("backend: {} ({})", backend.0, backend.1);
    let names: Vec<String> = std::env::args().skip(1).collect();
    let names = if names.is_empty() { vec!["hash.tri".to_string()] } else { names };
    let t = Instant::now();
    let keys = wrapped::chain_keys().expect("chain keys");
    let bound = wrap::max_proof_bytes(keys.last().expect("final key"));
    eprintln!("chain keys {:.1} s · final proof ≤ {bound} B over every transcript", t.elapsed().as_secs_f64());
    for name in names {
        let (prog, input) = fixture(&name).unwrap_or_else(|| panic!("fixture {name}"));
        let t = Instant::now();
        let env = wrapped::prove(&prog, &input, 1 << 40).expect("prove");
        let prove = t.elapsed().as_secs_f64();
        let bytes = env.to_bytes();
        let tokens = machine::statement::tokens(&prog);
        let mut v = Vec::new();
        for _ in 0..11 {
            let t = Instant::now();
            let back = Envelope::from_bytes_for(&bytes, &tokens).expect("decode");
            back.verify_program(&tokens, None).expect("verify");
            v.push(t.elapsed().as_secs_f64() * 1e3);
        }
        v.sort_by(|a, b| a.partial_cmp(b).expect("times"));
        println!(
            "{name}: envelope {} B (proof bound {bound} B) · prove {prove:.1} s on {} · decode+verify median {:.2} ms",
            bytes.len(),
            backend.0,
            v[5]
        );
    }
}
