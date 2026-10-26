//! zheng #58 review over a stored final proof of the shipped chain
//! (`audit/wrap-fastverify-review-2026-10.md`): the threaded verifier
//! (persistent pool, permutation memo, parallel Merkle chains) accepts and
//! refuses exactly as one verifier alone, under concurrent verifications
//! of honest and tampered proofs; the shipped key's ledger, wiring and
//! constraint graph.
//!
//! `ZHENG_IVC_DIR=<dir> cargo test --release -p zheng --test
//! wrap_fastverify_review -- --ignored`, `<dir>` holding
//! `add.tri.final-<chain>` and `final-<chain>.vk` (`examples/wrap_bench`,
//! `examples/wrap_verify`; chain `wrap::SHIPPED`).

mod common;

use lens::rspcs::field::eq_table;
use nebu::{Fp3, Goldilocks};
use zheng::machine;
use zheng::recursion::circuit::layout::{V1, pre};
use zheng::recursion::ivc;
use zheng::recursion::wrap::{self, FinalProof, WrapKey};

struct Stored {
    key: WrapKey,
    bytes: Vec<u8>,
    prep: ivc::Prepared,
}

fn stored() -> Stored {
    let dir = std::env::var("ZHENG_IVC_DIR").expect("ZHENG_IVC_DIR");
    let chain = wrap::SHIPPED.replace(',', "_");
    let vk = std::fs::read(format!("{dir}/final-{chain}.vk")).expect("stored verifying key");
    let key = WrapKey::from_vk_bytes(&vk).expect("verifying key");
    assert_eq!(key.vk_bytes(), vk, "verifying key round trip");
    let bytes = std::fs::read(format!("{dir}/add.tri.final-{chain}")).expect("stored final proof");
    let mut whir = zheng::execution::succinct::params_for(20);
    whir.log_inv_rate = ivc::SHIPPED_RATE;
    whir.pow_bits = ivc::SHIPPED_POW;
    let run =
        machine::execute_exact(&common::parse(common::ADD), &[7, 5], 1 << 40, 15).expect("run");
    let h = FinalProof::from_bytes(&bytes, &key).expect("parse");
    let prep = ivc::prepare(
        &run.statement,
        &whir,
        h.log_rows,
        h.start,
        h.segments,
        h.chain,
    )
    .expect("prepare");
    Stored { key, bytes, prep }
}

fn check(s: &Stored, bytes: &[u8]) -> Result<(), String> {
    let fp = FinalProof::from_bytes(bytes, &s.key).map_err(|e| format!("parse: {e}"))?;
    wrap::verify_final(&s.prep, &s.key, &fp)
}

/// (8) Every verification, on any thread and interleaved with others,
/// returns what one verifier alone returns — the same accept, the same
/// first failed check — for the honest proof and for tampered ones that
/// still decode.
#[test]
#[ignore]
fn concurrent_verifiers_accept_and_refuse_as_one_verifier_alone() {
    let s = stored();
    check(&s, &s.bytes).expect("the stored proof verifies");
    // bit flips spread over the proof, kept when they still decode
    let n = s.bytes.len();
    let mut cases: Vec<Vec<u8>> = vec![s.bytes.clone()];
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    while cases.len() < 241 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let mut b = s.bytes.clone();
        let at = (x % n as u64) as usize;
        b[at] ^= 1 << ((x >> 32) % 8);
        if FinalProof::from_bytes(&b, &s.key).is_ok() {
            cases.push(b);
        }
    }
    let baseline: Vec<Result<(), String>> = cases.iter().map(|c| check(&s, c)).collect();
    assert!(baseline[0].is_ok());
    assert!(
        baseline[1..].iter().all(|r| r.is_err()),
        "a flipped proof accepted"
    );
    let threads = 12;
    let rounds = 3;
    std::thread::scope(|sc| {
        for th in 0..threads {
            let (s, cases, baseline) = (&s, &cases, &baseline);
            sc.spawn(move || {
                for r in 0..rounds {
                    // each thread its own order; the honest proof often
                    for k in 0..cases.len() {
                        let i = if k % 4 == 0 {
                            0
                        } else {
                            (k * 7919 + th * 104_729 + r * 13) % cases.len()
                        };
                        assert_eq!(
                            check(s, &cases[i]),
                            baseline[i],
                            "thread {th}, round {r}, case {i}"
                        );
                    }
                }
            });
        }
    });
    eprintln!(
        "{} cases ({} decoded flips) × {threads} threads × {rounds} rounds: every result as alone",
        cases.len(),
        cases.len() - 1
    );
}

/// (4, 5, 7) The shipped final key: its ledger with the wiring's actual
/// reads; its successor and key columns from its graph; the compiled
/// graph equals the graph; the slot closing of its wiring equals the
/// per-cell closing at the opening's `|α|`.
#[test]
#[ignore]
fn the_shipped_final_key_ledger_columns_graph_and_wiring() {
    let s = stored();
    let k = &s.key;
    let w = k.wiring.as_ref().expect("final mode");
    let rows = wrap::ledger(&k.params, &k.cfg, k.constraints, w.reads);
    for (nm, b) in &rows {
        eprintln!("shipped final key (reads {}): {nm:<40} {b:.2}", w.reads);
    }
    let weakest = rows.iter().map(|r| r.1).fold(f64::INFINITY, f64::min);
    assert!(
        weakest >= 128.0 && (weakest - 128.07).abs() < 0.01,
        "{weakest}"
    );
    assert_eq!(
        (
            k.params.whir.log_inv_rate,
            k.params.whir.pow_bits,
            k.params.n
        ),
        (10, 32, 15)
    );
    // columns
    let used = k.g.used_inputs();
    assert_eq!(&used[2 * V1..2 * V1 + pre::COUNT], &k.key_cols[..]);
    let next: Vec<usize> = (0..V1).filter(|&c| used[V1 + c]).collect();
    assert_eq!(k.next_cols, next);
    // compiled graph
    let mut x = 7u64;
    let mut e = || {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        Fp3::new(
            Goldilocks::new(x),
            Goldilocks::new(x.rotate_left(21)),
            Goldilocks::new(x.rotate_left(42)),
        )
    };
    for _ in 0..4 {
        let ins: Vec<Fp3> = (0..k.g.inputs).map(|_| e()).collect();
        assert_eq!(k.gc.eval(&ins), k.g.eval(&ins));
    }
    // wiring: slot closing = per-cell, at the opening's |α| = ℓ − fv
    let n = k.params.n as usize;
    let pre_vars = k.cfg.wc.num_vars - k.cfg.wc.final_vars;
    let lambda = e();
    let alpha: Vec<Fp3> = (0..pre_vars).map(|_| e()).collect();
    let fm: Vec<Fp3> = (0..1usize << k.cfg.wc.final_vars).map(|_| e()).collect();
    let slot = w
        .closing(n, lambda, &alpha, &fm)
        .expect("the shipped wiring takes the slot form");
    let lp = w.powers(lambda);
    let ws = w.write_sums(&lp);
    let mut u = vec![Fp3::ZERO; wrap::WORD << n];
    for &(i, xi, c) in &w.read_cells {
        u[xi as usize] += c.apply(lp[i as usize]);
    }
    for &(j, xi, c) in &w.write_cells {
        u[xi as usize] -= c.apply(ws[j as usize]);
    }
    let ea = eq_table(&alpha);
    let mask = (1usize << pre_vars) - 1;
    let cell = u.iter().enumerate().fold(Fp3::ZERO, |a, (xi, &v)| {
        a + v * ea[xi & mask] * fm[xi >> pre_vars]
    });
    assert_eq!(slot, cell);
    eprintln!(
        "shipped final key: {} reads, {} writes, |α| = {pre_vars}, {} of {} key columns, {} successor columns, {} compiled operations",
        w.reads,
        w.write_at.len() - 1,
        k.key_cols.iter().filter(|&&c| c).count(),
        k.key_cols.len(),
        k.next_cols.len(),
        k.gc.len()
    );
}
