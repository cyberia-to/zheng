//! Block aggregation (G2, `specs/aggregation.md`): every verifier path —
//! the veil-r transaction verifier and the block verifier — runs on the
//! CPU. Under a recording backend the verifiers make no backend call; under
//! a backend that corrupts every result the verdicts are unchanged.
//!
//! `cargo test --release -p zheng --features test-hooks --test block_aggregate`

#[path = "common/rec.rs"]
mod rec;

use std::sync::Arc;

use lens::rspcs::backend;
use nebu::Goldilocks;
use rec::{Cpu2, Rec};
use zheng::execution::ExecutionNoun as N;
use zheng::execution::veil::rec::{self as veil_r, RecKey};
use zheng::recursion::agg::{self, AggKeys, BlockStatement};
use zheng::recursion::wrap::WrapProof;

fn pair(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}

/// x · x for one secret x (`veil::tests::square_secret`).
fn square_secret() -> N {
    let secret = pair(N::Atom(16), pair(pair(N::Atom(1), N::Atom(0)), pair(N::Atom(1), N::Atom(0))));
    let push = pair(N::Atom(3), pair(secret, pair(N::Atom(0), N::Atom(1))));
    let body = pair(N::Atom(7), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(2))));
    pair(N::Atom(2), pair(push, pair(N::Atom(1), body)))
}

#[test]
fn no_backend_moves_a_block_verdict() {
    // prove under a device-named recording backend (every device path
    // taken with lens's reference kernels)
    let prover = Arc::new(Rec::new("rec-device", false));
    backend::install(prover.clone());
    let program = square_secret();
    let veil = Arc::new(RecKey::new(&program, 0).unwrap());
    let keys = AggKeys::derive(veil.clone(), 1).unwrap();
    let mut txs = Vec::new();
    let mut proofs = Vec::new();
    for x in [11u64, 12] {
        let (s, p) = veil_r::prove_seeded(&veil, &program, &[], &[x], 1000, [x as u8; 32]).unwrap();
        txs.push(veil.statement_pins(&s).unwrap());
        proofs.push(p);
    }
    let st = BlockStatement { txs, fields: [5, 6, 7, 8].map(Goldilocks::new) };
    let (block, _) = agg::prove(&keys, &st, &proofs).unwrap();
    assert!(!prover.counts().is_empty(), "the prover used the backend");
    let bytes = block.to_bytes(&keys.last);
    let mut flipped = bytes.clone();
    flipped[bytes.len() / 2] ^= 4;
    let mut other = st.clone();
    other.txs.swap(0, 1);
    let verdicts = || -> Vec<bool> {
        let mut v = Vec::new();
        for b in [&bytes, &flipped] {
            for s in [&st, &other] {
                v.push(WrapProof::from_bytes(b, &keys.last).is_ok_and(|p| agg::verify(&keys, s, &p).is_ok()));
            }
        }
        for (p, pf) in st.txs.iter().zip(&proofs) {
            v.push(veil_r::verify_pins(&veil, p, pf).is_ok());
        }
        v.push(veil_r::verify_pins(&veil, &st.txs[1], &proofs[0]).is_ok());
        v
    };
    let rec = Arc::new(Rec::new("rec-device", false));
    backend::install(rec.clone());
    let under_rec = verdicts();
    assert!(rec.counts().is_empty(), "a verifier called the backend: {:?}", rec.counts());
    backend::install(Arc::new(Cpu2));
    let under_cpu = verdicts();
    let evil = Arc::new(Rec::new("evil-device", true));
    backend::install(evil.clone());
    let under_evil = verdicts();
    backend::install(Arc::new(Cpu2));
    assert_eq!(under_rec, under_cpu);
    assert_eq!(under_evil, under_cpu, "a corrupting backend moved a verdict");
    assert_eq!(under_cpu, vec![true, false, false, false, true, true, false]);
}
