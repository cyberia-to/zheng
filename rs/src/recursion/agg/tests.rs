//! Block aggregation: completeness, and the statement attacks — a missing,
//! an extra, a reordered or an altered transaction, other block fields, a
//! tampered transaction proof — are refused. Every verifier here runs on
//! the CPU backend (the test process never selects a device).

use std::sync::{Arc, OnceLock};

use nebu::Goldilocks;

use super::*;
use crate::execution::veil::rec::{self, RecKey};
use crate::execution::veil::tests::square_secret;

struct Fixture {
    keys: AggKeys,
    st: BlockStatement,
    proofs: Vec<RecProof>,
    block: WrapProof,
}

/// Three transactions (x² for x = 3, 4, 5) at depth 2: a full pair and a
/// lone child at level 1.
fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let program = square_secret();
        let veil = Arc::new(RecKey::new(&program, 0).unwrap());
        let keys = AggKeys::derive(veil.clone(), 2).unwrap();
        let mut txs = Vec::new();
        let mut proofs = Vec::new();
        for x in [3u64, 4, 5] {
            let (s, p) = rec::prove_seeded(&veil, &program, &[], &[x], 1000, [x as u8; 32]).unwrap();
            txs.push(veil.statement_pins(&s).unwrap());
            proofs.push(p);
        }
        let st = BlockStatement { txs, fields: [7, 8, 9, 10].map(Goldilocks::new) };
        let (block, _) = prove(&keys, &st, &proofs).unwrap();
        Fixture { keys, st, proofs, block }
    })
}

#[test]
fn a_block_proof_verifies_and_is_at_most_64_kib() {
    let f = fixture();
    verify(&f.keys, &f.st, &f.block).unwrap();
    let bytes = f.block.to_bytes(&f.keys.last);
    assert!(bytes.len() <= f.keys.max_proof_bytes() && f.keys.max_proof_bytes() <= wrap::MAX_FINAL_BYTES);
    let back = WrapProof::from_bytes(&bytes, &f.keys.last).unwrap();
    verify(&f.keys, &f.st, &back).unwrap();
}

#[test]
fn a_missing_extra_reordered_or_altered_transaction_is_refused() {
    let f = fixture();
    let mut bad = Vec::new();
    let mut s = f.st.clone();
    s.txs.pop();
    bad.push(("missing", s));
    let mut s = f.st.clone();
    s.txs.push(f.st.txs[0].clone());
    bad.push(("extra", s));
    let mut s = f.st.clone();
    s.txs.swap(0, 2);
    bad.push(("reordered", s));
    for i in 0..f.st.txs.len() {
        for j in 0..f.st.txs[i].len() {
            let mut s = f.st.clone();
            s.txs[i][j] += Goldilocks::ONE;
            bad.push(("altered pin", s));
        }
    }
    let mut s = f.st.clone();
    s.fields[2] += Goldilocks::ONE;
    bad.push(("fields", s));
    for (what, s) in bad {
        assert!(verify(&f.keys, &s, &f.block).is_err(), "{what}");
    }
}

#[test]
fn a_tampered_transaction_proof_is_refused_natively_and_by_the_circuit() {
    let f = fixture();
    let mut proofs = f.proofs.clone();
    proofs[1].linear[0] += nebu::Fp3::ONE;
    assert!(prove(&f.keys, &f.st, &proofs).is_err(), "the aggregator's check");
    // the circuit itself: the leaf program on the tampered proof fails
    let mut b = Builder::new(true);
    let (_, c) = program::leaf(&mut b, &f.keys.veil, &f.st.txs[1], &proofs[1]);
    b.set_output(&c);
    assert!(b.finish().is_err());
    // a proof of transaction 0 under transaction 1's pins
    let mut b = Builder::new(true);
    let (_, c) = program::leaf(&mut b, &f.keys.veil, &f.st.txs[1], &f.proofs[0]);
    b.set_output(&c);
    assert!(b.finish().is_err());
}

#[test]
fn a_lone_child_cannot_stand_for_a_pair() {
    // h = 0 with a right digest other than the left's fails the circuit
    let f = fixture();
    let d = wrap::dummy_proof(&f.keys.levels[0]);
    let mut b = Builder::new(true);
    let (_, l, r) = program::node_digest(&mut b, &[Goldilocks::ONE; 4], &[Goldilocks::new(2); 4], false);
    let _ = (l, r, d);
    assert!(b.finish().is_err());
}
