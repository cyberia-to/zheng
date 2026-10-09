//! Bit-flip scan of a full serialized succinct proof of `hash.tri`: every
//! single-bit change of the envelope must fail to decode or fail to verify.
//! Run for both schemes; the counts are recorded in
//! `audit/succinct-profile-2026-10.md`.
mod common;

use common::{HASH, parse};
use std::sync::atomic::{AtomicUsize, Ordering};
use zheng::envelope::{Envelope, SuccinctStatement};
use zheng::execution::succinct::{self, TensorRs, TensorRsParams, Whir, WhirParams};

fn scan(envelope: &Envelope) -> (usize, usize) {
    let bytes = envelope.to_bytes();
    assert!(Envelope::from_bytes(&bytes).unwrap().verify(None).is_ok());
    let accepted = AtomicUsize::new(0);
    let total = bytes.len() * 8;
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for t in 0..threads {
            let (bytes, accepted) = (&bytes, &accepted);
            s.spawn(move || {
                let mut bad = bytes.clone();
                for flip in (t..total).step_by(threads) {
                    let (i, bit) = (flip / 8, 1u8 << (flip % 8));
                    bad[i] ^= bit;
                    let ok = Envelope::from_bytes(&bad)
                        .is_ok_and(|e| e.verify(None).is_ok());
                    if ok {
                        eprintln!("accepted flip: byte {i} bit {}", flip % 8);
                        accepted.fetch_add(1, Ordering::Relaxed);
                    }
                    bad[i] ^= bit;
                }
            });
        }
    });
    (total, accepted.into_inner())
}

#[test]
fn every_bit_flip_of_a_whir_hash_proof_is_rejected() {
    let (statement, proof) =
        succinct::prove::<Whir>(&WhirParams::default(), &parse(HASH), &[7], 1_000_000).unwrap();
    let e = Envelope::Succinct {
        statement: SuccinctStatement::Execution(statement),
        proof: proof.into(),
    };
    let (flips, accepted) = scan(&e);
    println!("WHIR hash.tri: {} bytes, {flips} flips, {accepted} accepted", e.to_bytes().len());
    assert_eq!(accepted, 0);
}

/// ~3 min on 16 cores; run with `--ignored` (recorded in the audit).
#[test]
#[ignore]
fn every_bit_flip_of_a_tensor_hash_proof_is_rejected() {
    let (statement, proof) =
        succinct::prove::<TensorRs>(&TensorRsParams::default(), &parse(HASH), &[7], 1_000_000)
            .unwrap();
    let e = Envelope::Succinct {
        statement: SuccinctStatement::Execution(statement),
        proof: proof.into(),
    };
    let (flips, accepted) = scan(&e);
    println!("TensorRs hash.tri: {} bytes, {flips} flips, {accepted} accepted", e.to_bytes().len());
    assert_eq!(accepted, 0);
}
