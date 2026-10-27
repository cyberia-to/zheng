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
                    let ok = Envelope::from_bytes(&bad).is_ok_and(|e| e.verify(None).is_ok());
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
    println!(
        "WHIR hash.tri: {} bytes, {flips} flips, {accepted} accepted",
        e.to_bytes().len()
    );
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
    println!(
        "TensorRs hash.tri: {} bytes, {flips} flips, {accepted} accepted",
        e.to_bytes().len()
    );
    assert_eq!(accepted, 0);
}

/// The shipped one-relation parameters (`device_params`, 16 grinding bits
/// at this size) through `prove_default`.
#[test]
fn every_bit_flip_of_a_shipped_device_proof_is_rejected() {
    let (statement, proof) = succinct::prove_default(&parse(HASH), &[7], 1_000_000).unwrap();
    let e = Envelope::Succinct {
        statement: SuccinctStatement::Execution(statement),
        proof,
    };
    let (flips, accepted) = scan(&e);
    println!(
        "device_params hash.tri: {} bytes, {flips} flips, {accepted} accepted",
        e.to_bytes().len()
    );
    assert_eq!(accepted, 0);
}

/// The 2^17 / 2^18 classes' shape (folding 5; 16 and 22 grinding bits) at
/// hash.tri's size; ~1 min each on 16 cores.
#[test]
#[ignore]
fn every_bit_flip_of_a_folding_5_proof_is_rejected() {
    for pow_bits in [16, 22] {
        let p = WhirParams {
            log_inv_rate: 6,
            folding_factor: 5,
            pow_bits,
            ..WhirParams::default()
        };
        let (statement, proof) =
            succinct::prove::<Whir>(&p, &parse(HASH), &[7], 1_000_000).unwrap();
        let e = Envelope::Succinct {
            statement: SuccinctStatement::Execution(statement),
            proof: proof.into(),
        };
        let (flips, accepted) = scan(&e);
        println!(
            "WHIR 1/64 k=5 pow={pow_bits} hash.tri: {} bytes, {flips} flips, {accepted} accepted",
            e.to_bytes().len()
        );
        assert_eq!(accepted, 0);
    }
}

/// A hemera Merkle path through the node jet (`execution::node`), depth 4,
/// shipped parameters: the program carries the node formula, so flips land
/// in the formula's tokens, the path, the proof. ~4 min on 16 cores; run
/// with `--ignored` (recorded in `audit/fast-path-2-2026-10.md`).
#[test]
#[ignore]
fn every_bit_flip_of_a_node_merkle_proof_is_rejected() {
    let levels = 4;
    let root = zheng::execution::node::digest_noun(common::node_merkle_root(levels, 5));
    let program = common::node_merkle_program(levels, Some(&root));
    let (statement, proof) = succinct::prove_default(&program, &[5], 1 << 40).unwrap();
    let e = Envelope::Succinct {
        statement: SuccinctStatement::Execution(statement),
        proof,
    };
    let (flips, accepted) = scan(&e);
    println!(
        "node-merkle-4: {} bytes, {flips} flips, {accepted} accepted",
        e.to_bytes().len()
    );
    assert_eq!(accepted, 0);
}
