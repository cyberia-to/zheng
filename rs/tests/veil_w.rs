//! veil-W (research, `docs/explanation/zk-small.md`): attacks on the public
//! API and the bit-flip scan.
mod common;

use common::parse;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use zheng::execution::veil::small::{self, SmallProof};

/// hash.tri's hash of a secret preimage (`tests/veil_profile.rs`'s fixture).
fn hash_secret() -> String {
    let inner = "[15 [3 [[0 2] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [1 0]]]]]]]]]]]]]]]]";
    format!("[2 [[3 [[16 [[1 0] [1 0]]] [0 1]]] [1 {inner}]]]")
}

#[test]
fn proofs_of_one_statement_do_not_verify_another() {
    let p = parse(&hash_secret());
    let (s7, p7) = small::prove(&p, &[], &[7], 1 << 20).unwrap();
    let (s8, p8) = small::prove(&p, &[], &[8], 1 << 20).unwrap();
    small::verify(&s7, &p7).unwrap();
    small::verify(&s8, &p8).unwrap();
    assert!(small::verify(&s7, &p8).is_err());
    assert!(small::verify(&s8, &p7).is_err());
    let mut forged = s7.clone();
    forged.execution.cycles += 1;
    assert!(small::verify(&forged, &p7).is_err(), "cycles");
    let mut forged = s7.clone();
    forged.execution.budget += 1;
    assert!(small::verify(&forged, &p7).is_err(), "budget");
}

#[test]
fn spliced_proofs_are_rejected() {
    // the head of one proof with the opening of another of the same statement
    let p = parse(&hash_secret());
    let (s, a) = small::prove(&p, &[], &[7], 1 << 20).unwrap();
    let (_, b) = small::prove(&p, &[], &[7], 1 << 20).unwrap();
    let (a, b) = (a.as_bytes(), b.as_bytes());
    for cut in [48, a.len() / 4, a.len() / 2, a.len() - 100] {
        let mut x = a[..cut].to_vec();
        x.extend_from_slice(&b[cut..]);
        let proof = SmallProof::from_bytes(&x).unwrap();
        assert!(small::verify(&s, &proof).is_err(), "cut {cut}");
    }
}

#[test]
fn weak_or_foreign_parameters_are_refused() {
    let p = parse(&hash_secret());
    let (s, proof) = small::prove(&p, &[], &[7], 1 << 20).unwrap();
    let bytes = proof.as_bytes();
    // header = bytes[8..16]: version, rate, folding, pow, target (2), decoding, final
    for (pos, value) in [(11usize, 0u8), (11, 4), (9, 7), (10, 9), (12, 100), (13, 0), (14, 0), (15, 17), (8, 2)] {
        let mut b = bytes.to_vec();
        b[pos] = value;
        if b == bytes {
            continue;
        }
        let ok = SmallProof::from_bytes(&b).is_ok_and(|q| small::verify(&s, &q).is_ok());
        assert!(!ok, "header byte {pos} = {value}");
    }
}

#[test]
#[ignore = "bit-flip scan: minutes on 16 threads"]
fn every_bit_flip_of_a_veil_w_proof_is_rejected() {
    let (s, proof) = small::prove(&parse(&hash_secret()), &[], &[7], 1 << 20).unwrap();
    let bytes = proof.as_bytes().to_vec();
    small::verify(&s, &proof).unwrap();
    let accepted = AtomicUsize::new(0);
    let total = bytes.len() * 8;
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let t = Instant::now();
    std::thread::scope(|sc| {
        for k in 0..threads {
            let (bytes, accepted, s) = (&bytes, &accepted, &s);
            sc.spawn(move || {
                let mut bad = bytes.clone();
                for flip in (k..total).step_by(threads) {
                    let (i, bit) = (flip / 8, 1u8 << (flip % 8));
                    bad[i] ^= bit;
                    if SmallProof::from_bytes(&bad).is_ok_and(|q| small::verify(s, &q).is_ok()) {
                        eprintln!("accepted flip: byte {i} bit {}", flip % 8);
                        accepted.fetch_add(1, Ordering::Relaxed);
                    }
                    bad[i] ^= bit;
                }
            });
        }
    });
    let accepted = accepted.into_inner();
    println!(
        "veil-W proof (hash with secret preimage): {} bytes, {total} flips, {accepted} accepted, {:.0} s",
        bytes.len(),
        t.elapsed().as_secs_f64()
    );
    assert_eq!(accepted, 0);
}
