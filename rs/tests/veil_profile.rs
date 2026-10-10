//! The zk profile on hash.tri's hash with a secret preimage: completeness,
//! agreement with the public profile and with MPC-in-the-head on the same
//! statement, the envelope round trip, size and time against MITH, and the
//! bit-flip scan of a full zk envelope. Numbers print with `--nocapture`;
//! they are recorded in `audit/zk-profile-2026-10.md`.
mod common;

use common::parse;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use zheng::envelope::{Envelope, ZkProof, prove_zk, zk_statement_bytes};
use zheng::execution::{VerifyingKey, certify_execution, private, veil, zk};
use zheng::types::CCSWitness;

/// hash.tri's hash: `hemera(x, 0, 0, 0, 0, 0, 0, 0)` of subject axis 2.
const INNER: &str = "[15 [3 [[0 2] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [1 0]]]]]]]]]]]]]]]]";
/// One secret, no check.
const SECRET: &str = "[16 [[1 0] [1 0]]]";

/// The hash of a secret preimage.
fn hash_secret() -> String {
    format!("[2 [[3 [{SECRET} [0 1]]] [1 {INNER}]]]")
}
/// The same hash of a public input.
fn hash_public() -> String {
    format!("[2 [[3 [[0 2] [0 1]]] [1 {INNER}]]]")
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

#[test]
fn secret_preimage_proofs_agree_with_public_and_mith_and_are_measured() {
    let program = parse(&hash_secret());
    let preimage = 7u64;
    // the public profile on the same hash of a public input
    let (public, _) = certify_execution(&parse(&hash_public()), &[preimage], 1_000_000).unwrap();

    let reps = 11;
    let mut prove_ms = vec![];
    let mut sizes = vec![];
    let mut last = None;
    for _ in 0..reps {
        let t = Instant::now();
        let (s, p) = veil::prove(&program, &[], &[preimage], 1_000_000).unwrap();
        prove_ms.push(ms(t));
        sizes.push(p.as_bytes().len() as f64);
        last = Some((s, p));
    }
    let (statement, proof) = last.unwrap();
    assert_eq!(statement.execution.public_output, public.public_output, "same digest");
    assert!(statement.execution.public_input.is_empty(), "the preimage is not in the statement");
    let vk = VerifyingKey::for_execution(&statement.execution).unwrap();
    let time = |vk: Option<&VerifyingKey>| {
        median(
            (0..21)
                .map(|_| {
                    let t = Instant::now();
                    veil::verify_with(&statement, &proof, vk).unwrap();
                    ms(t)
                })
                .collect(),
        )
    };
    let (cold, cached) = (time(None), time(Some(&vk)));
    let report = veil::report(&statement, &veil::HidingParams::default()).unwrap();
    println!("{report:?}");
    let envelope = prove_zk(&program, &[], &[preimage], 1_000_000, [5; 32]).unwrap();
    let bytes = envelope.to_bytes();
    assert_eq!(bytes[10], 2, "profile byte");
    assert_eq!(Envelope::from_bytes(&bytes).unwrap(), envelope);
    Envelope::from_bytes(&bytes).unwrap().verify(None).unwrap();

    // MPC-in-the-head on the same statement: the differential oracle
    let (mstmt, prepared, witness) = private::prepare_execution(&program, &[], &[preimage], 1_000_000).unwrap();
    assert_eq!(mstmt, statement);
    let public_coords: Vec<_> = prepared
        .public_coordinates
        .iter()
        .map(|&(i, v)| (i, nebu::Goldilocks::new(v)))
        .collect();
    let w = CCSWitness { z: witness.into_iter().map(nebu::Goldilocks::new).collect() };
    let context = [5u8; 32];
    let t = Instant::now();
    let mith = zk::prove(&prepared.relation.instance, &w, &zk_statement_bytes(&mstmt, &context), &public_coords).unwrap();
    let mith_prove = ms(t);
    let t = Instant::now();
    zk::verify(&prepared.relation.instance, &mith, &zk_statement_bytes(&mstmt, &context), &public_coords).unwrap();
    let mith_verify = ms(t);
    let mith_env = Envelope::Zk { statement: mstmt, context, proof: ZkProof::Mith(mith) };
    mith_env.verify(None).unwrap();
    let (lo, hi) = (sizes.iter().cloned().fold(f64::MAX, f64::min), sizes.iter().cloned().fold(0.0, f64::max));
    println!(
        "hash with secret preimage: veil proof {} B (median of {reps}; min {lo}, max {hi}), envelope {} B, \
         prove {:.1} ms, verify {cold:.3} ms ({cached:.3} ms with a cached key); MITH proof {} B, envelope {} B, \
         prove {mith_prove:.1} ms, verify {mith_verify:.1} ms",
        median(sizes.clone()),
        bytes.len(),
        median(prove_ms),
        match &mith_env {
            Envelope::Zk { proof, .. } => proof.as_bytes().len(),
            _ => 0,
        },
        mith_env.to_bytes().len(),
    );
}

#[test]
fn zk_envelopes_bind_statement_and_context() {
    let program = parse(&hash_secret());
    let envelope = prove_zk(&program, &[], &[7], 1_000_000, [5; 32]).unwrap();
    let Envelope::Zk { statement, context, proof } = envelope.clone() else { unreachable!() };
    let mut other = context;
    other[0] ^= 1;
    assert!(Envelope::Zk { statement: statement.clone(), context: other, proof: proof.clone() }.verify(None).is_err());
    let mut forged = statement.clone();
    forged.execution.public_output[0] ^= 1;
    assert!(Envelope::Zk { statement: forged, context, proof: proof.clone() }.verify(None).is_err());
    // the veil bytes under the MITH scheme byte do not decode as MITH
    let mut bytes = envelope.to_bytes();
    bytes[11] = 1;
    assert!(Envelope::from_bytes(&bytes).map_or(true, |e| e.verify(None).is_err()));
    bytes[11] = 3;
    assert!(Envelope::from_bytes(&bytes).is_err());
}

/// Every single-bit change of a full zk envelope must fail to decode or to
/// verify. `cargo test --release --test veil_profile -- --ignored`.
#[test]
#[ignore]
fn every_bit_flip_of_a_zk_envelope_is_rejected() {
    let envelope = prove_zk(&parse(&hash_secret()), &[], &[7], 1_000_000, [5; 32]).unwrap();
    let bytes = envelope.to_bytes();
    assert!(Envelope::from_bytes(&bytes).unwrap().verify(None).is_ok());
    let accepted = AtomicUsize::new(0);
    let total = bytes.len() * 8;
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let t = Instant::now();
    std::thread::scope(|s| {
        for k in 0..threads {
            let (bytes, accepted) = (&bytes, &accepted);
            s.spawn(move || {
                let mut bad = bytes.clone();
                for flip in (k..total).step_by(threads) {
                    let (i, bit) = (flip / 8, 1u8 << (flip % 8));
                    bad[i] ^= bit;
                    if Envelope::from_bytes(&bad).is_ok_and(|e| e.verify(None).is_ok()) {
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
        "zk envelope (veil, hash with secret preimage): {} bytes, {total} flips, {accepted} accepted, {:.0} s",
        bytes.len(),
        t.elapsed().as_secs_f64()
    );
    assert_eq!(accepted, 0);
}
