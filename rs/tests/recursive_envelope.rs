//! Envelope profile 5 (recursive): one IVC proof of hash.tri, wrapped,
//! round-trips canonically and verifies; every truncation, a trailing byte,
//! a wrong profile byte, a wrong format byte, parameters outside the
//! admitted sets and a sample of bit flips are refused.
//!
//! Proving takes ~1–2 min in release; run with `--release`.

mod common;

use std::sync::OnceLock;
use zheng::envelope::recursive::{self, ADMITTED, MAX_PROOF_BYTES, RECURSIVE_FORMAT};
use zheng::envelope::{Envelope, EnvelopeError, HEADER_BYTES, Profile};

const BUDGET: u64 = 1 << 20;

fn envelope() -> &'static (Envelope, Vec<u8>) {
    static E: OnceLock<(Envelope, Vec<u8>)> = OnceLock::new();
    E.get_or_init(|| {
        let e = recursive::prove(&common::parse(common::HASH), &[7], BUDGET, &recursive::params()).unwrap();
        let bytes = e.to_bytes();
        (e, bytes)
    })
}

/// Offset of the proof's length prefix and the proof bytes.
fn proof_span() -> (usize, Vec<u8>) {
    let (e, bytes) = envelope();
    let Envelope::Recursive { params, proof, .. } = e else { unreachable!() };
    let inner = recursive::proof_bytes(params, proof).unwrap();
    let prefix = varint(inner.len() as u64).len();
    (bytes.len() - inner.len() - prefix, inner)
}

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

/// The envelope with its proof replaced by `inner` (prefix recomputed).
fn with_inner(inner: &[u8]) -> Vec<u8> {
    let (at, _) = proof_span();
    let mut out = envelope().1[..at].to_vec();
    out.extend(varint(inner.len() as u64));
    out.extend_from_slice(inner);
    out
}

fn accepted(bytes: &[u8]) -> bool {
    Envelope::from_bytes(bytes).is_ok_and(|e| e.verify(None).is_ok())
}

#[test]
fn a_recursive_envelope_round_trips_canonically_and_verifies() {
    let (e, bytes) = envelope();
    assert_eq!(&bytes[..8], zheng::envelope::MAGIC);
    assert_eq!(bytes[10], Profile::Recursive as u8);
    assert_eq!(bytes[HEADER_BYTES], RECURSIVE_FORMAT);
    let back = Envelope::from_bytes(bytes).unwrap();
    assert_eq!(&back, e);
    assert_eq!(&back.to_bytes(), bytes, "one encoding per value");
    back.verify(None).unwrap();
    // the statement is bound
    let Envelope::Recursive { params, statement, proof } = back else { unreachable!() };
    let mut other = statement.clone();
    other.input = vec![8];
    assert!(Envelope::Recursive { params, statement: other, proof: proof.clone() }.verify(None).is_err());
    let mut other = statement.clone();
    other.cycles += 1;
    assert!(Envelope::Recursive { params, statement: other, proof }.verify(None).is_err());
}

#[test]
fn every_truncation_and_a_trailing_byte_are_rejected() {
    let (_, bytes) = envelope();
    for cut in 0..bytes.len() {
        assert!(Envelope::from_bytes(&bytes[..cut]).is_err(), "prefix {cut}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Envelope::from_bytes(&longer), Err(EnvelopeError::TrailingBytes));
    // inside the length prefix: a shorter or longer proof is refused by the
    // IVC wire itself
    let (_, inner) = proof_span();
    let step = inner.len() / 97;
    for cut in (0..inner.len()).step_by(step).chain(inner.len() - 8..inner.len()) {
        assert!(Envelope::from_bytes(&with_inner(&inner[..cut])).is_err(), "inner prefix {cut}");
    }
    let mut longer = inner.clone();
    longer.push(0);
    assert_eq!(Envelope::from_bytes(&with_inner(&longer)), Err(EnvelopeError::NonCanonical));
}

#[test]
fn a_wrong_profile_or_format_byte_is_rejected() {
    let (_, bytes) = envelope();
    for profile in [0u8, 1, 2, 3, 4] {
        let mut bad = bytes.clone();
        bad[10] = profile;
        assert!(!accepted(&bad), "profile {profile}");
    }
    for profile in [6u8, 0xff] {
        let mut bad = bytes.clone();
        bad[10] = profile;
        assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::UnknownProfile(profile)));
    }
    for format in [0u8, 2, 0xff] {
        let mut bad = bytes.clone();
        bad[HEADER_BYTES] = format;
        assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::NonCanonical));
    }
}

#[test]
fn parameters_outside_the_admitted_sets_are_refused_before_any_key() {
    let (_, bytes) = envelope();
    let at = HEADER_BYTES + 1;
    for rate in [1u8, 3, 5, 7] {
        let mut w = recursive::params();
        w.log_inv_rate = rate;
        let mut bad = bytes.clone();
        bad[at..at + 8].copy_from_slice(&w.header());
        assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::NonCanonical), "rate {rate}");
    }
    let mut w = recursive::params();
    w.pow_bits = 16;
    let mut bad = bytes.clone();
    bad[at..at + 8].copy_from_slice(&w.header());
    assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::NonCanonical));
    // the IVC header's step size
    let (_, inner) = proof_span();
    for log_rows in [0u8, 10, 14, 16, 20, 0xff] {
        let mut bad = inner.clone();
        bad[0] = log_rows;
        assert_eq!(Envelope::from_bytes(&with_inner(&bad)), Err(EnvelopeError::NonCanonical), "log_rows {log_rows}");
    }
    assert_eq!(ADMITTED.len(), 2);
    // a proof length beyond the bound
    let (span, _) = proof_span();
    let mut bad = bytes[..span].to_vec();
    bad.extend(varint(MAX_PROOF_BYTES as u64 + 1));
    assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::TooLarge));
}

#[test]
fn a_sample_of_bit_flips_is_never_accepted() {
    let (_, bytes) = envelope();
    let (span, _) = proof_span();
    // every bit of the header, format, parameters, statement and length
    // prefix; then a stride over the proof
    let bits: Vec<usize> = (0..(span + 3) * 8).chain(((span + 3) * 8..bytes.len() * 8).step_by(1031)).collect();
    let (mut decoded, mut tried) = (0, 0);
    for bit in bits {
        let mut bad = bytes.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        tried += 1;
        if let Ok(e) = Envelope::from_bytes(&bad) {
            decoded += 1;
            assert!(e.verify(None).is_err(), "bit {bit} accepted");
        }
    }
    eprintln!("bit flips: {tried} tried, {decoded} decoded, 0 accepted");
    assert!(decoded > 0);
}
