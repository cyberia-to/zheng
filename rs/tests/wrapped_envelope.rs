//! Envelope profile 6 (wrapped): one final proof of hash.tri round-trips
//! canonically and verifies; every truncation, a trailing byte, a wrong
//! profile byte, a wrong format byte, a chain outside the admitted one and
//! a sample of bit flips are refused.
//!
//! The chain is refused before any key is built (cheap tests, run by
//! default). The proof tests are ignored by default: proving runs the IVC
//! and the wrap chain (~20 min, peak ~38 GB). Run them with `--release
//! -- --ignored`; `ZHENG_WRAPPED_ENVELOPE=<file>` stores the envelope on
//! the first run and reuses it after.

mod common;

use std::sync::OnceLock;
use zheng::envelope::wrapped::{self, LEVELS, MAX_PROOF_BYTES, WRAPPED_FORMAT};
use zheng::envelope::{Envelope, EnvelopeError, HEADER_BYTES, MAGIC, Profile, VERSION};

const BUDGET: u64 = 1 << 20;

fn header() -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    b.extend(VERSION.to_le_bytes());
    b.push(Profile::Wrapped as u8);
    b
}

/// A minimal statement: program `0`, no inputs, output `0`, 0 cycles,
/// budget 0, no state.
const STATEMENT: [u8; 9] = [1, 0, 0, 0, 1, 0, 0, 0, 0];

/// A body under the admitted chain with `proof` as its final proof.
fn body_with(proof: &[u8]) -> Vec<u8> {
    let mut b = header();
    b.push(WRAPPED_FORMAT);
    b.extend(wrapped::chain_bytes());
    b.extend(STATEMENT);
    b.push(0); // state: none
    b.extend(varint(proof.len() as u64));
    b.extend_from_slice(proof);
    b
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

#[test]
fn a_chain_outside_the_admitted_one_is_refused_before_any_key() {
    let chain = wrapped::chain_bytes();
    assert_eq!(chain.len(), 8 + 1 + LEVELS * 9);
    let good = body_with(&[15]);
    // the chain's every byte changed, the format byte, the step size
    for i in 0..chain.len() {
        for delta in [1u8, 0x80] {
            let mut bad = good.clone();
            bad[HEADER_BYTES + 1 + i] ^= delta;
            assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::NonCanonical), "chain byte {i}");
        }
    }
    for format in [0u8, 2, 0xff] {
        let mut bad = good.clone();
        bad[HEADER_BYTES] = format;
        assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::NonCanonical), "format {format}");
    }
    for log_rows in [0u8, 10, 14, 16, 20, 0xff] {
        assert_eq!(Envelope::from_bytes(&body_with(&[log_rows])), Err(EnvelopeError::NonCanonical), "log_rows {log_rows}");
    }
    // a proof length beyond the bound, an empty proof
    let mut bad = body_with(&[]);
    bad.pop();
    bad.extend(varint(MAX_PROOF_BYTES as u64 + 1));
    assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::TooLarge));
    assert_eq!(Envelope::from_bytes(&body_with(&[])), Err(EnvelopeError::Truncated));
    assert!(!wrapped::final_key_cached() || std::env::var_os("ZHENG_WRAPPED_ENVELOPE").is_some(), "a key was built");
}

fn envelope() -> &'static (Envelope, Vec<u8>) {
    static E: OnceLock<(Envelope, Vec<u8>)> = OnceLock::new();
    E.get_or_init(|| {
        let file = std::env::var("ZHENG_WRAPPED_ENVELOPE").ok();
        if let Some(bytes) = file.as_ref().and_then(|f| std::fs::read(f).ok()) {
            return (Envelope::from_bytes(&bytes).expect("stored envelope"), bytes);
        }
        let e = wrapped::prove(&common::parse(common::HASH), &[7], BUDGET).unwrap();
        let bytes = e.to_bytes();
        if let Some(f) = file {
            std::fs::write(f, &bytes).expect("store the envelope");
        }
        (e, bytes)
    })
}

/// Offset of the proof's length prefix and the proof bytes.
fn proof_span() -> (usize, Vec<u8>) {
    let (e, bytes) = envelope();
    let Envelope::Wrapped { proof, .. } = e else { unreachable!() };
    let inner = wrapped::proof_bytes(proof).unwrap();
    let prefix = varint(inner.len() as u64).len();
    (bytes.len() - inner.len() - prefix, inner)
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
#[ignore = "proves the wrap chain: ~20 min, ~38 GB"]
fn a_wrapped_envelope_round_trips_canonically_and_verifies() {
    let (e, bytes) = envelope();
    assert_eq!(&bytes[..8], MAGIC);
    assert_eq!(bytes[10], Profile::Wrapped as u8);
    assert_eq!(bytes[HEADER_BYTES], WRAPPED_FORMAT);
    assert!(bytes.len() <= 64 * 1024, "{} B", bytes.len());
    let back = Envelope::from_bytes(bytes).unwrap();
    assert_eq!(&back, e);
    assert_eq!(&back.to_bytes(), bytes, "one encoding per value");
    back.verify(None).unwrap();
    // the statement is bound
    let Envelope::Wrapped { statement, proof } = back else { unreachable!() };
    for f in [
        (|s: &mut zheng::machine::MachineStatement| s.input = vec![8]) as fn(&mut _),
        |s| s.cycles += 1,
        |s| s.budget += 1,
        |s| s.output = zheng::machine::statement::tokens(&zheng::execution::ExecutionNoun::Atom(13)),
    ] {
        let mut other = statement.clone();
        f(&mut other);
        assert!(Envelope::Wrapped { statement: other, proof: proof.clone() }.verify(None).is_err());
    }
}

#[test]
#[ignore = "proves the wrap chain: ~20 min, ~38 GB"]
fn every_truncation_and_a_trailing_byte_are_rejected() {
    let (_, bytes) = envelope();
    for cut in 0..bytes.len() {
        assert!(Envelope::from_bytes(&bytes[..cut]).is_err(), "prefix {cut}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Envelope::from_bytes(&longer), Err(EnvelopeError::TrailingBytes));
    // inside the length prefix: a shorter or longer proof is refused by the
    // final proof's wire itself
    let (_, inner) = proof_span();
    for cut in 0..inner.len() {
        assert!(Envelope::from_bytes(&with_inner(&inner[..cut])).is_err(), "inner prefix {cut}");
    }
    let mut longer = inner.clone();
    longer.push(0);
    assert_eq!(Envelope::from_bytes(&with_inner(&longer)), Err(EnvelopeError::NonCanonical));
}

#[test]
#[ignore = "proves the wrap chain: ~20 min, ~38 GB"]
fn a_wrong_profile_or_format_byte_is_rejected() {
    let (_, bytes) = envelope();
    for profile in [0u8, 1, 2, 3, 4, 5] {
        let mut bad = bytes.clone();
        bad[10] = profile;
        assert!(!accepted(&bad), "profile {profile}");
    }
    for profile in [7u8, 0xff] {
        let mut bad = bytes.clone();
        bad[10] = profile;
        assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::UnknownProfile(profile)));
    }
    for format in [0u8, 2, 0xff] {
        let mut bad = bytes.clone();
        bad[HEADER_BYTES] = format;
        assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::NonCanonical));
    }
    // a final proof of another step size
    let (_, inner) = proof_span();
    for log_rows in [14u8, 16] {
        let mut bad = inner.clone();
        bad[0] = log_rows;
        assert_eq!(Envelope::from_bytes(&with_inner(&bad)), Err(EnvelopeError::NonCanonical));
    }
}

#[test]
#[ignore = "proves the wrap chain: ~20 min, ~38 GB"]
fn a_sample_of_bit_flips_is_never_accepted() {
    let (_, bytes) = envelope();
    let (span, _) = proof_span();
    // every bit of the header, format, chain, statement and length prefix;
    // then a stride over the proof
    let bits: Vec<usize> = (0..(span + 3) * 8).chain(((span + 3) * 8..bytes.len() * 8).step_by(257)).collect();
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
