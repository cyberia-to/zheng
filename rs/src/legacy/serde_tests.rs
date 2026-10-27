use super::*;
use nox::{NullCalls, Reduction, VecTrace};

/// A proof artifact survives JSON round-trip and still verifies;
/// a tampered byte in the wire form is rejected or fails verification.
#[test]
fn proof_json_roundtrip_verifies() {
    let g = Goldilocks::new;
    let mut order = Reduction::<1024>::new();
    let s = order.atom(g(7)).unwrap();
    let tag0 = order.atom(g(0)).unwrap();
    let addr = order.atom(g(1)).unwrap();
    let axis_f = order.pair(tag0, addr).unwrap();
    let mut trace = VecTrace::default();
    nox::reduce(&mut order, s, axis_f, 100, &NullCalls, &mut trace);
    nox::reduce(&mut order, s, axis_f, 99, &NullCalls, &mut trace);

    let stmt = Statement {
        program_hash: [3u8; 32],
        input_hash: [0u8; 32],
        output_hash: [0u8; 32],
        focus_bound: 10,
        bbg_root: [0u8; 32],
    };
    let params = ProofParams::default();
    let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
    assert!(verify(&tp, &stmt, &params).is_ok());

    let proof_json = serde_json::to_string(&tp).unwrap();
    let stmt_json = serde_json::to_string(&stmt).unwrap();
    let tp2: TraceProof = serde_json::from_str(&proof_json).unwrap();
    let stmt2: Statement = serde_json::from_str(&stmt_json).unwrap();
    assert_eq!(stmt, stmt2);
    assert!(verify(&tp2, &stmt2, &params).is_ok());

    // Non-canonical field element rejected at deserialize.
    let bad = proof_json.replacen("[", "[18446744073709551615,", 1);
    let r: Result<TraceProof, _> = serde_json::from_str(&bad);
    assert!(r.is_err(), "non-canonical wire form must not deserialize");
}

fn zero_statement() -> Statement {
    Statement {
        program_hash: [0u8; 32],
        input_hash: [0u8; 32],
        output_hash: [0u8; 32],
        focus_bound: 0,
        bbg_root: [0u8; 32],
    }
}

/// Every bit position of `bytes` flipped in turn must leave a proof
/// that fails to deserialize or fails to verify. `bits` selects which
/// bits of each byte to flip.
fn assert_wire_tight(bytes: &[u8], stmt: &Statement, bits: &[u8]) {
    let params = ProofParams::default();
    let mut survivors = Vec::new();
    for i in 0..bytes.len() {
        for &b in bits {
            let mut t = bytes.to_vec();
            t[i] ^= 1 << b;
            if let Ok(p) = postcard::from_bytes::<TraceProof>(&t)
                && verify(&p, stmt, &params).is_ok()
            {
                survivors.push((i, b));
            }
        }
    }
    assert!(
        survivors.is_empty(),
        "{} single-bit flips still verify (byte, bit): {:?}",
        survivors.len(),
        &survivors[..survivors.len().min(16)]
    );
}

/// Wire tightness: every bit of a serialized proof is verifier-checked.
/// A flip that still verifies would mean the verifier accepted a proof
/// different from the one produced — or that the wire carries bytes
/// the verifier never reads. Universal group only (no openings), every
/// bit of every byte.
#[test]
fn every_bit_of_the_wire_is_checked() {
    let g = Goldilocks::new;
    let mut order = Reduction::<1024>::new();
    let obj = order.atom(g(0)).unwrap();
    let t1 = order.atom(g(1)).unwrap();
    let five = order.atom(g(5)).unwrap();
    let formula = order.pair(t1, five).unwrap();
    let mut trace = VecTrace::default();
    nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);
    nox::reduce(&mut order, obj, formula, 10, &NullCalls, &mut trace);

    let stmt = zero_statement();
    let params = ProofParams::default();
    let tp = commit(&trace, &[], &[], &[], &stmt, &params).unwrap();
    let bytes = postcard::to_allocvec(&tp).unwrap();
    let back: TraceProof = postcard::from_bytes(&bytes).unwrap();
    assert!(verify(&back, &stmt, &params).is_ok(), "the untouched wire verifies");
    assert_wire_tight(&bytes, &stmt, &[0, 1, 2, 3, 4, 5, 6, 7]);
}

/// Wire tightness of a two-group proof (a hash block: universal +
/// binding group, two lens openings). Bits 0 and 7 of every byte — the
/// value bit and the varint continuation bit.
#[test]
fn every_byte_of_a_two_group_wire_is_checked() {
    let g = Goldilocks::new;
    let mut order = Reduction::<1024>::new();
    let s = order.atom(g(42)).unwrap();
    let tag1 = order.atom(g(1)).unwrap();
    let tag15 = order.atom(g(15)).unwrap();
    let quote_f = order.pair(tag1, s).unwrap();
    let hash_f = order.pair(tag15, quote_f).unwrap();
    let mut trace = VecTrace::default();
    nox::reduce(&mut order, s, hash_f, 100, &NullCalls, &mut trace);
    let d = *order.digest(s).unwrap();
    let rate = [d[0], d[1], d[2], d[3], g(0), g(0), g(0), g(0)];

    let stmt = zero_statement();
    let params = ProofParams::default();
    let tp = commit(&trace, &[HashAux { rate }], &[], &[], &stmt, &params).unwrap();
    assert_eq!(tp.group_count(), 2);
    let bytes = postcard::to_allocvec(&tp).unwrap();
    assert_wire_tight(&bytes, &stmt, &[0, 7]);
}
