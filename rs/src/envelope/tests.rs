//! Envelope round trips for every live profile and strict rejection of every
//! malformed header and body.
use super::*;
use crate::execution::private::prepare_execution;
use crate::execution::state::certify_state_execution;
use crate::execution::{ExecutionNoun as N, certify_execution};

fn pair(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}
fn quote(v: u64) -> N {
    pair(N::Atom(1), N::Atom(v))
}
/// (a + b) · a over subject [a [b 0]].
fn add_mul() -> N {
    let add = pair(N::Atom(5), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(6))));
    pair(N::Atom(7), pair(add, pair(N::Atom(0), N::Atom(2))))
}
fn cell(ns: u64, key: u64) -> Option<u64> {
    ((ns, key) == (2, 11)).then_some(42)
}
const ROOT: [u64; 4] = [1, 2, 3, 4];

/// Verify as a deployment does: state reads come from a state certificate
/// verified under the envelope's own root, which answers only for ROOT.
fn verify_authenticated(e: &Envelope) -> Result<(), String> {
    let root = match e {
        Envelope::StatePublic { statement, .. } => statement.state_root,
        _ => ROOT,
    };
    e.verify(&mut |ns, key| if root == ROOT { cell(ns, key) } else { None })
}

fn public() -> Envelope {
    let (statement, certificate) = certify_execution(&add_mul(), &[7, 5], 1000).unwrap();
    Envelope::Public { statement, certificate }
}

fn state() -> Envelope {
    let program = pair(N::Atom(7), pair(pair(N::Atom(17), pair(quote(2), quote(11))), quote(3)));
    let (statement, certificate) =
        certify_state_execution(&program, &[], 1000, ROOT, true, [9; 32], &mut cell)
            .unwrap();
    Envelope::StatePublic { statement, certificate }
}

fn zk_envelope() -> Envelope {
    let (statement, prepared, witness) = prepare_execution(&add_mul(), &[7, 5], &[], 1000).unwrap();
    let context = [3u8; 32];
    let public: Vec<_> = prepared
        .public_coordinates
        .iter()
        .map(|&(i, v)| (i, nebu::Goldilocks::new(v)))
        .collect();
    let witness = crate::types::CCSWitness {
        z: witness.into_iter().map(nebu::Goldilocks::new).collect(),
    };
    let proof = zk::prove(
        &prepared.relation.instance,
        &witness,
        &zk_statement_bytes(&statement, &context),
        &public,
    )
    .unwrap();
    Envelope::Zk { statement, context, proof }
}

#[test]
fn every_live_profile_round_trips_canonically_and_verifies() {
    for envelope in [public(), state(), zk_envelope()] {
        let bytes = envelope.to_bytes();
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), VERSION);
        assert_eq!(bytes[10], envelope.profile() as u8);
        let back = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(back, envelope);
        assert_eq!(back.to_bytes(), bytes, "one encoding per value");
        back.verify(&mut cell).unwrap();
    }
}

#[test]
fn wrong_magic_version_and_profile_are_rejected() {
    let bytes = public().to_bytes();
    let mut bad = bytes.clone();
    bad[..8].copy_from_slice(b"JOYEXEC3");
    assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::BadMagic));
    for version in [0u16, 2, u16::MAX] {
        let mut bad = bytes.clone();
        bad[8..10].copy_from_slice(&version.to_le_bytes());
        assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::UnsupportedVersion(version)));
    }
    let mut bad = bytes.clone();
    bad[10] = 1;
    assert_eq!(
        Envelope::from_bytes(&bad),
        Err(EnvelopeError::ReservedProfile(Profile::Succinct))
    );
    for profile in [4u8, 0x80, 0xff] {
        let mut bad = bytes.clone();
        bad[10] = profile;
        assert_eq!(Envelope::from_bytes(&bad), Err(EnvelopeError::UnknownProfile(profile)));
    }
    // a public body under the zk or state profile byte does not decode or verify
    for profile in [2u8, 3] {
        let mut bad = bytes.clone();
        bad[10] = profile;
        let accepted =
            Envelope::from_bytes(&bad).map(|e| e.verify(&mut cell).is_ok()).unwrap_or(false);
        assert!(!accepted, "profile {profile}");
    }
}

#[test]
fn truncation_and_trailing_bytes_are_rejected() {
    for envelope in [public(), state()] {
        let bytes = envelope.to_bytes();
        for cut in 0..bytes.len() {
            assert!(Envelope::from_bytes(&bytes[..cut]).is_err(), "prefix {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Envelope::from_bytes(&longer), Err(EnvelopeError::TrailingBytes));
    }
    let bytes = zk_envelope().to_bytes();
    for cut in [0, 10, 11, 200, bytes.len() / 2, bytes.len() - 1] {
        assert!(Envelope::from_bytes(&bytes[..cut]).is_err(), "zk prefix {cut}");
    }
}

/// Byte ranges every change of which must be rejected: the header and the
/// statement. The certificate tail may hold "don't care" wires (see the
/// malleability tests); the state context is caller metadata that zheng
/// carries but does not interpret (joy binds program name and source hash).
fn bound_ranges(envelope: &Envelope) -> Vec<core::ops::Range<usize>> {
    let len = |f: &dyn Fn(&mut codec::Writer)| {
        let mut w = codec::Writer::default();
        f(&mut w);
        w.bytes.len()
    };
    match envelope {
        Envelope::Public { statement, .. } => {
            vec![0..HEADER_BYTES + len(&|w| body::execution(statement, w))]
        }
        Envelope::StatePublic { statement, .. } => {
            let roots = len(&|w| {
                body::execution(&statement.execution, w);
                statement.state_root.iter().for_each(|&l| w.varint(l));
            });
            let reads = len(&|w| {
                w.bool(statement.root_in_subject);
                w.len(statement.reads.len());
                for r in &statement.reads {
                    w.bool(r.active);
                    [r.namespace, r.key, r.value].iter().for_each(|&v| w.varint(v));
                }
            });
            let context_end = HEADER_BYTES + roots + 32;
            vec![0..HEADER_BYTES + roots, context_end..context_end + reads]
        }
        Envelope::Zk { .. } => unreachable!(),
    }
}

/// The execution facts of a decoded envelope: everything but the budget,
/// which only declares an upper bound (any budget ≥ cycles states a truth).
fn facts(e: &Envelope) -> Envelope {
    let mut e = e.clone();
    match &mut e {
        Envelope::Public { statement, .. } => statement.budget = 0,
        Envelope::StatePublic { statement, .. } => statement.execution.budget = 0,
        Envelope::Zk { statement, .. } => statement.execution.budget = 0,
    }
    e
}

#[test]
fn every_single_byte_change_of_header_and_statement_is_rejected() {
    for envelope in [public(), state()] {
        let bytes = envelope.to_bytes();
        let mut budget_only = 0;
        for range in bound_ranges(&envelope) {
            for i in range {
                for delta in [1u8, 0x80, 0xff] {
                    let mut bad = bytes.clone();
                    bad[i] ^= delta;
                    let Ok(decoded) = Envelope::from_bytes(&bad) else { continue };
                    if verify_authenticated(&decoded).is_err() {
                        continue;
                    }
                    assert_eq!(
                        facts(&decoded),
                        facts(&envelope),
                        "{:?} byte {i} ^ {delta:#x} changed an execution fact",
                        envelope.profile()
                    );
                    budget_only += 1;
                }
            }
        }
        // only the budget's own varint can move, and only upward-compatible
        assert!(budget_only <= 6, "{budget_only} budget-only changes");
    }
}

#[test]
fn zk_context_and_proof_bytes_are_bound() {
    let Envelope::Zk { statement, context, proof } = zk_envelope() else { unreachable!() };
    let mut other = context;
    other[0] ^= 1;
    let moved = Envelope::Zk { statement: statement.clone(), context: other, proof: proof.clone() };
    assert!(moved.verify(&mut cell).is_err());
    let mut forged = statement.clone();
    forged.execution.public_output[0] += 1;
    assert!(Envelope::Zk { statement: forged, context, proof }.verify(&mut cell).is_err());
}

#[test]
fn hostile_lengths_fail_before_allocation() {
    let mut w = codec::Writer::default();
    w.raw(MAGIC);
    w.raw(&VERSION.to_le_bytes());
    w.raw(&[0]);
    w.varint(u64::MAX); // program length
    assert_eq!(Envelope::from_bytes(&w.bytes), Err(EnvelopeError::TooLarge));
    let mut w = codec::Writer::default();
    w.raw(MAGIC);
    w.raw(&VERSION.to_le_bytes());
    w.raw(&[0]);
    w.varint(4096); // within the bound, but no bytes follow
    assert_eq!(Envelope::from_bytes(&w.bytes), Err(EnvelopeError::Truncated));
    let oversized = vec![0u8; MAX_BYTES + 1];
    assert_eq!(Envelope::from_bytes(&oversized), Err(EnvelopeError::TooLarge));
}

#[test]
fn noncanonical_body_values_are_rejected() {
    let Envelope::Public { statement, certificate } = public() else { unreachable!() };
    let encode = |s: &ExecutionStatement, c: &Certificate| {
        Envelope::Public { statement: s.clone(), certificate: c.clone() }.to_bytes()
    };
    let mut big = statement.clone();
    big.public_output[0] = nebu::field::P;
    assert_eq!(Envelope::from_bytes(&encode(&big, &certificate)), Err(EnvelopeError::NonCanonical));
    let mut zero_tail = certificate.clone();
    zero_tail.free.push(0);
    assert_eq!(
        Envelope::from_bytes(&encode(&statement, &zero_tail)),
        Err(EnvelopeError::NonCanonical)
    );
    let mut over_budget = statement.clone();
    over_budget.cycles = over_budget.budget + 1;
    assert_eq!(
        Envelope::from_bytes(&encode(&over_budget, &certificate)),
        Err(EnvelopeError::NonCanonical)
    );
    // an overlong varint for the first program token's atom
    let bytes = encode(&statement, &certificate);
    let Envelope::Public { statement: s, .. } = Envelope::from_bytes(&bytes).unwrap() else {
        unreachable!()
    };
    assert_eq!(s, statement);
    let mut overlong = bytes[..HEADER_BYTES].to_vec();
    overlong.extend_from_slice(&[1, 0, 0x81, 0x00]); // one token: Atom(1) in two bytes
    assert_eq!(Envelope::from_bytes(&overlong), Err(EnvelopeError::NonCanonical));
}
