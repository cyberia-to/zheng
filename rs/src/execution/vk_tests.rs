//! Keys are derived, never trusted: a key for another program, another
//! subject shape or another relation is rejected.
use super::*;
use crate::execution::succinct::{self, Whir, WhirParams};
use crate::execution::{ExecutionNoun as N, certify_execution, verify_certificate_with};

fn pair(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}
/// (a + b) · a over subject [a [b 0]].
fn add_mul() -> N {
    let add = pair(N::Atom(5), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(6))));
    pair(N::Atom(7), pair(add, pair(N::Atom(0), N::Atom(2))))
}
/// a · a over subject [a [b 0]].
fn square() -> N {
    pair(N::Atom(7), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(2))))
}

#[test]
fn a_derived_key_verifies_and_a_foreign_key_is_rejected() {
    let (statement, certificate) = certify_execution(&add_mul(), &[7, 5], 1000).unwrap();
    let vk = VerifyingKey::for_execution(&statement).unwrap();
    assert_eq!(vk.program_key(), statement.program_key());
    verify_certificate_with(&statement, &certificate, &vk).unwrap();
    // the same key serves every statement of the program and shape
    let (other_io, other_cert) = certify_execution(&add_mul(), &[3, 4], 1000).unwrap();
    verify_certificate_with(&other_io, &other_cert, &vk).unwrap();
    // a key for another program
    let (sq, _) = certify_execution(&square(), &[7, 5], 1000).unwrap();
    let foreign = VerifyingKey::for_execution(&sq).unwrap();
    assert_ne!(foreign.program_key(), vk.program_key());
    assert!(verify_certificate_with(&statement, &certificate, &foreign).is_err());
    // a key for the same program under another subject shape (one more input)
    let (wide, _) = certify_execution(&add_mul(), &[7, 5, 1], 1000).unwrap();
    let shape = VerifyingKey::for_execution(&wide).unwrap();
    assert_ne!(shape.program_key(), vk.program_key());
    assert!(verify_certificate_with(&statement, &certificate, &shape).is_err());
}

#[test]
fn the_digest_binds_succinct_proofs_to_their_relation() {
    let (statement, proof) =
        succinct::prove::<Whir>(&WhirParams::default(), &add_mul(), &[7, 5], 1000).unwrap();
    let vk = VerifyingKey::for_execution(&statement).unwrap();
    succinct::verify_with(&statement, &proof, Some(&vk)).unwrap();
    succinct::verify_with(&statement, &proof, None).unwrap();
    // a key for another program is rejected before anything is checked
    let (sq, _) = certify_execution(&square(), &[7, 5], 1000).unwrap();
    let foreign = VerifyingKey::for_execution(&sq).unwrap();
    assert!(succinct::verify_with(&statement, &proof, Some(&foreign)).is_err());
    // a key that names this program but carries another relation: its
    // digest differs, the transcript diverges, the proof fails
    let forged = VerifyingKey::new(vk.program_key(), foreign.relation().clone());
    assert_ne!(forged.digest(), vk.digest());
    assert!(succinct::verify_with(&statement, &proof, Some(&forged)).is_err());
    // a key whose digest alone was altered
    let mut altered = vk.clone();
    altered.digest[0] ^= 1;
    assert!(succinct::verify_with(&statement, &proof, Some(&altered)).is_err());
}

#[test]
fn digests_are_deterministic_and_separate_kinds() {
    let (statement, _) = certify_execution(&add_mul(), &[7, 5], 1000).unwrap();
    let a = VerifyingKey::for_execution(&statement).unwrap();
    let b = VerifyingKey::for_execution(&statement).unwrap();
    assert_eq!(a.digest(), b.digest());
    let state = program_key(&statement.program, 2, StatementKind::State { root_in_subject: false });
    assert_ne!(state, a.program_key());
}
