//! veil-W: completeness, binding, tampering.
use super::*;
use crate::execution::ExecutionNoun as N;
use crate::execution::veil::tests::{pair, square_secret};

fn seeded(program: &N, input: &[u64], secret: &[u64], seed: u8) -> (PrivateStatement, SmallProof) {
    prove_with_coins(program, input, secret, 1 << 20, &Coins::seeded([seed; 32])).unwrap()
}

/// hash(x) for one secret x: `[15 [0 2]]` on `[x 0]`, wrapped as veil's.
fn hash_secret() -> N {
    let secret = pair(N::Atom(16), pair(pair(N::Atom(1), N::Atom(0)), pair(N::Atom(1), N::Atom(0))));
    let push = pair(N::Atom(3), pair(secret, pair(N::Atom(0), N::Atom(1))));
    let body = pair(N::Atom(15), pair(N::Atom(0), N::Atom(2)));
    pair(N::Atom(2), pair(push, pair(N::Atom(1), body)))
}

#[test]
fn secret_input_proofs_verify() {
    for (prog, x) in [(square_secret(), 12u64), (hash_secret(), 7)] {
        let (statement, proof) = seeded(&prog, &[], &[x], 1);
        verify(&statement, &proof).unwrap();
        let (statement2, proof2) = prove(&prog, &[], &[x], 1 << 20).unwrap();
        assert_eq!(statement, statement2);
        assert_ne!(proof, proof2, "OS coins differ");
        verify(&statement2, &proof2).unwrap();
    }
}

#[test]
fn seeded_proofs_reproduce() {
    let a = seeded(&square_secret(), &[], &[12], 3).1;
    let b = seeded(&square_secret(), &[], &[12], 3).1;
    assert_eq!(a, b);
}

#[test]
fn proofs_bind_the_statement() {
    let (statement, proof) = seeded(&square_secret(), &[], &[12], 4);
    let mut forged = statement.clone();
    forged.execution.public_output = vec![145];
    assert!(verify(&forged, &proof).is_err());
    let (other, _) = seeded(&square_secret(), &[], &[13], 4);
    assert!(verify(&other, &proof).is_err());
}

#[test]
fn every_byte_region_is_checked() {
    let (statement, proof) = seeded(&square_secret(), &[], &[12], 5);
    let bytes = proof.as_bytes();
    // one flip per 64 bytes across the whole proof, plus truncation and extension
    for i in (8..bytes.len()).step_by(64) {
        let mut b = bytes.to_vec();
        b[i] ^= 1;
        if let Ok(p) = SmallProof::from_bytes(&b) {
            assert!(verify(&statement, &p).is_err(), "byte {i}");
        }
    }
    let p = SmallProof::from_bytes(&bytes[..bytes.len() - 1]).unwrap();
    assert!(verify(&statement, &p).is_err());
    let mut b = bytes.to_vec();
    b.push(0);
    assert!(verify(&statement, &SmallProof::from_bytes(&b).unwrap()).is_err());
}

#[test]
fn layouts_meet_the_lemma_bound_and_keep_masks_off_the_wires() {
    for (prog, x) in [(square_secret(), 12u64), (hash_secret(), 7)] {
        let (_, prepared, _) = crate::execution::private::prepare_execution(&prog, &[], &[x], 1 << 20).unwrap();
        let public: Vec<_> = prepared.public_coordinates.iter().map(|&(i, v)| (i, Goldilocks::new(v))).collect();
        let s = Setup::new(&prepared.relation.instance, &with_constant(&public)).unwrap();
        let (params, slots) = choose(&s).unwrap();
        assert!(slots.per_coset() >= slots.q0 + 3 * (1 + slots.s0), "{slots:?}");
        assert!(slots.used <= slots.lib && slots.lib + slots.lib_len <= slots.block_start());
        assert!(slots.rho >= slots.k0 && slots.rho < slots.n);
        assert!(admit(&params, &s).unwrap() >= MIN_SECURITY_BITS);
    }
}
