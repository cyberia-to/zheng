//! zk profile: completeness with secret inputs, rejection of forged
//! statements, tampered proofs, foreign keys and weak parameters.
use super::*;
use crate::execution::ExecutionNoun as N;
use crate::execution::certify_execution;

pub(super) fn pair(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}
/// `[16 [[1 0] [1 0]]]`: one secret, no check.
fn secret() -> N {
    pair(N::Atom(16), pair(pair(N::Atom(1), N::Atom(0)), pair(N::Atom(1), N::Atom(0))))
}
/// `[2 [[3 [secret [0 1]]] [1 body]]]`: run `body` on `[x subject]`.
fn with_secret(body: N) -> N {
    let push = pair(N::Atom(3), pair(secret(), pair(N::Atom(0), N::Atom(1))));
    pair(N::Atom(2), pair(push, pair(N::Atom(1), body)))
}
/// x · x for one secret x.
pub(super) fn square_secret() -> N {
    with_secret(pair(N::Atom(7), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(2)))))
}
/// x · a + b for a secret x and public a, b (subject `[x [a [b 0]]]`).
fn affine_secret() -> N {
    let mul = pair(N::Atom(7), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(6))));
    with_secret(pair(N::Atom(5), pair(mul, pair(N::Atom(0), N::Atom(14)))))
}

fn seeded(program: &N, input: &[u64], secret: &[u64], seed: u8) -> (PrivateStatement, VeilProof) {
    let (statement, prepared, witness) =
        crate::execution::private::prepare_execution(program, input, secret, 1000).unwrap();
    let vk = VerifyingKey::new(statement.execution.program_key(), prepared.relation);
    let public: Vec<_> =
        prepared.public_coordinates.iter().map(|&(i, v)| (i, Goldilocks::new(v))).collect();
    let w = CCSWitness {
        z: witness.into_iter().map(Goldilocks::new).collect(),
    };
    let bytes = crate::execution::succinct::keyed_statement(&vk, &statement.transcript_bytes());
    let proof = prove_relation_with(
        &HidingParams::default(),
        &vk.relation().instance,
        &w,
        &bytes,
        &public,
        &mut Coins::seeded([seed; 32]),
    )
    .unwrap();
    (statement, proof)
}

#[test]
fn secret_input_proofs_verify() {
    let (statement, proof) = prove(&square_secret(), &[], &[12], 1000).unwrap();
    assert_eq!(statement.execution.public_output, vec![144]);
    verify(&statement, &proof).unwrap();
    let (statement, proof) = prove(&affine_secret(), &[3, 4], &[5], 1000).unwrap();
    // subject [x [4 [3 0]]]: the inputs sit reversed, so x·4 + 3
    assert_eq!(statement.execution.public_output, vec![23]);
    verify(&statement, &proof).unwrap();
    // the statement holds only public values: the same for x and −x
    let (minus, _) = prove(&square_secret(), &[], &[nebu::field::P - 12], 1000).unwrap();
    assert_eq!(minus, statement_of(&square_secret(), 12));
}

fn statement_of(program: &N, x: u64) -> PrivateStatement {
    crate::execution::private::prepare_execution(program, &[], &[x], 1000).unwrap().0
}

#[test]
fn proofs_are_randomized_and_seeded_proofs_reproduce() {
    let (s, a) = seeded(&square_secret(), &[], &[12], 1);
    let (_, b) = seeded(&square_secret(), &[], &[12], 1);
    let (_, c) = seeded(&square_secret(), &[], &[12], 2);
    assert_eq!(a, b);
    assert_ne!(a, c);
    verify(&s, &a).unwrap();
    verify(&s, &c).unwrap();
    let (_, fresh) = prove(&square_secret(), &[], &[12], 1000).unwrap();
    assert_ne!(fresh, a, "OS coins");
}

#[test]
fn forged_statements_are_rejected() {
    let (s, proof) = prove(&affine_secret(), &[3, 4], &[5], 1000).unwrap();
    let forge = |edit: &dyn Fn(&mut PrivateStatement)| {
        let mut bad = s.clone();
        edit(&mut bad);
        verify(&bad, &proof).is_err()
    };
    assert!(forge(&|b| b.execution.public_output[0] = 20), "output");
    assert!(forge(&|b| b.execution.public_input[0] = 4), "input");
    assert!(forge(&|b| b.execution.cycles += 1), "cycles");
    assert!(forge(&|b| b.execution.budget = b.execution.cycles - 1), "budget below cost");
    assert!(forge(&|b| b.execution.public_input.push(0)), "shape");
    // a proof for another statement of the same program
    let (other, other_proof) = prove(&affine_secret(), &[3, 4], &[6], 1000).unwrap();
    assert!(verify(&s, &other_proof).is_err());
    assert!(verify(&other, &proof).is_err());
    // the same execution proven under another program
    let (sq, sq_proof) = prove(&square_secret(), &[], &[12], 1000).unwrap();
    assert!(verify(&sq, &proof).is_err());
    assert!(verify(&s, &sq_proof).is_err());
}

#[test]
fn keys_must_be_derived_for_the_statement() {
    let (s, proof) = prove(&affine_secret(), &[3, 4], &[5], 1000).unwrap();
    let vk = VerifyingKey::for_execution(&s.execution).unwrap();
    verify_with(&s, &proof, Some(&vk)).unwrap();
    let (sq, _) = certify_execution(&pair(N::Atom(1), N::Atom(7)), &[3, 4], 1000).unwrap();
    let foreign = VerifyingKey::for_execution(&sq).unwrap();
    assert!(verify_with(&s, &proof, Some(&foreign)).is_err());
    let forged = VerifyingKey::new(vk.program_key(), foreign.relation().clone());
    assert!(verify_with(&s, &proof, Some(&forged)).is_err());
}

#[test]
fn tampered_proofs_and_weak_parameters_are_rejected() {
    let (s, proof) = seeded(&affine_secret(), &[3, 4], &[5], 7);
    let bytes = proof.as_bytes();
    // a byte in every region: magic, root, masks, rounds, evals, opening
    let positions = [0, 9, 45, 70, 200, 400, 600, bytes.len() / 2, bytes.len() - 40, bytes.len() - 1];
    for &i in &positions {
        let mut bad = bytes.to_vec();
        bad[i] ^= 1;
        let rejected = VeilProof::from_bytes(&bad).map_or(true, |p| verify(&s, &p).is_err());
        assert!(rejected, "byte {i}");
    }
    assert!(VeilProof::from_bytes(&bytes[..bytes.len() - 1]).map_or(true, |p| verify(&s, &p).is_err()));
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(verify(&s, &VeilProof::from_bytes(&longer).unwrap()).is_err());
    // a header naming weaker parameters: below policy, or out of range
    for (offset, value) in [(2, 0u8), (1, 1), (3, 64)] {
        let header = bytes.len() - proof_tail(&s, &proof);
        let mut bad = bytes.to_vec();
        bad[header + offset] = value;
        assert!(verify(&s, &VeilProof::from_bytes(&bad).unwrap()).is_err(), "header {offset}");
    }
}

#[test]
fn every_admissible_parameter_set_carries_128_proven_bits() {
    // queries follow from the target and grinding, so no in-range header
    // can name a weaker opening; out-of-range headers do not derive
    for r in 3..=8u8 {
        for pow in [0u8, 8, 16, 24, 30] {
            for lg in [4usize, 10, 16, 20] {
                let p = HidingParams { log_inv_rate: r, pow_bits: pow, security_target: 128 };
                let bits = protocol::admit(&p, 1 << lg).unwrap();
                assert!(bits >= 128.0, "r {r} pow {pow} 2^{lg}: {bits}");
            }
        }
    }
    for bad in [
        HidingParams { security_target: 100, ..HidingParams::default() },
        HidingParams { log_inv_rate: 2, ..HidingParams::default() },
        HidingParams { pow_bits: 40, ..HidingParams::default() },
    ] {
        assert!(protocol::admit(&bad, 1 << 10).is_err());
    }
}

/// Bytes from the hiding header to the end.
fn proof_tail(s: &PrivateStatement, proof: &VeilProof) -> usize {
    let prepared = s.prepare().unwrap();
    let public: Vec<_> =
        prepared.public_coordinates.iter().map(|&(i, v)| (i, Goldilocks::new(v))).collect();
    let setup = protocol::Setup::new(&prepared.relation.instance, &with_constant(&public)).unwrap();
    let parsed = wire::Parsed::from_bytes(proof.as_bytes(), setup.shape()).unwrap();
    let mut tail = Vec::new();
    parsed.opening.write(&mut tail);
    tail.len()
}

#[test]
fn unsatisfying_witnesses_are_refused_by_the_prover() {
    let (statement, prepared, witness) =
        crate::execution::private::prepare_execution(&square_secret(), &[], &[12], 1000).unwrap();
    let mut z: Vec<Goldilocks> = witness.into_iter().map(Goldilocks::new).collect();
    let i = prepared.relation.output_indices[0];
    z[i] += Goldilocks::ONE;
    let public: Vec<_> =
        prepared.public_coordinates.iter().map(|&(i, v)| (i, Goldilocks::new(v))).collect();
    assert!(
        prove_relation(&prepared.relation.instance, &CCSWitness { z }, &statement.transcript_bytes(), &public)
            .is_err()
    );
}
