//! The Spartan IOP over Fp3 challenges on real compiled relations. The test
//! plays the PCS: it checks the final claim against the witness polynomial
//! evaluated directly at the Fp3 point.
use super::*;
use crate::execution::{ExecutionNoun as N, certify_execution};
use crate::multilinear::pad_to_power_of_two;
use crate::types::CCSWitness;
use nebu::Fp3;

fn pair(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}

/// `[7 [[5 [[0 2] [0 6]]] [0 2]]]`: (a + b) · a over subject [a [b 0]].
fn relation_and_witness() -> (CCSInstance, Vec<Goldilocks>) {
    let add = pair(N::Atom(5), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(6))));
    let program = pair(N::Atom(7), pair(add, pair(N::Atom(0), N::Atom(2))));
    let (statement, _) = certify_execution(&program, &[7, 5], 1000).unwrap();
    let relation = statement.relation().unwrap();
    let CCSWitness { z } = relation.witness(&statement.inputs()).unwrap();
    assert!(relation.instance.is_satisfied_by(&CCSWitness { z: z.clone() }));
    let mut z = z;
    pad_to_power_of_two(&mut z, 64);
    (relation.instance, z)
}

fn run<F: ChallengeField>(
    instance: &CCSInstance,
    z: &[Goldilocks],
) -> (IopProof<F>, Vec<F>, Result<Vec<F>, VerifyError>) {
    let mut pt = Transcript::new();
    pt.absorb(b"iop-test");
    let (proof, point) = prove::<F>(instance, z, &mut pt);
    let mut vt = Transcript::new();
    vt.absorb(b"iop-test");
    let zero = vec![Goldilocks::ZERO; instance.num_rows];
    let n = z.len().trailing_zeros() as usize;
    let verdict = verify::<F>(instance, &proof, &zero, n, &mut vt);
    (proof, point, verdict)
}

fn witness_poly_at<F: ChallengeField>(z: &[Goldilocks], point: &[F]) -> F {
    let lifted: Vec<F> = z.iter().map(|&v| F::from_base(v)).collect();
    evaluate_multilinear(&lifted, point)
}

#[test]
fn fp3_iop_accepts_an_honest_witness_and_ends_in_a_true_claim() {
    let (instance, z) = relation_and_witness();
    let (proof, point, verdict) = run::<Fp3>(&instance, &z);
    assert_eq!(verdict.unwrap(), point);
    assert_eq!(proof.eval_value, witness_poly_at(&z, &point));
    assert!(
        point.iter().any(|r| r.c1 != Goldilocks::ZERO || r.c2 != Goldilocks::ZERO),
        "challenges leave the base field"
    );
    let degree = instance.multisets.iter().map(Vec::len).max().unwrap();
    assert!(proof.outer_sumcheck_polys.iter().all(|p| p.coeffs.len() == degree + 2));
}

#[test]
fn goldilocks_iop_agrees_with_the_same_relation() {
    let (instance, z) = relation_and_witness();
    let (proof, point, verdict) = run::<Goldilocks>(&instance, &z);
    assert_eq!(verdict.unwrap(), point);
    assert_eq!(proof.eval_value, witness_poly_at(&z, &point));
}

#[test]
fn fp3_iop_rejects_an_unsatisfying_witness() {
    let (instance, mut z) = relation_and_witness();
    // the product wire of (a + b) · a: change any value the rows read
    let read = instance.matrices[0].entries.iter().flatten().map(|&(c, _)| c).max().unwrap();
    z[read] += Goldilocks::ONE;
    assert!(!instance.is_satisfied_by(&CCSWitness { z: z.clone() }));
    let (_, _, verdict) = run::<Fp3>(&instance, &z);
    assert!(verdict.is_err());
}

#[test]
fn fp3_iop_rejects_tampered_messages() {
    let (instance, z) = relation_and_witness();
    let mut pt = Transcript::new();
    let (proof, _) = prove::<Fp3>(&instance, &z, &mut pt);
    let n = z.len().trailing_zeros() as usize;
    let zero = vec![Goldilocks::ZERO; instance.num_rows];
    let check = |p: &IopProof<Fp3>| verify::<Fp3>(&instance, p, &zero, n, &mut Transcript::new());
    check(&proof).unwrap();
    let one = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);

    let mut bad = proof.clone();
    bad.eval_value = bad.eval_value + one;
    assert!(check(&bad).is_err(), "eval value");
    let mut bad = proof.clone();
    bad.matrix_evals[0] = bad.matrix_evals[0] + one;
    assert!(check(&bad).is_err(), "matrix evaluation");
    for round in 0..proof.sumcheck_polys.len() {
        let mut bad = proof.clone();
        bad.sumcheck_polys[round].coeffs[1] = bad.sumcheck_polys[round].coeffs[1] + one;
        assert!(check(&bad).is_err(), "inner round {round}");
    }
    for round in 0..proof.outer_sumcheck_polys.len() {
        let mut bad = proof.clone();
        bad.outer_sumcheck_polys[round].coeffs[2] =
            bad.outer_sumcheck_polys[round].coeffs[2] + one;
        assert!(check(&bad).is_err(), "outer round {round}");
    }
    let mut short = proof.clone();
    short.sumcheck_polys.pop();
    assert!(check(&short).is_err(), "round count is the caller's");
    // a different transcript prefix draws different challenges
    let mut other = Transcript::new();
    other.absorb(b"another statement");
    assert!(verify::<Fp3>(&instance, &proof, &zero, n, &mut other).is_err());
}
