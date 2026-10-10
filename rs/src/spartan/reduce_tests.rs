//! `reduce` accepts exactly what `iop::verify` accepts, from compressed
//! rounds, on a real compiled relation over Fp3.
use super::*;
use crate::execution::{ExecutionNoun as N, certify_execution};
use crate::multilinear::pad_to_power_of_two;
use crate::spartan::iop::{prove, verify};
use crate::types::CCSWitness;
use nebu::{Fp3, Goldilocks};

fn pair(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}

fn relation_and_witness() -> (CCSInstance, Vec<Goldilocks>) {
    let add = pair(N::Atom(5), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(6))));
    let program = pair(N::Atom(7), pair(add, pair(N::Atom(0), N::Atom(2))));
    let (statement, _) = certify_execution(&program, &[7, 5], 1000).unwrap();
    let relation = statement.relation().unwrap();
    let CCSWitness { mut z } = relation.witness(&statement.inputs()).unwrap();
    pad_to_power_of_two(&mut z, 64);
    (relation.instance, z)
}

fn check(
    instance: &CCSInstance,
    proof: &IopProof<Fp3>,
    outer: &CompressedRounds<Fp3>,
    inner: &CompressedRounds<Fp3>,
    n: usize,
) -> bool {
    let mut t = Transcript::new();
    match reduce(instance, &proof.matrix_evals, outer, inner, n, &mut t) {
        Ok(r) => r.claim == r.weight(instance) * proof.eval_value,
        Err(_) => false,
    }
}

#[test]
fn compressed_reduction_agrees_with_the_full_verifier() {
    let (instance, z) = relation_and_witness();
    let n = z.len().trailing_zeros() as usize;
    let (proof, point) = prove::<Fp3>(&instance, &z, &mut Transcript::new());
    let full = verify::<Fp3>(&instance, &proof, &[], n, &mut Transcript::new()).unwrap();
    let (outer, inner) = compress_proof(&proof);
    let r = reduce(&instance, &proof.matrix_evals, &outer, &inner, n, &mut Transcript::new())
        .unwrap();
    assert_eq!(r.point, full);
    assert_eq!(r.point, point);
    assert_eq!(r.claim, r.weight(&instance) * proof.eval_value);
    // every round lost exactly one coefficient
    for (c, p) in outer.rounds.iter().zip(&proof.outer_sumcheck_polys) {
        assert_eq!(c.len() + 1, p.coeffs.len());
    }
    for (c, p) in inner.rounds.iter().zip(&proof.sumcheck_polys) {
        assert_eq!(c.len() + 1, p.coeffs.len());
    }
}

#[test]
fn every_compressed_coefficient_is_bound() {
    let (instance, z) = relation_and_witness();
    let n = z.len().trailing_zeros() as usize;
    let (proof, _) = prove::<Fp3>(&instance, &z, &mut Transcript::new());
    let (outer, inner) = compress_proof(&proof);
    assert!(check(&instance, &proof, &outer, &inner, n));
    let one = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
    for r in 0..outer.rounds.len() {
        for c in 0..outer.rounds[r].len() {
            let mut bad = outer.clone();
            bad.rounds[r][c] += one;
            assert!(!check(&instance, &proof, &bad, &inner, n), "outer {r}.{c}");
        }
    }
    for r in 0..inner.rounds.len() {
        for c in 0..inner.rounds[r].len() {
            let mut bad = inner.clone();
            bad.rounds[r][c] += one;
            assert!(!check(&instance, &proof, &outer, &bad, n), "inner {r}.{c}");
        }
    }
    for i in 0..proof.matrix_evals.len() {
        let mut bad = proof.clone();
        bad.matrix_evals[i] += one;
        assert!(!check(&instance, &bad, &outer, &inner, n), "matrix {i}");
    }
    let mut bad = proof.clone();
    bad.eval_value += one;
    assert!(!check(&instance, &bad, &outer, &inner, n), "witness claim");
    // wrong shapes: a missing round, a short or long round
    let mut short = inner.clone();
    short.rounds.pop();
    assert!(!check(&instance, &proof, &outer, &short, n));
    let mut long = outer.clone();
    long.rounds[0].push(Fp3::ZERO);
    assert!(!check(&instance, &proof, &long, &inner, n));
    assert!(!check(&instance, &proof, &outer, &inner, n + 1), "one round short");
}

#[test]
fn decompress_restores_the_linear_coefficient() {
    let g = |v| Fp3::from_base(Goldilocks::new(v));
    // g(X) = 3 + 5X + 7X² + 11X³: g(0) + g(1) = 3 + 26 = 29
    let p = decompress(g(29), 3, &[g(3), g(7), g(11)]).unwrap();
    assert_eq!(p.coeffs, vec![g(3), g(5), g(7), g(11)]);
    assert!(decompress(g(29), 3, &[g(3), g(7)]).is_none());
    assert!(decompress::<Fp3>(g(29), 0, &[]).is_none());
}
