//! Independent relation/backend regression probes added during the soft3 audit.
use nebu::Goldilocks as F;
use nox::call::{CallProvider, LookProvider};
use nox::trace::NoTrace;
use nox::{Order, Outcome, Reduction};
use std::sync::atomic::{AtomicUsize, Ordering};
use zheng::execution::relation::{ExecutionNoun, SubjectShape, compile_relation};
use zheng::execution::zk;
use zheng::types::{CCSInstance, CCSWitness, SparseMatrix};

fn a(v: u64) -> ExecutionNoun {
    ExecutionNoun::Atom(v)
}
fn p(x: ExecutionNoun, y: ExecutionNoun) -> ExecutionNoun {
    ExecutionNoun::Pair(Box::new(x), Box::new(y))
}
fn q(v: u64) -> ExecutionNoun {
    p(a(1), a(v))
}
fn axis() -> ExecutionNoun {
    p(a(0), a(1))
}
fn op(tag: u64, x: ExecutionNoun, y: ExecutionNoun) -> ExecutionNoun {
    p(a(tag), p(x, y))
}

struct Calls {
    value: F,
    count: AtomicUsize,
}
impl LookProvider for Calls {
    fn look(&self, _: F, _: F, _: F) -> Option<F> {
        None
    }
}
impl<const N: usize> CallProvider<N> for Calls {
    fn provide(&self, arena: &mut Reduction<N>, _: F, _: Order) -> Option<Order> {
        self.count.fetch_add(1, Ordering::Relaxed);
        arena.atom(self.value)
    }
}
fn put<const N: usize>(arena: &mut Reduction<N>, noun: &ExecutionNoun) -> Order {
    match noun {
        ExecutionNoun::Atom(value) => arena.atom(F::new(*value)).unwrap(),
        ExecutionNoun::Pair(left, right) => {
            let left = put(arena, left);
            let right = put(arena, right);
            arena.pair(left, right).unwrap()
        }
    }
}

fn generated(seed: &mut u64, depth: usize) -> ExecutionNoun {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    let choice = (*seed >> 32) as usize;
    if depth == 0 {
        return match choice % 4 {
            0 => axis(),
            1 => op(16, q(0), q(0)),
            2 => q(0),
            _ => q((choice % 37) as u64),
        };
    }
    let left = generated(seed, depth - 1);
    let right = generated(seed, depth - 1);
    match choice % 13 {
        0..=8 => op([5, 6, 7, 9, 10, 11, 12, 14, 5][choice % 13], left, right),
        9 => p(a(8), left),
        10 => p(a(13), left),
        11 => p(a(4), p(left, p(right, q(0)))),
        _ => op(2, left, p(a(1), right)),
    }
}

#[test]
fn generated_private_relations_match_native_success_failure_output_and_cost() {
    let mut seed = 0x4a6f_792d_6175_6469;
    for case in 0..64 {
        let program = generated(&mut seed, 3);
        let relation = compile_relation(&program, &SubjectShape::Atom).unwrap();
        for input in [0, 1, 7, u32::MAX as u64, 1 << 32, nebu::field::P - 1] {
            for secret in [0, 11, nebu::field::P - 1] {
                let mut arena = Reduction::<8192>::new();
                let object = arena.atom(F::new(input)).unwrap();
                let formula = put(&mut arena, &program);
                let calls = Calls {
                    value: F::new(secret),
                    count: AtomicUsize::new(0),
                };
                let outcome =
                    nox::reduce(&mut arena, object, formula, 100_000, &calls, &mut NoTrace);
                let witness = relation.witness_with_secrets(
                    &[F::new(input)],
                    &vec![F::new(secret); calls.count.load(Ordering::Relaxed)],
                );
                let valid = witness
                    .as_ref()
                    .is_ok_and(|w| relation.instance.is_satisfied_by(w));
                match outcome {
                    Outcome::Ok(output, remaining) => {
                        assert!(
                            valid,
                            "case {case}, input {input}, secret {secret}, {program:?}"
                        );
                        let witness = witness.unwrap();
                        assert_eq!(
                            arena.atom_value(output).unwrap(),
                            witness.z[relation.output_indices[0]],
                            "case {case}"
                        );
                        assert_eq!(
                            100_000 - remaining,
                            witness.z[relation.cost_index].as_u64(),
                            "case {case}"
                        );
                    }
                    _ => assert!(
                        !valid,
                        "accepted native failure in case {case}: {program:?}"
                    ),
                }
            }
        }
    }
}

#[test]
fn native_private_ccs_handles_constants_sparse_cancellation_and_degree_sixteen() {
    for degree in [0, 1, 2, 3, 16] {
        let mut matrix = SparseMatrix::new(2, 3);
        matrix.set(0, 1, F::ONE);
        // Repeated sparse coordinates add, including exact cancellation.
        matrix.set(0, 1, F::new(13));
        matrix.set(0, 1, -F::new(13));
        matrix.set(1, 1, F::ZERO);
        let mut constant = SparseMatrix::new(2, 3);
        constant.set(0, 0, F::ONE);
        if degree == 0 {
            constant.set(1, 0, F::ONE);
        }
        let instance = CCSInstance {
            num_rows: 2,
            num_cols: 3,
            matrices: vec![matrix, constant],
            multisets: vec![vec![0; degree], vec![1]],
            coeffs: vec![F::ONE, -F::new(7).exp(degree as u64)],
        };
        let witness = CCSWitness {
            z: vec![F::ONE, F::new(7), F::new(99)],
        };
        assert!(instance.is_satisfied_by(&witness));
        let proof = zk::prove(&instance, &witness, b"independent general CCS", &[]).unwrap();
        zk::verify(&instance, &proof, b"independent general CCS", &[]).unwrap();
        let mut changed = instance.clone();
        changed.coeffs[1] += F::ONE;
        assert!(zk::verify(&changed, &proof, b"independent general CCS", &[]).is_err());
        if degree > 0 {
            let bad = CCSWitness {
                z: vec![F::ONE, F::new(8), F::new(99)],
            };
            assert!(zk::prove(&instance, &bad, b"independent general CCS", &[]).is_err());
        }
    }
}

#[test]
fn private_verifier_rejects_dimension_bombs_and_excessive_sparse_expansion() {
    let mut matrix = SparseMatrix::new(1, 2);
    matrix.set(0, 0, F::ONE);
    let mut instance = CCSInstance {
        num_rows: 1,
        num_cols: 2,
        matrices: vec![matrix],
        multisets: vec![vec![0], vec![0]],
        coeffs: vec![F::ONE, -F::ONE],
    };
    let witness = CCSWitness {
        z: vec![F::ONE, F::ZERO],
    };
    let proof = zk::prove(&instance, &witness, b"limits", &[]).unwrap();
    instance.num_cols = usize::MAX;
    assert!(zk::verify(&instance, &proof, b"limits", &[]).is_err());
    instance.num_cols = 2;
    instance.matrices[0].entries[0] = vec![(0, F::ONE); 65_537];
    instance.multisets = vec![vec![0; 16], vec![0; 16]];
    assert!(zk::verify(&instance, &proof, b"limits", &[]).is_err());
}

#[test]
#[ignore = "diagnostic timing experiment; timing is not a portable test assertion"]
fn measure_equal_statement_witness_timing() {
    // Equality is discarded by a static continuation. Both secrets produce
    // the identical public result and declared nox cost. This probe exposed
    // the former zero-inversion shortcut; keep timing as diagnostic evidence.
    let program = op(2, op(9, op(16, q(0), q(0)), q(0)), p(a(1), q(0)));
    let relation = compile_relation(&program, &SubjectShape::Atom).unwrap();
    let mut observed = Vec::new();
    for (sample, secret) in [0, 11, 11, 0, 0, 11].into_iter().enumerate() {
        let witness = relation
            .witness_with_secrets(&[F::ZERO], &[F::new(secret)])
            .unwrap();
        assert!(relation.instance.is_satisfied_by(&witness));
        observed.push((
            witness.z[relation.output_indices[0]],
            witness.z[relation.cost_index],
        ));
        let start = std::time::Instant::now();
        for _ in 0..100_000 {
            std::hint::black_box(
                relation
                    .witness_with_secrets(
                        std::hint::black_box(&[F::ZERO]),
                        std::hint::black_box(&[F::new(secret)]),
                    )
                    .unwrap(),
            );
        }
        eprintln!(
            "witness timing sample={sample}, secret={secret}, repetitions=100000, ns={}",
            start.elapsed().as_nanos()
        );
    }
    assert!(observed.windows(2).all(|pair| pair[0] == pair[1]));
}
