//! Independent checks of the direct verifier's hostile-artifact boundary.
use lens::Opening;
use nebu::Goldilocks as F;
use zheng::{
    execution::proof,
    types::{CCSInstance, CCSWitness, SparseMatrix},
};

fn relation(width: usize) -> CCSInstance {
    // z[1] * z[2] = z[3], with a nontrivial second row z[4] = 7*z[0].
    let mut matrices = vec![SparseMatrix::new(2, width); 3];
    matrices[0].set(0, 1, F::ONE);
    matrices[1].set(0, 2, F::ONE);
    matrices[2].set(0, 3, F::ONE);
    matrices[0].set(1, 4, F::ONE);
    matrices[1].set(1, 0, F::ONE);
    matrices[2].set(1, 0, F::new(7));
    CCSInstance {
        matrices,
        multisets: vec![vec![0, 1], vec![2]],
        coeffs: vec![F::ONE, -F::ONE],
        num_rows: 2,
        num_cols: width,
    }
}

fn witness(width: usize, input: u64) -> CCSWitness {
    let mut z = vec![F::ZERO; width];
    z[..5].copy_from_slice(&[
        F::ONE,
        F::new(input),
        F::new(3),
        F::new(input * 3),
        F::new(7),
    ]);
    CCSWitness { z }
}

const STATEMENT: &[u8] = b"independent-execution-adversarial-test-v1";

#[test]
fn odd_and_even_witness_dimensions_authenticate_public_values() {
    for width in [64, 128] {
        let instance = relation(width);
        let public = [(1, F::new(5)), (3, F::new(15))];
        let p = proof::prove(&instance, &witness(width, 5), STATEMENT, &public).unwrap();
        proof::verify(&instance, &p, STATEMENT, &public).unwrap();
        for bad in [
            [(1, F::new(6)), (3, F::new(15))],
            [(1, F::new(5)), (3, F::new(16))],
        ] {
            assert!(proof::verify(&instance, &p, STATEMENT, &bad).is_err());
        }
        assert!(proof::verify(&instance, &p, b"different-program", &public).is_err());
    }
}

#[test]
fn reproving_a_different_valid_execution_cannot_substitute_its_input_or_output() {
    let instance = relation(64);
    let expected = [(1, F::new(5)), (3, F::new(15))];
    let other = [(1, F::new(6)), (3, F::new(18))];
    // A new honest proof with newly generated sumchecks, not a byte mutation.
    let other_proof = proof::prove(&instance, &witness(64, 6), STATEMENT, &other).unwrap();
    proof::verify(&instance, &other_proof, STATEMENT, &other).unwrap();
    assert!(proof::verify(&instance, &other_proof, STATEMENT, &expected).is_err());
    let mut different_relation = instance.clone();
    different_relation.matrices[2].entries[1][0].1 = F::new(8);
    assert!(proof::verify(&different_relation, &other_proof, STATEMENT, &other).is_err());
}

#[test]
fn untrusted_dimensions_and_round_degree_metadata_fail_closed() {
    let instance = relation(64);
    let public = [(1, F::new(5)), (3, F::new(15))];
    let p = proof::prove(&instance, &witness(64, 5), STATEMENT, &public).unwrap();
    let mut malformed = vec![];
    let mut v = p.clone();
    v.spartan.sumcheck_polys.pop();
    malformed.push(v);
    let mut v = p.clone();
    v.spartan.sumcheck_polys[0].degree = 255;
    malformed.push(v);
    let mut v = p.clone();
    v.spartan.sumcheck_polys[0].coeffs.push(F::ZERO);
    malformed.push(v);
    let mut v = p.clone();
    v.spartan.outer_sumcheck_polys[0].coeffs.clear();
    malformed.push(v);
    let mut v = p.clone();
    v.spartan.matrix_evals.pop();
    malformed.push(v);
    for v in malformed {
        assert!(proof::verify(&instance, &v, STATEMENT, &public).is_err());
    }
    for width in [0, 32, 63, 128, usize::MAX] {
        let mut invalid = instance.clone();
        invalid.num_cols = width;
        assert!(proof::verify(&invalid, &p, STATEMENT, &public).is_err());
    }
    for rows in [0, 1, 3, usize::MAX] {
        let mut invalid = instance.clone();
        invalid.num_rows = rows;
        assert!(proof::verify(&invalid, &p, STATEMENT, &public).is_err());
    }
    let mut invalid = instance.clone();
    invalid.matrices[0].entries[0][0].0 = 64;
    assert!(proof::verify(&invalid, &p, STATEMENT, &public).is_err());
}

#[test]
fn noncanonical_openings_and_spliced_columns_are_rejected() {
    let instance = relation(64);
    let public = [(1, F::new(5)), (3, F::new(15))];
    let p = proof::prove(&instance, &witness(64, 5), STATEMENT, &public).unwrap();
    let mut mutations = vec![];
    for attack in 0..3 {
        let mut v = p.clone();
        if let Opening::TensorMerkle { columns, .. } = &mut v.spartan.pcs_opening {
            match attack {
                0 => columns.swap(0, 1),
                1 => columns[1] = columns[0].clone(),
                2 => {
                    columns.pop();
                }
                _ => unreachable!(),
            }
        } else {
            panic!("unexpected opening");
        }
        mutations.push(v);
    }
    let mut v = p.clone();
    if let Opening::TensorMerkle {
        row_combination, ..
    } = &mut v.spartan.pcs_opening
    {
        row_combination.extend_from_slice(&[0]);
    } else {
        panic!("unexpected opening");
    }
    mutations.push(v);
    let mut v = p.clone();
    if let Opening::TensorMerkle {
        row_combination, ..
    } = &mut v.spartan.pcs_opening
    {
        row_combination[..8].copy_from_slice(&nebu::field::P.to_le_bytes());
    } else {
        panic!("unexpected opening");
    }
    mutations.push(v);
    let mut v = p.clone();
    if let Opening::TensorMerkle { columns, .. } = &mut v.spartan.pcs_opening {
        columns[0].index = usize::MAX;
    } else {
        panic!("unexpected opening");
    }
    mutations.push(v);
    for v in mutations {
        assert!(proof::verify(&instance, &v, STATEMENT, &public).is_err());
    }
    for invalid in [
        vec![(0, F::ONE)],
        vec![(1, F::new(5)), (1, F::new(5))],
        vec![(3, F::new(15)), (1, F::new(5))],
        vec![(64, F::ONE)],
    ] {
        assert!(proof::verify(&instance, &p, STATEMENT, &invalid).is_err());
    }
}

#[test]
fn execution_statement_authenticates_program_input_output_and_cost() {
    use zheng::execution::{
        ExecutionNoun as N, ExecutionStatement, prove_execution, verify_execution,
    };
    let pair = |a, b| N::Pair(Box::new(a), Box::new(b));
    // (axis(subject, 2) * quote(3)): reads the latest public input.
    let program = pair(
        N::Atom(7),
        pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(1), N::Atom(3))),
    );
    let (s, p) = prove_execution(&program, &[5], 100).unwrap();
    assert_eq!(s.public_output, vec![15]);
    assert_eq!(s.cycles, 3);
    verify_execution(&s, &p).unwrap();
    let mut mutations = vec![];
    let mut t = s.clone();
    t.public_input[0] = 6;
    mutations.push(t);
    let mut t = s.clone();
    t.public_output[0] = 16;
    mutations.push(t);
    let mut t = s.clone();
    t.cycles = 2;
    mutations.push(t);
    let mut t = s.clone();
    t.budget = 101;
    mutations.push(t);
    let mut t = s.clone();
    t.public_input[0] = nebu::field::P;
    mutations.push(t);
    let mut t = s.clone();
    t.public_output.push(0);
    mutations.push(t);
    let mut t = s.clone();
    t.program = ExecutionStatement::encode_program(&pair(N::Atom(1), N::Atom(15))).unwrap();
    mutations.push(t);
    for t in mutations {
        assert!(verify_execution(&t, &p).is_err());
    }
    // Re-prove another real execution and try presenting it as this statement.
    let (other, other_proof) = prove_execution(&program, &[6], 100).unwrap();
    assert_eq!(other.public_output, vec![18]);
    verify_execution(&other, &other_proof).unwrap();
    assert!(verify_execution(&s, &other_proof).is_err());
}
