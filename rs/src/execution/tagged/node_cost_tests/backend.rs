use super::*;
use crate::execution::proof;
use std::time::Instant;

#[test]
fn fixed_schema_is_identical_across_builds() {
    let a = build(MAX_GATES).unwrap();
    let b = build(MAX_GATES).unwrap();
    for (a, b) in a
        .parts
        .instance
        .matrices
        .iter()
        .zip(&b.parts.instance.matrices)
    {
        assert_eq!(a.entries, b.entries);
    }
    let mut ar = Reduction::<1024>::new();
    let q = quote(&mut ar, 5);
    let other = atom(&mut ar, nebu::field::P - 1);
    let dynamic = binary(&mut ar, 2, q, q);
    let branch = branch(&mut ar, q, other, dynamic);
    for root in [q, other, dynamic, branch] {
        valid(&a, &inputs(&ar, root));
        valid(&b, &inputs(&ar, root));
    }
    // Actual legacy execution matrices retain the default cap/layout.
    let program = Noun::Pair(Box::new(Noun::Atom(1)), Box::new(Noun::Atom(42)));
    let legacy = compile(&program, &SubjectShape::Atom).unwrap();
    let mut builder = Builder::with_gate_limit(1, MAX_GATES).unwrap();
    let subject = builder.subject(&SubjectShape::Atom, &mut 2).unwrap();
    let (out, cost, max) = builder.eval(&subject, &program, ONE, 0).unwrap();
    let limited = builder.finish(out, cost, max).unwrap();
    for (a, b) in legacy
        .instance
        .matrices
        .iter()
        .zip(&limited.instance.matrices)
    {
        assert_eq!(a.entries, b.entries);
    }
}

#[test]
fn existing_backend_binds_component_premises_and_rejects_forged_witnesses() {
    let build_start = Instant::now();
    let c = build(MAX_GATES).unwrap();
    let build_ns = build_start.elapsed().as_nanos();
    let mut ar = Reduction::<1024>::new();
    let q = quote(&mut ar, 42);
    let dynamic = binary(&mut ar, 2, q, q);
    let root = branch(&mut ar, q, dynamic, q);
    let supplied = inputs(&ar, root);
    let witness_start = Instant::now();
    let w = valid(&c, &supplied);
    let witness_ns = witness_start.elapsed().as_nanos();
    let public = pins(&supplied);
    let statement = b"zheng-local-noun-cost-v1-explicit-public-read-premises";
    let started = Instant::now();
    let proof = proof::prove(&c.parts.instance, &w, statement, &public).unwrap();
    let proof_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    proof::verify(&c.parts.instance, &proof, statement, &public).unwrap();
    let verify_ns = started.elapsed().as_nanos();
    println!(
        "node-cost timing build_ns={build_ns} witness_ns={witness_ns} prove_ns={proof_ns} verify_ns={verify_ns}"
    );
    #[cfg(feature = "serde")]
    println!(
        "node-cost full-witness postcard_proof_bytes={}",
        postcard::to_allocvec(&proof).unwrap().len()
    );

    assert!(proof::verify(&c.parts.instance, &proof, b"wrong-schema", &public).is_err());
    for index in [
        0,
        1,
        4,
        5,
        6,
        7,
        17,
        18,
        1 + 3 * RECORD_FIELDS,
        2 + 2 * RECORD_FIELDS + 16,
    ] {
        let mut wrong = public.clone();
        wrong[index].1 += F::ONE;
        assert!(proof::verify(&c.parts.instance, &proof, statement, &wrong).is_err());
    }
    for bad in [
        vec![(0, F::ONE)],
        vec![(1, F::ZERO), (1, F::ONE)],
        vec![(2, F::ONE), (1, F::ZERO)],
        vec![(c.parts.instance.num_cols, F::ZERO)],
    ] {
        assert!(proof::verify(&c.parts.instance, &proof, statement, &bad).is_err());
    }
    let mut bad = proof.clone();
    if let lens::Opening::TensorMerkle { columns, .. } = &mut bad.spartan.pcs_opening {
        columns[0].column[0] ^= 1;
    } else {
        panic!("full-witness proof format changed");
    }
    assert!(proof::verify(&c.parts.instance, &bad, statement, &public).is_err());

    // Independently construct an invalid candidate with matching NEW public
    // coordinates, bypass the honest prover gate, and demand verifier rejection.
    let mut wrong_input = supplied;
    wrong_input[1 + 16] += 1;
    let wrong_witness = witness(&c, &wrong_input);
    let wrong_public = pins(&wrong_input);
    assert!(!c.parts.instance.is_satisfied_by(&wrong_witness));
    let forged =
        proof::unchecked_test_proof(&c.parts.instance, &wrong_witness, statement, &wrong_public);
    assert!(proof::verify(&c.parts.instance, &forged, statement, &wrong_public).is_err());

    let zero = CCSWitness {
        z: vec![F::ZERO; c.parts.instance.num_cols],
    };
    assert!(
        c.parts.instance.is_satisfied_by(&zero),
        "homogeneous rows require external constant binding"
    );
    let forged = proof::unchecked_test_proof(&c.parts.instance, &zero, statement, &[]);
    assert!(proof::verify(&c.parts.instance, &forged, statement, &[]).is_err());
}
