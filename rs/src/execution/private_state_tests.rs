use super::{
    ExecutionNoun,
    private_state::prepare_execution,
    relation::{SubjectShape, compile_relation_with_state},
    state_evidence::{StateEvidence, StateTable, table_leaf},
};
use nebu::Goldilocks as F;
fn a(v: u64) -> ExecutionNoun {
    ExecutionNoun::Atom(v)
}
fn p(x: ExecutionNoun, y: ExecutionNoun) -> ExecutionNoun {
    ExecutionNoun::Pair(Box::new(x), Box::new(y))
}
fn q(v: u64) -> ExecutionNoun {
    p(a(1), a(v))
}
fn op(t: u64, x: ExecutionNoun, y: ExecutionNoun) -> ExecutionNoun {
    p(a(t), p(x, y))
}
/// Ten tables: namespace `ns` holds `ns + 20` at key 3 and `ns + 100` at key 4.
fn evidence() -> StateEvidence {
    StateEvidence::with_tables(
        (0..10).map(|ns| StateTable::with_body(ns, &[ns + 20, ns + 100])).collect(),
    )
}
#[test]
fn hidden_namespace_and_index_select_exact_committed_cell() {
    let program = op(17, op(16, q(0), q(0)), op(16, q(0), q(0)));
    let state = evidence();
    let root = state.root().unwrap().map(F::new);
    for (ns, key, expected) in [(0, 3, 20), (4, 4, 104), (9, 4, 109)] {
        let (s, prepared, _) =
            prepare_execution(&program, &[], &[ns, key], 1000, true, &state).unwrap();
        assert_eq!(s.execution.public_output, vec![expected]);
        assert_eq!(s.execution.cycles, 7);
        assert_eq!(
            s.prepare(&state).unwrap().relation.instance,
            prepared.relation.instance
        );
        let bad = prepared
            .relation
            .witness_with_provider(
                &[root[0], root[1], root[2], root[3], F::ZERO],
                &[F::new(ns), F::new(key)],
                &mut |_, _, _| Some(F::new(expected + 1)),
            )
            .unwrap();
        assert!(
            !prepared.relation.instance.is_satisfied_by(&bad),
            "forged query value must fail CCS itself"
        );
    }
    assert!(prepare_execution(&program, &[], &[10, 0], 1000, true, &state).is_err());
    assert!(prepare_execution(&program, &[], &[0, 5], 1000, true, &state).is_err());
}
#[test]
fn forged_program_root_fails_even_when_provider_returns_requested_cell() {
    // Construct the wrong root inside the formula, then perform a lookup.
    let root = p(a(1), p(a(2), p(a(3), a(99))));
    let object = p(root, a(0));
    let program = op(2, p(a(1), object), p(a(1), op(17, q(0), q(0))));
    let state = evidence();
    let tables = state.private_tables(state.root().unwrap()).unwrap();
    let relation = compile_relation_with_state(&program, &SubjectShape::Atom, &tables).unwrap();
    let forged = relation
        .witness_with_provider(&[F::ZERO], &[], &mut |_, _, _| Some(F::new(20)))
        .unwrap();
    assert!(!relation.instance.is_satisfied_by(&forged));
}

/// Both private-state verifiers reject, by themselves, a statement naming
/// another root, evidence for another state, a table altered under the
/// honest leaves, a leaf altered to match it, and a missing table.
#[test]
fn every_private_state_verifier_authenticates_the_evidence_itself() {
    use super::private_state::PrivateStateStatement;
    use super::{veil, zk};
    let program = op(17, op(16, q(0), q(0)), op(16, q(0), q(0)));
    let state = evidence();
    let (statement, prepared, witness) =
        prepare_execution(&program, &[], &[4, 4], 1000, true, &state).unwrap();
    assert_eq!(statement.root, state.root().unwrap());
    let public: Vec<_> =
        prepared.public_coordinates.iter().map(|&(i, v)| (i, F::new(v))).collect();
    let w = crate::types::CCSWitness { z: witness.into_iter().map(F::new).collect() };
    let bytes = b"private-state-test".to_vec();
    let veil_proof = veil::prove_relation(&prepared.relation.instance, &w, &bytes, &public).unwrap();
    let mith_proof = zk::prove(&prepared.relation.instance, &w, &bytes, &public).unwrap();
    type Check<'a> = Box<dyn Fn(&PrivateStateStatement, &StateEvidence) -> bool + 'a>;
    let verifiers: Vec<(&str, Check)> = vec![
        ("veil", Box::new(|s, e| s.verify_veil(e, &veil_proof, &bytes).is_ok())),
        ("mith", Box::new(|s, e| s.verify_mith(e, &mith_proof, &bytes).is_ok())),
    ];
    let mut wrong_root = statement.clone();
    wrong_root.root[0] = (wrong_root.root[0] + 1) % nebu::field::P;
    let foreign = StateEvidence::with_tables(
        (0..10).map(|ns| StateTable::with_body(ns, &[ns + 21, ns + 100])).collect(),
    );
    let mut altered_table = state.clone();
    altered_table.tables[4].fields[4] += 1;
    let mut altered_leaf = altered_table.clone();
    altered_leaf.leaves[4] = table_leaf(&altered_leaf.tables[4].fields);
    let mut missing = state.clone();
    missing.tables.remove(7);
    for (name, verify) in &verifiers {
        assert!(verify(&statement, &state), "{name}: honest");
        assert!(!verify(&wrong_root, &state), "{name}: wrong root");
        assert!(!verify(&statement, &foreign), "{name}: foreign evidence");
        let mut rerooted = statement.clone();
        rerooted.root = foreign.root().unwrap();
        assert!(!verify(&rerooted, &foreign), "{name}: statement re-rooted to foreign evidence");
        assert!(!verify(&statement, &altered_table), "{name}: altered table");
        assert!(!verify(&statement, &altered_leaf), "{name}: altered leaf");
        assert!(!verify(&statement, &missing), "{name}: missing table");
    }
}
