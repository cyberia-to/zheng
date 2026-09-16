use super::{
    ExecutionNoun,
    private_state::prepare_execution,
    relation::{PublicStateTables, SubjectShape, compile_relation_with_state},
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
fn tables() -> PublicStateTables {
    PublicStateTables {
        root: [F::new(1), F::new(2), F::new(3), F::new(4)],
        dimensions: std::array::from_fn(|ns| vec![F::new(ns as u64 + 20), F::new(ns as u64 + 100)]),
    }
}
#[test]
fn hidden_namespace_and_index_select_exact_committed_cell() {
    let program = op(17, op(16, q(0), q(0)), op(16, q(0), q(0)));
    let state = tables();
    for (ns, key, expected) in [(0, 0, 20), (4, 1, 104), (9, 1, 109)] {
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
                &[F::new(1), F::new(2), F::new(3), F::new(4), F::ZERO],
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
    assert!(prepare_execution(&program, &[], &[0, 2], 1000, true, &state).is_err());
}
#[test]
fn forged_program_root_fails_even_when_provider_returns_requested_cell() {
    // Construct the wrong root inside the formula, then perform a lookup.
    let root = p(a(1), p(a(2), p(a(3), a(99))));
    let object = p(root, a(0));
    let program = op(2, p(a(1), object), p(a(1), op(17, q(0), q(0))));
    let state = tables();
    let relation = compile_relation_with_state(&program, &SubjectShape::Atom, &state).unwrap();
    let forged = relation
        .witness_with_provider(&[F::ZERO], &[], &mut |_, _, _| Some(F::new(20)))
        .unwrap();
    assert!(!relation.instance.is_satisfied_by(&forged));
}
