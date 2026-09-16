use super::{ExecutionStatement, private::prepare_execution, relation::*};
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
fn axis(v: u64) -> ExecutionNoun {
    p(a(0), a(v))
}
fn op(t: u64, x: ExecutionNoun, y: ExecutionNoun) -> ExecutionNoun {
    p(a(t), p(x, y))
}
#[test]
fn call_checks_the_actual_private_witness_and_public_result() {
    // [16 [quote(tag), witness == original first input]]
    let program = op(16, q(7), op(9, axis(2), axis(6)));
    let (statement, prepared, witness) = prepare_execution(&program, &[42], &[42], 1000).unwrap();
    assert_eq!(statement.execution.public_output, vec![42]);
    assert_eq!(statement.execution.cycles, 5);
    assert!(prepare_execution(&program, &[42], &[41], 1000).is_err());
    assert!(prepare_execution(&program, &[42], &[], 1000).is_err());
    assert!(prepare_execution(&program, &[42], &[42, 43], 1000).is_err());
    let regenerated = statement.prepare().unwrap();
    assert_eq!(regenerated.relation.instance, prepared.relation.instance);
    let mut bad = zheng_witness(witness);
    bad.z[prepared.relation.output_indices[0]] += F::ONE;
    assert!(!prepared.relation.instance.is_satisfied_by(&bad));
}
fn zheng_witness(w: Vec<u64>) -> crate::types::CCSWitness {
    crate::types::CCSWitness {
        z: w.into_iter().map(F::new).collect(),
    }
}
#[test]
fn inactive_calls_do_not_consume_secrets_or_require_success() {
    let good = op(16, q(0), q(0));
    let bad = op(16, q(0), q(1));
    let program = p(a(4), p(axis(2), p(good, bad)));
    let (s, _, _) = prepare_execution(&program, &[0], &[123], 1000).unwrap();
    assert_eq!(s.execution.public_output, vec![123]);
    assert!(prepare_execution(&program, &[1], &[123], 1000).is_err());
    // Two active calls in sequence use the native left-to-right stream order.
    let program = op(3, op(16, q(0), q(0)), op(16, q(0), q(0)));
    let (s, _, _) = prepare_execution(&program, &[], &[11, 22], 1000).unwrap();
    assert_eq!(s.execution.public_output, vec![11, 22]);
}
#[test]
fn inactive_word_range_is_allowed_but_selected_invalid_word_fails() {
    let program = p(a(4), p(axis(2), p(q(7), p(a(13), q(1u64 << 32)))));
    let shape = SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom));
    let relation = compile_relation(&program, &shape).unwrap();
    assert!(
        relation
            .instance
            .is_satisfied_by(&relation.witness(&[F::ZERO, F::ZERO]).unwrap())
    );
    assert!(
        !relation
            .instance
            .is_satisfied_by(&relation.witness(&[F::ONE, F::ZERO]).unwrap())
    );
    assert!(ExecutionStatement::encode_program(&program).is_ok());
}
