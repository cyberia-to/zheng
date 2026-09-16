use super::state::*;
use super::{ExecutionNoun, ExecutionStatement};
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
fn program() -> ExecutionNoun {
    op(7, op(17, q(2), q(11)), q(3))
}
fn cell(ns: u64, key: u64) -> Option<u64> {
    if (ns, key) == (2, 11) { Some(42) } else { None }
}
#[test]
fn every_lookup_coordinate_and_root_limb_is_bound_to_execution() {
    let (s, proof) = prove_state_execution(
        &program(),
        &[],
        1000,
        [1, 2, 3, 4],
        true,
        [0; 32],
        &mut cell,
    )
    .unwrap();
    assert_eq!(s.execution.public_output, vec![126]);
    assert_eq!(s.execution.cycles, 5);
    s.verify(&proof, &mut cell).unwrap();
    for i in 0..4 {
        let mut bad = s.clone();
        bad.state_root[i] += 1;
        assert!(bad.verify(&proof, &mut cell).is_err());
    }
    for i in 0..5 {
        let mut bad = s.clone();
        match i {
            0 => bad.reads[0].namespace = 1,
            1 => bad.reads[0].key = 12,
            2 => bad.reads[0].value = 43,
            3 => bad.execution.public_output[0] = 129,
            _ => bad.root_in_subject = false,
        }
        assert!(bad.verify(&proof, &mut cell).is_err());
    }
    let mut bad = s.clone();
    bad.reads.clear();
    assert!(bad.verify(&proof, &mut cell).is_err());
    let mut bad = s.clone();
    bad.reads.push(bad.reads[0].clone());
    assert!(bad.verify(&proof, &mut cell).is_err());
    assert!(super::prove_execution(&program(), &[], 1000).is_err());
    assert!(super::private::prepare_execution(&program(), &[], &[], 1000).is_err());
}
#[test]
fn forged_lookup_value_cannot_be_authenticated_by_another_provider() {
    let (forged, proof) = prove_state_execution(
        &program(),
        &[],
        1000,
        [1, 2, 3, 4],
        true,
        [0; 32],
        &mut |_, _| Some(43),
    )
    .unwrap();
    assert_eq!(forged.execution.public_output, vec![129]);
    assert!(forged.verify(&proof, &mut cell).is_err());
}
#[test]
fn inactive_lookup_needs_no_cell_but_cannot_hide_an_active_read() {
    let program = p(a(4), p(q(0), p(q(7), op(17, q(9), q(1234)))));
    let (s, proof) = prove_state_execution(
        &program,
        &[],
        1000,
        [1, 2, 3, 4],
        true,
        [0; 32],
        &mut |_, _| panic!("inactive lookup"),
    )
    .unwrap();
    assert_eq!(s.execution.public_output, vec![7]);
    s.verify(&proof, &mut |_, _| panic!("inactive lookup"))
        .unwrap();
    let mut bad = s.clone();
    bad.reads[0].active = true;
    assert!(bad.verify(&proof, &mut |_, _| Some(0)).is_err());
    // Plain execution cannot smuggle unauthenticated inactive look rows either.
    let execution = ExecutionStatement {
        program: ExecutionStatement::encode_program(&program).unwrap(),
        public_input: vec![],
        public_output: vec![7],
        cycles: 3,
        budget: 1000,
    };
    assert!(execution.relation().is_err());
}
