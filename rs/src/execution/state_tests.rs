use super::state::*;
use super::state_evidence::StateEvidence;
use super::state_evidence::tests::{evidence, table};
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
/// cell(2, 11) = 42.
fn state_with(value: u64) -> StateEvidence {
    let mut body = vec![0u64; 9];
    body[8] = value;
    evidence(vec![table(2, &body)])
}
fn state() -> StateEvidence {
    state_with(42)
}
#[test]
fn every_lookup_coordinate_and_root_limb_is_bound_to_execution() {
    let (s, proof) = prove_state_execution(&program(), &[], 1000, true, &[0; 32], &state()).unwrap();
    assert_eq!(s.execution.public_output, vec![126]);
    assert_eq!(s.execution.cycles, 5);
    s.verify_v1(&[0; 32], &proof, &state()).unwrap();
    for i in 0..4 {
        let mut bad = s.clone();
        bad.state_root[i] = (bad.state_root[i] + 1) % nebu::field::P;
        assert!(bad.verify_v1(&[0; 32], &proof, &state()).is_err());
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
        assert!(bad.verify_v1(&[0; 32], &proof, &state()).is_err());
    }
    let mut bad = s.clone();
    bad.reads.clear();
    assert!(bad.verify_v1(&[0; 32], &proof, &state()).is_err());
    let mut bad = s.clone();
    bad.reads.push(bad.reads[0].clone());
    assert!(bad.verify_v1(&[0; 32], &proof, &state()).is_err());
    assert!(super::prove_execution(&program(), &[], 1000).is_err());
    assert!(super::private::prepare_execution(&program(), &[], &[], 1000).is_err());
}
#[test]
fn forged_lookup_value_cannot_be_authenticated_by_another_provider() {
    // a proof made from another state is a statement about another root
    let (forged, proof) =
        prove_state_execution(&program(), &[], 1000, true, &[0; 32], &state_with(43)).unwrap();
    assert_eq!(forged.execution.public_output, vec![129]);
    assert!(forged.verify_v1(&[0; 32], &proof, &state()).is_err());
    let mut rerooted = forged.clone();
    rerooted.state_root = state().root().unwrap();
    assert!(rerooted.verify_v1(&[0; 32], &proof, &state()).is_err());
}
#[test]
fn inactive_lookup_needs_no_cell_but_cannot_hide_an_active_read() {
    let program = p(a(4), p(q(0), p(q(7), op(17, q(9), q(1234)))));
    let (s, proof) = prove_state_execution(&program, &[], 1000, true, &[0; 32], &state()).unwrap();
    assert_eq!(s.execution.public_output, vec![7]);
    s.verify_v1(&[0; 32], &proof, &state()).unwrap();
    let mut bad = s.clone();
    bad.reads[0].active = true;
    assert!(bad.verify_v1(&[0; 32], &proof, &state()).is_err());
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
