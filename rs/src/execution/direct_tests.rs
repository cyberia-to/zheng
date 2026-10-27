//! Direct (v2 public, v1 state) execution proofs: binding and splice tests,
//! moved from the crate root when the legacy API left the default build.

/// Actual execution protocol binds an axis result to the public subject.
#[test]
fn e2e_axis_execution_binds_subject_and_result() {
    use crate::execution::{ExecutionNoun as N, prove_execution, verify_execution};
    let axis = N::Pair(Box::new(N::Atom(0)), Box::new(N::Atom(2)));
    let (statement, proof) = prove_execution(&axis, &[22], 100).unwrap();
    assert_eq!(statement.public_output, vec![22]);
    assert_eq!(statement.cycles, 1);
    verify_execution(&statement, &proof).unwrap();
    let mut forged = statement.clone();
    forged.public_output[0] = 23;
    assert!(verify_execution(&forged, &proof).is_err());
    let mut swapped = statement.clone();
    swapped.public_input[0] = 23;
    assert!(verify_execution(&swapped, &proof).is_err());
}

/// Opening substitution between two valid execution proofs must fail.
#[test]
fn verify_rejects_spliced_axis_execution_opening() {
    use crate::execution::{ExecutionNoun as N, prove_execution, verify_execution};
    let axis = N::Pair(Box::new(N::Atom(0)), Box::new(N::Atom(2)));
    let (s1, p1) = prove_execution(&axis, &[22], 100).unwrap();
    let (s2, p2) = prove_execution(&axis, &[29], 100).unwrap();
    verify_execution(&s1, &p1).unwrap();
    verify_execution(&s2, &p2).unwrap();
    assert_ne!(p1.spartan.commitment, p2.spartan.commitment);
    let mut spliced = p1.clone();
    spliced.spartan.pcs_opening = p2.spartan.pcs_opening.clone();
    assert!(verify_execution(&s1, &spliced).is_err());
    assert!(verify_execution(&s1, &p2).is_err());
}

/// Namespace 0 holds 10, 20, 30, 40 at keys 3..7.
fn public_state(body: &[u64]) -> crate::execution::state_evidence::StateEvidence {
    use crate::execution::state_evidence::{StateEvidence, StateTable};
    StateEvidence::with_tables(vec![StateTable::with_body(0, body)])
}
fn public_cell() -> crate::execution::state_evidence::StateEvidence {
    public_state(&[10, 20, 30, 40])
}

// zheng authenticates the evidence under the statement's root; BBG's own
// certificate conversion is tested in BBG's look_e2e suite.
fn state_execution_fixture(key: u64) -> (crate::execution::state::StateStatement, crate::execution::DirectProof) {
    use crate::execution::ExecutionNoun as N;
    let pair = |a, b| N::Pair(Box::new(a), Box::new(b));
    let quote = |v| pair(N::Atom(1), N::Atom(v));
    let program = pair(N::Atom(17), pair(quote(0), quote(key)));
    crate::execution::state::prove_state_execution(
        &program, &[], 100, true, &[0; 32], &public_cell(),
    ).unwrap()
}

/// A verifier-authenticated lookup binds root, cell, and execution result.
#[test]
fn e2e_authenticated_public_state_execution_roundtrip() {
    let (statement, proof) = state_execution_fixture(5);
    assert_eq!(statement.execution.public_output, vec![30]);
    statement.verify_v1(&[0; 32], &proof, &public_cell()).unwrap();
    for limb in 0..4 {
        let mut bad = statement.clone(); bad.state_root[limb] = (bad.state_root[limb] + 1) % nebu::field::P;
        assert!(bad.verify_v1(&[0; 32], &proof, &public_cell()).is_err());
    }
    let mut bad = statement.clone(); bad.execution.public_output[0] = 31;
    assert!(bad.verify_v1(&[0; 32], &proof, &public_cell()).is_err());
    let mut empty = public_cell();
    empty.tables.clear();
    assert!(statement.verify_v1(&[0; 32], &proof, &empty).is_err(), "table absent");
    assert!(statement.verify_v1(&[0; 32], &proof, &public_state(&[10, 20, 31, 40])).is_err());
}

/// Valid state proofs for different keys cannot exchange openings or reads.
#[test]
fn verify_rejects_spliced_state_execution_opening() {
    let (s1, p1) = state_execution_fixture(5);
    let (s2, p2) = state_execution_fixture(3);
    assert_eq!(s1.state_root, s2.state_root);
    s1.verify_v1(&[0; 32], &p1, &public_cell()).unwrap();
    s2.verify_v1(&[0; 32], &p2, &public_cell()).unwrap();
    assert_ne!(p1.spartan.commitment, p2.spartan.commitment);
    let mut spliced = p1.clone();
    spliced.spartan.pcs_opening = p2.spartan.pcs_opening.clone();
    assert!(s1.verify_v1(&[0; 32], &spliced, &public_cell()).is_err());
    assert!(s1.verify_v1(&[0; 32], &p2, &public_cell()).is_err());
    let mut changed_read = s1.clone(); changed_read.reads = s2.reads.clone();
    assert!(changed_read.verify_v1(&[0; 32], &p1, &public_cell()).is_err());
}
