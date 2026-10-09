//! The succinct profile on authenticated-state statements (the state v3
//! statement with a committed witness): completeness, and rejection of a
//! wrong root, a wrong read value, a read the evidence does not answer, and
//! a state proof shown for another statement — all by zheng alone, from the
//! state evidence it authenticates under the statement's root.
use zheng::envelope::{Envelope, SuccinctStatement};
use zheng::execution::ExecutionNoun;
use zheng::execution::state_evidence::{StateEvidence, StateTable};
use zheng::execution::succinct::{self, Whir, WhirParams};

fn pair(a: ExecutionNoun, b: ExecutionNoun) -> ExecutionNoun {
    ExecutionNoun::Pair(Box::new(a), Box::new(b))
}
fn q(v: u64) -> ExecutionNoun {
    pair(ExecutionNoun::Atom(1), ExecutionNoun::Atom(v))
}

/// `read(2, 11) · 3`.
fn program() -> ExecutionNoun {
    let read = pair(ExecutionNoun::Atom(17), pair(q(2), q(11)));
    pair(ExecutionNoun::Atom(7), pair(read, q(3)))
}

/// The state with cell(2, 11) = `value`.
fn state(value: u64) -> StateEvidence {
    let mut body = vec![0u64; 9];
    body[8] = value;
    StateEvidence::with_tables(vec![StateTable::with_body(2, &body)])
}

#[test]
fn state_statements_prove_and_bind_their_reads() {
    let (statement, proof) = succinct::prove_state::<Whir>(
        &WhirParams::default(),
        &program(),
        &[],
        1000,
        true,
        &state(42),
    )
    .unwrap();
    assert_eq!(statement.execution.public_output, vec![126]);
    succinct::verify_state(&statement, &proof, &state(42)).unwrap();
    let envelope = Envelope::Succinct {
        statement: SuccinctStatement::State(statement.clone()),
        proof: proof.clone().into(),
    };
    let decoded = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
    assert_eq!(decoded, envelope);
    decoded.verify(Some(&state(42))).unwrap();
    assert!(decoded.verify(None).is_err(), "no evidence");

    // evidence for another state: another root, rejected
    assert!(succinct::verify_state(&statement, &proof, &state(43)).is_err());
    // evidence without the table the read names
    let mut absent = state(42);
    absent.tables.clear();
    assert!(succinct::verify_state(&statement, &proof, &absent).is_err());
    // the statement claims another value and the root of a state that holds it
    let mut forged = statement.clone();
    forged.reads[0].value = 43;
    forged.execution.public_output = vec![129];
    forged.state_root = state(43).root().unwrap();
    assert!(succinct::verify_state(&forged, &proof, &state(43)).is_err());
    // another root
    for limb in 0..4 {
        let mut wrong = statement.clone();
        wrong.state_root[limb] = (wrong.state_root[limb] + 1) % 0xFFFF_FFFF_0000_0001;
        assert!(succinct::verify_state(&wrong, &proof, &state(42)).is_err(), "limb {limb}");
    }
}
