//! The succinct profile on authenticated-state statements (the state v3
//! statement with a committed witness): completeness, and rejection of a
//! wrong root, a wrong read value, a read the caller's certificate does not
//! answer, and a state proof shown for another statement.
use zheng::envelope::{Envelope, SuccinctStatement};
use zheng::execution::ExecutionNoun;
use zheng::execution::succinct::{self, Whir, WhirParams};

const ROOT: [u64; 4] = [1, 2, 3, 4];

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

fn table(root: [u64; 4], value: u64) -> impl FnMut(u64, u64) -> Option<u64> {
    move |ns, key| (root == ROOT && (ns, key) == (2, 11)).then_some(value)
}

#[test]
fn state_statements_prove_and_bind_their_reads() {
    let (statement, proof) = succinct::prove_state::<Whir>(
        &WhirParams::default(),
        &program(),
        &[],
        1000,
        ROOT,
        true,
        [9; 32],
        &mut table(ROOT, 42),
    )
    .unwrap();
    assert_eq!(statement.execution.public_output, vec![126]);
    succinct::verify_state(&statement, &proof, &mut table(ROOT, 42)).unwrap();
    let envelope = Envelope::Succinct {
        statement: SuccinctStatement::State(statement.clone()),
        proof: proof.clone().into(),
    };
    let decoded = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
    assert_eq!(decoded, envelope);
    decoded.verify(&mut table(ROOT, 42)).unwrap();

    // the caller's certificate answers another value: the read is pinned
    assert!(succinct::verify_state(&statement, &proof, &mut table(ROOT, 43)).is_err());
    // no answer at all
    assert!(succinct::verify_state(&statement, &proof, &mut |_, _| None).is_err());
    // the statement claims another value, consistent with a forged certificate
    let mut forged = statement.clone();
    forged.reads[0].value = 43;
    forged.execution.public_output = vec![129];
    assert!(succinct::verify_state(&forged, &proof, &mut table(ROOT, 43)).is_err());
    // another root, answered by a certificate for that root
    for limb in 0..4 {
        let mut wrong = statement.clone();
        wrong.state_root[limb] += 1;
        let root = wrong.state_root;
        let mut lookup = move |ns, key| ((ns, key) == (2, 11) && root != ROOT).then_some(42);
        assert!(succinct::verify_state(&wrong, &proof, &mut lookup).is_err(), "limb {limb}");
    }
    // the context is bound
    let mut other = statement.clone();
    other.context[0] ^= 1;
    assert!(succinct::verify_state(&other, &proof, &mut table(ROOT, 42)).is_err());
}
