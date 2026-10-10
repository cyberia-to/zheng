//! The succinct profile: completeness on every fixture under both schemes,
//! rejection of forged statements, of a satisfying witness shown for another
//! statement, of tampered messages and of parameters below policy, and
//! byte-for-byte determinism.
mod common;

use common::{ADD, HASH, P, hash_chain, native, parse, synthetic};
use nebu::Goldilocks as F;
use zheng::envelope::{AnySuccinct, Envelope, SuccinctStatement};
use zheng::execution::succinct::{
    self, MultilinearPcs, SuccinctPcs, SuccinctProof, TensorRs, TensorRsParams, Whir, WhirParams,
};
use zheng::execution::{ExecutionNoun, ExecutionStatement, certify_execution};

fn envelope_of<Pc: SuccinctPcs>(s: &ExecutionStatement, p: &SuccinctProof<Pc>) -> Envelope
where
    SuccinctProof<Pc>: Into<AnySuccinct>,
{
    Envelope::Succinct {
        statement: SuccinctStatement::Execution(s.clone()),
        proof: p.clone().into(),
    }
}

fn accepted(e: &Envelope) -> bool {
    Envelope::from_bytes(&e.to_bytes()).is_ok_and(|d| d.verify(&mut |_, _| None).is_ok())
}

fn fixtures() -> Vec<(&'static str, ExecutionNoun, Vec<u64>)> {
    vec![
        ("hash", parse(HASH), vec![7]),
        ("hash", parse(HASH), vec![P - 1]),
        ("add", parse(ADD), vec![7, 5]),
        ("add", parse(ADD), vec![0, 0]),
        ("chain11", hash_chain(11), vec![7]),
    ]
}

fn complete<Pc: SuccinctPcs>(params: Pc::Params)
where
    SuccinctProof<Pc>: Into<AnySuccinct>,
{
    for (name, program, input) in fixtures() {
        let (statement, proof) = succinct::prove::<Pc>(&params, &program, &input, 1_000_000)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let (_, cert) = certify_execution(&program, &input, 1_000_000).unwrap();
        // the same statement public v3 proves
        assert_eq!(statement, certify_execution(&program, &input, 1_000_000).unwrap().0);
        succinct::verify(&statement, &proof).unwrap_or_else(|e| panic!("{name}: {e}"));
        let e = envelope_of(&statement, &proof);
        assert!(accepted(&e), "{name} envelope");
        assert_eq!(e.to_bytes()[10], 1, "profile byte");
        let decoded = Envelope::from_bytes(&e.to_bytes()).unwrap();
        assert_eq!(decoded, e, "{name} round trip");
        println!(
            "{} {name} {input:?}: envelope {} B (public v3 certificate {} free values)",
            Pc::NAME,
            e.to_bytes().len(),
            cert.free.len()
        );
    }
}

#[test]
fn whir_proves_every_fixture() {
    complete::<Whir>(WhirParams::default());
}

#[test]
fn tensor_proves_every_fixture() {
    complete::<TensorRs>(TensorRsParams::default());
}

#[test]
fn hash_chain_agrees_with_native_nox() {
    // 11 is the longest chain the relation compiler admits (32,768 ops/rows)
    for n in [1, 2, 11] {
        let program = hash_chain(n);
        let (statement, _) = certify_execution(&program, &[7], 1_000_000).unwrap();
        let (output, cycles) = native(&program, &[7], 1_000_000);
        assert_eq!(statement.public_output, output, "chain {n}");
        assert_eq!(statement.cycles, cycles, "chain {n}");
    }
}

#[test]
fn synthetic_relations_prove_under_both_schemes() {
    let s = synthetic(10, 3);
    let pw = succinct::prove_relation::<Whir>(
        &WhirParams::default(),
        &s.instance,
        &s.z,
        &s.pins,
        &s.statement,
    )
    .unwrap();
    succinct::verify_relation(&s.instance, &s.pins, &s.statement, &pw).unwrap();
    let pt = succinct::prove_relation::<TensorRs>(
        &TensorRsParams::default(),
        &s.instance,
        &s.z,
        &s.pins,
        &s.statement,
    )
    .unwrap();
    succinct::verify_relation(&s.instance, &s.pins, &s.statement, &pt).unwrap();
    // the output pin is bound: claim another output with the same proof
    let mut pins = s.pins.clone();
    pins[2].1 += F::ONE;
    assert!(succinct::verify_relation(&s.instance, &pins, &s.statement, &pw).is_err());
    // the constant pin cannot be zeroed
    let mut pins = s.pins.clone();
    pins[0].1 = F::ZERO;
    assert!(succinct::verify_relation(&s.instance, &pins, &s.statement, &pw).is_err());
}

fn honest(program: &str, input: &[u64]) -> (ExecutionStatement, SuccinctProof<Whir>) {
    succinct::prove::<Whir>(&WhirParams::default(), &parse(program), input, 1_000_000).unwrap()
}

#[test]
fn forged_statements_are_rejected() {
    for (program, input) in [(HASH, vec![7]), (ADD, vec![7, 5])] {
        let (statement, proof) = honest(program, &input);
        assert!(accepted(&envelope_of(&statement, &proof)));
        let forge = |edit: &dyn Fn(&mut ExecutionStatement)| {
            let mut s = statement.clone();
            edit(&mut s);
            !accepted(&envelope_of(&s, &proof))
        };
        assert!(forge(&|s| s.public_input[0] = (s.public_input[0] + 1) % P), "input");
        assert!(forge(&|s| s.public_output[0] = (s.public_output[0] + 1) % P), "output");
        assert!(forge(&|s| s.public_output.push(0)), "extra output");
        assert!(forge(&|s| s.cycles += 1), "cycles");
        assert!(forge(&|s| s.cycles -= 1), "fewer cycles");
        assert!(forge(&|s| s.budget += 1), "budget");
        let program_edit = |s: &mut ExecutionStatement| {
            let i = s
                .program
                .iter()
                .rposition(|t| matches!(t, zheng::execution::NounToken::Atom(v) if *v == 0))
                .unwrap();
            s.program[i] = zheng::execution::NounToken::Atom(1);
        };
        assert!(forge(&program_edit), "program");
    }
}

#[test]
fn a_satisfying_witness_of_another_statement_is_rejected() {
    // each proof is honest for its own statement; shown for another it fails
    let runs = [
        honest(ADD, &[7, 5]),
        honest(ADD, &[1, 2]),
        honest(ADD, &[0, 0]),
        honest(HASH, &[7]),
        honest(HASH, &[8]),
    ];
    for (i, (statement, _)) in runs.iter().enumerate() {
        for (j, (_, proof)) in runs.iter().enumerate() {
            let ok = succinct::verify(statement, proof).is_ok();
            assert_eq!(ok, i == j, "statement {i} with proof {j}");
        }
    }
}

#[test]
fn tampered_messages_are_rejected() {
    let (statement, proof) = honest(HASH, &[7]);
    let one = nebu::Fp3::new(F::ZERO, F::ONE, F::ZERO);
    let reject = |p: SuccinctProof<Whir>| succinct::verify(&statement, &p).is_err();
    let mut p = proof.clone();
    p.witness_eval += one;
    assert!(reject(p), "witness evaluation");
    for i in 0..proof.matrix_evals.len() {
        let mut p = proof.clone();
        p.matrix_evals[i] += one;
        assert!(reject(p), "matrix {i}");
    }
    let mut p = proof.clone();
    p.outer.rounds[0][0] += one;
    assert!(reject(p), "outer round");
    let mut p = proof.clone();
    let last = p.inner.rounds.len() - 1;
    p.inner.rounds[last][1] += one;
    assert!(reject(p), "inner round");
    let mut p = proof.clone();
    p.root = succinct::prove::<Whir>(&WhirParams::default(), &parse(HASH), &[8], 1_000_000)
        .unwrap()
        .1
        .root;
    assert!(reject(p), "root");
    // other admitted parameters than the opening was made under
    let mut p = proof.clone();
    p.params.pow_bits = 20;
    assert!(reject(p), "params");
}

#[test]
fn parameters_below_policy_are_refused_by_prover_and_verifier() {
    let weak = WhirParams {
        security_target: 96,
        ..WhirParams::default()
    };
    assert!(succinct::prove::<Whir>(&weak, &parse(HASH), &[7], 1_000_000).is_err());
    let few = WhirParams {
        pow_bits: 0,
        log_inv_rate: 1,
        ..WhirParams::default()
    };
    // admitted only if lens proves ≥ 128 bits at this size
    let bits = <Whir as MultilinearPcs>::security_bits(&few, 11);
    let r = succinct::prove::<Whir>(&few, &parse(HASH), &[7], 1_000_000);
    assert_eq!(r.is_ok(), bits >= 128.0, "{bits}");
    // a proof whose header names a weaker target than it was made under
    let (statement, proof) = honest(HASH, &[7]);
    let mut p = proof.clone();
    p.params.security_target = 100;
    assert!(succinct::verify(&statement, &p).is_err());
    let bytes = envelope_of(&statement, &p).to_bytes();
    assert!(Envelope::from_bytes(&bytes).is_ok_and(|e| e.verify(&mut |_, _| None).is_err()));
}

#[test]
fn proofs_are_deterministic() {
    for (program, input) in [(HASH, vec![7]), (ADD, vec![7, 5])] {
        let a = envelope_of(&honest(program, &input).0, &honest(program, &input).1).to_bytes();
        let b = envelope_of(&honest(program, &input).0, &honest(program, &input).1).to_bytes();
        assert_eq!(a, b);
        let pt = TensorRsParams::default();
        let t1 = succinct::prove::<TensorRs>(&pt, &parse(program), &input, 1_000_000).unwrap();
        let t2 = succinct::prove::<TensorRs>(&pt, &parse(program), &input, 1_000_000).unwrap();
        assert_eq!(envelope_of(&t1.0, &t1.1).to_bytes(), envelope_of(&t2.0, &t2.1).to_bytes());
    }
}
