//! Recursive (IVC) proofs of nox runs: a one-step proof and a two-step
//! proof — the second step's circuit verifies the first step's proof, so
//! accepting it is `verify(verify(π))` — verify, and wrong statements,
//! tampered proofs and a forged state are refused.

mod common;

use nebu::{Fp3, Goldilocks};
use zheng::machine::{self, MachineStatement};
use zheng::recursion::ivc::{self, IvcProof};

const STEP: u32 = 15;

fn whir() -> lens::WhirParams {
    let mut w = zheng::execution::succinct::params_for(20);
    w.log_inv_rate = 4;
    w.pow_bits = 24;
    w
}

fn roundtrip(p: &IvcProof) -> IvcProof {
    let w = whir();
    let k = ivc::key(&w, p.log_rows as usize).unwrap();
    let bytes = p.to_bytes(&k);
    let q = IvcProof::from_bytes(&bytes, |lr| ivc::key(&w, lr as usize)).unwrap();
    assert_eq!(&q, p);
    q
}

fn refuses(st: &MachineStatement, p: &IvcProof, what: &str) {
    assert!(ivc::verify(st, p, &whir()).is_err(), "{what} accepted");
}

fn tampered(st: &MachineStatement, p: &IvcProof) {
    let one = Fp3::ONE;
    let mut bad = p.clone();
    bad.step.local[3] += one;
    refuses(st, &bad, "a column value");
    let mut bad = p.clone();
    bad.step.fold_g[0] += one;
    refuses(st, &bad, "a deferred line");
    let mut bad = p.clone();
    bad.step.pub_v[2] += one;
    refuses(st, &bad, "a circuit-key value");
    let mut bad = p.clone();
    bad.step.acc.openings[0][1].symbols[0] += one;
    refuses(st, &bad, "an opened symbol");
    let mut bad = p.clone();
    bad.state.g.value += one;
    refuses(st, &bad, "the carried constraint claim");
    let mut bad = p.clone();
    bad.state.acc.v0 += one;
    refuses(st, &bad, "the carried accumulator");
    let mut bad = p.clone();
    bad.chain[0] += Goldilocks::ONE;
    refuses(st, &bad, "the pre-commitment chain");
    let mut bad = p.clone();
    bad.segments += 1;
    refuses(st, &bad, "the segment count");
}

#[test]
fn a_one_step_recursive_proof_verifies_and_binds_its_statement() {
    let prog = common::parse(common::ADD);
    let (st, p) = ivc::prove(&prog, &[7, 5], 1 << 20, &whir(), STEP).unwrap();
    assert_eq!(p.segments, 1);
    let p = roundtrip(&p);
    ivc::verify(&st, &p, &whir()).unwrap();
    let mut other = st.clone();
    other.output = machine::statement::tokens(&zheng::execution::ExecutionNoun::Atom(13));
    refuses(&other, &p, "a wrong output");
    let mut other = st.clone();
    other.input = vec![7, 6];
    refuses(&other, &p, "a wrong input");
    let mut other = st.clone();
    other.cycles += 1;
    refuses(&other, &p, "a wrong cycle count");
    tampered(&st, &p);
}

#[test]
fn a_two_step_proof_is_verify_of_verify() {
    let prog = common::tree_program(12);
    let run = machine::execute_exact(&prog, &[3], 1 << 30, STEP).unwrap();
    assert_eq!(run.segments(), 2);
    let p = ivc::prove_run(&run, &whir()).unwrap();
    let p = roundtrip(&p);
    ivc::verify(&run.statement, &p, &whir()).unwrap();
    // the proof carries one step and the state the second step's circuit
    // derived by verifying the first
    assert_eq!(p.state.step, Fp3::from_base(Goldilocks::new(1)));
    tampered(&run.statement, &p);
}
