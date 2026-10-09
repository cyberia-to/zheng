//! The nox machine on joy's compiled fixtures, a Merkle path, and runs
//! long enough to need several segments: agreement with native
//! `nox::reduce` (output noun and cycles), proofs that verify, and
//! statements that do not.

mod common;

use nebu::Goldilocks;
use zheng::execution::ExecutionNoun as N;
use zheng::machine::{self, MachineProof, statement};

fn arena(r: &mut nox::Reduction<8192>, n: &N) -> nox::Order {
    match n {
        N::Atom(v) => r.atom(Goldilocks::new(*v)).unwrap(),
        N::Pair(a, b) => {
            let a = arena(r, a);
            let b = arena(r, b);
            r.pair(a, b).unwrap()
        }
    }
}

fn back(r: &nox::Reduction<8192>, o: nox::Order) -> N {
    match r.get(o).unwrap().inner {
        nox::data::Data::Atom { value } => N::Atom(value.as_u64()),
        nox::data::Data::Pair { left, right } => N::Pair(Box::new(back(r, left)), Box::new(back(r, right))),
    }
}

/// Native nox on joy's subject convention (last input at the head).
fn native(program: &N, input: &[u64], budget: u64) -> (N, u64) {
    let mut r = Box::new(nox::Reduction::<8192>::new());
    let s = arena(&mut r, &statement::subject(input));
    let f = arena(&mut r, program);
    match nox::reduce(&mut r, s, f, budget, &nox::NullCalls, &mut nox::NoTrace) {
        nox::Outcome::Ok(o, rem) => (back(&r, o), budget - rem),
        other => panic!("native: {other:?}"),
    }
}

fn whir() -> lens::WhirParams {
    lens::WhirParams {
        log_inv_rate: 3,
        pow_bits: 16,
        ..lens::WhirParams::default()
    }
}

fn agrees(program: &N, input: &[u64], seg: u32) -> machine::Run {
    let budget = 1 << 40;
    let run = machine::execute_with(program, input, budget, seg).expect("machine");
    let (out, cycles) = native(program, input, budget);
    assert_eq!(statement::parse(&run.statement.output).unwrap(), out);
    assert_eq!(run.statement.cycles, cycles);
    run
}

#[test]
fn joy_fixtures_agree_with_native_nox() {
    let (hash, add) = (common::parse(common::HASH), common::parse(common::ADD));
    for (prog, input) in [
        (&hash, vec![7]),
        (&hash, vec![common::P - 1]),
        (&hash, vec![0]),
        (&add, vec![7, 5]),
        (&add, vec![0, 0]),
        (&add, vec![common::P - 1, 3]),
    ] {
        agrees(prog, &input, machine::SEGMENT_LOG_ROWS);
    }
    // the chain of eleven hashes the relation compiler admits at most
    agrees(&common::hash_chain(11), &[3], machine::SEGMENT_LOG_ROWS);
}

#[test]
fn joy_fixtures_prove_and_bind_their_statements() {
    let w = whir();
    for (prog, input) in [
        (common::parse(common::HASH), vec![7]),
        (common::parse(common::ADD), vec![7, 5]),
    ] {
        let run = agrees(&prog, &input, machine::SEGMENT_LOG_ROWS);
        let proof = machine::prove_run(&run, &w).unwrap();
        let bytes = proof.to_bytes();
        let parsed = MachineProof::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, proof);
        machine::verify(&run.statement, &parsed, &w).unwrap();
        let st = &run.statement;
        let mut forged = vec![st.clone(), st.clone(), st.clone(), st.clone()];
        forged[0].input[0] += 1;
        forged[1].cycles -= 1;
        forged[2].output = statement::tokens(&N::Atom(1));
        forged[3].program = statement::tokens(&N::Pair(Box::new(N::Atom(1)), Box::new(N::Atom(0))));
        for f in &forged {
            assert!(machine::verify(f, &parsed, &w).is_err());
        }
    }
}

#[test]
fn a_merkle_path_and_a_multi_segment_run_prove() {
    let w = whir();
    // an 8-level Merkle path, root computed natively
    let root = native(&common::merkle_program(8, None), &[5], 1 << 30).0;
    let prog = common::merkle_program(8, Some(&root));
    let run = agrees(&prog, &[5], machine::SEGMENT_LOG_ROWS);
    assert_eq!(statement::parse(&run.statement.output).unwrap(), N::Atom(0));
    let proof = machine::prove_run(&run, &w).unwrap();
    machine::verify(&run.statement, &proof, &w).unwrap();
    // a wrong root: the program outputs 1, and the statement claiming 0 fails
    let bad = common::merkle_program(8, Some(&N::Atom(9)));
    let run_bad = agrees(&bad, &[5], machine::SEGMENT_LOG_ROWS);
    assert_eq!(statement::parse(&run_bad.statement.output).unwrap(), N::Atom(1));
    let mut lie = run_bad.statement.clone();
    lie.output = statement::tokens(&N::Atom(0));
    let proof_bad = machine::prove_run(&run_bad, &w).unwrap();
    assert!(machine::verify(&lie, &proof_bad, &w).is_err());
    // a run in many 2^8-row segments
    let tree = common::tree_program(7);
    let run = agrees(&tree, &[3], 8);
    assert!(run.segments() > 4, "{} segments", run.segments());
    let proof = machine::prove_run(&run, &w).unwrap();
    let parsed = MachineProof::from_bytes(&proof.to_bytes()).unwrap();
    machine::verify(&run.statement, &parsed, &w).unwrap();
    let mut lie = run.statement.clone();
    lie.cycles += 1;
    lie.budget += 1;
    assert!(machine::verify(&lie, &parsed, &w).is_err());
    // a self-referencing recursion (computed formulas all the way down)
    let rec = common::rec_program();
    let run = agrees(&rec, &[6], 9);
    assert_eq!(statement::parse(&run.statement.output).unwrap(), N::Atom(64));
    let p2 = machine::prove_run(&run, &w).unwrap();
    machine::verify(&run.statement, &p2, &w).unwrap();
    // a segment's proof moved to another position does not verify
    let mut swapped = parsed.clone();
    swapped.air.segments.swap(1, 2);
    assert!(machine::verify(&run.statement, &swapped, &w).is_err());
}

#[test]
fn the_machine_rides_the_envelope_as_profile_four() {
    use zheng::envelope::{Envelope, Profile};
    let w = whir();
    let run = agrees(&common::parse(common::ADD), &[7, 5], machine::SEGMENT_LOG_ROWS);
    let proof = machine::prove_run(&run, &w).unwrap();
    let env = Envelope::Machine {
        params: w,
        statement: run.statement.clone(),
        proof: Box::new(proof),
    };
    let bytes = env.to_bytes();
    assert_eq!(bytes[10], Profile::Machine as u8);
    let back = Envelope::from_bytes(&bytes).unwrap();
    assert_eq!(back, env);
    back.verify(&mut |_, _| None).unwrap();
    // weak parameters in the header are refused by the policy
    let mut weak = bytes.clone();
    weak[11 + 1] = 1; // log_inv_rate 1
    if let Ok(e) = Envelope::from_bytes(&weak) {
        assert!(e.verify(&mut |_, _| None).is_err());
    }
    // truncation and trailing bytes are rejected
    assert!(Envelope::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(Envelope::from_bytes(&longer).is_err());
}
