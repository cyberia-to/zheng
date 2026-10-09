//! Machine: every opcode against native nox (output and cycles), every
//! constraint on honest traces, rejection of tampered traces, and one
//! end-to-end proof.

use nebu::{Fp3, Goldilocks};

use super::*;
use crate::air::first_violation;
use crate::execution::ExecutionNoun as N;

pub(crate) fn a(v: u64) -> N {
    N::Atom(v)
}
pub(crate) fn p(x: N, y: N) -> N {
    N::Pair(Box::new(x), Box::new(y))
}
pub(crate) fn q(v: u64) -> N {
    p(a(1), a(v))
}
pub(crate) fn ax(n: u64) -> N {
    p(a(0), a(n))
}
pub(crate) fn op2(t: u64, x: N, y: N) -> N {
    p(a(t), p(x, y))
}
pub(crate) fn op1(t: u64, x: N) -> N {
    p(a(t), x)
}

fn arena(r: &mut nox::Reduction<8192>, n: &N) -> nox::Order {
    match n {
        N::Atom(v) => r.atom(Goldilocks::new(*v)).unwrap(),
        N::Pair(x, y) => {
            let x = arena(r, x);
            let y = arena(r, y);
            r.pair(x, y).unwrap()
        }
    }
}

fn read_back(r: &nox::Reduction<8192>, o: nox::Order) -> N {
    match r.get(o).unwrap().inner {
        nox::data::Data::Atom { value } => N::Atom(value.as_u64()),
        nox::data::Data::Pair { left, right } => p(read_back(r, left), read_back(r, right)),
    }
}

/// Native `nox::reduce`: `(output, cycles)` or `None` on any failure.
pub(crate) fn native(program: &N, input: &[u64], budget: u64) -> Option<(N, u64)> {
    let mut r = Box::new(nox::Reduction::<8192>::new());
    let subject = arena(&mut r, &statement::subject(input));
    let formula = arena(&mut r, program);
    match nox::reduce(&mut r, subject, formula, budget, &nox::NullCalls, &mut nox::NoTrace) {
        nox::Outcome::Ok(o, rem) => Some((read_back(&r, o), budget - rem)),
        _ => None,
    }
}

fn challenges() -> [Fp3; 2] {
    let e = |a, b, c| Fp3::new(Goldilocks::new(a), Goldilocks::new(b), Goldilocks::new(c));
    [e(91, 7, 1234567), e(5, 77, 31)]
}

/// Run, compare with native nox, and check every constraint on every row.
pub(crate) fn check(program: &N, input: &[u64]) -> Run {
    let budget = 1 << 40;
    let run = execute(program, input, budget).expect("machine run");
    let (out, cycles) = native(program, input, budget).expect("native run");
    assert_eq!(statement::parse(&run.statement.output).unwrap(), out, "output");
    assert_eq!(run.statement.cycles, cycles, "cycles");
    assert_eq!(run.segments(), 1);
    let ch = challenges();
    let m = run.machine(0);
    let (w2, sum) = phase2::build(&m, &run.trace, &ch, Fp3::ZERO);
    assert_eq!(sum, Fp3::ZERO, "logUp sum closes");
    assert_eq!(first_violation(&m, &run.trace, &w2, &ch), None);
    run
}

pub(crate) fn programs() -> Vec<(&'static str, N, Vec<u64>)> {
    let add = op2(5, ax(2), ax(6));
    vec![
        ("quote", q(42), vec![]),
        ("axis", ax(1), vec![9]),
        ("axis-deep", ax(7), vec![3, 4, 5]),
        ("add", add.clone(), vec![7, 5]),
        ("sub-mul", op2(7, op2(6, ax(2), q(3)), ax(6)), vec![7, 5]),
        ("cons", op2(3, ax(2), q(8)), vec![1]),
        ("branch-yes", p(a(4), p(q(0), p(q(10), q(20)))), vec![]),
        ("branch-no", p(a(4), p(ax(2), p(q(10), q(20)))), vec![3]),
        ("compose", op2(2, ax(1), p(a(1), q(5))), vec![]),
        ("compose-computed", op2(2, ax(2), op2(3, q(0), q(1))), vec![6]),
        ("inv", op1(8, ax(2)), vec![5]),
        ("eq-atoms", op2(9, ax(2), ax(6)), vec![4, 4]),
        ("eq-atoms-ne", op2(9, ax(2), ax(6)), vec![4, 3]),
        ("eq-mixed", op2(9, ax(1), ax(2)), vec![4]),
        ("eq-pairs", op2(9, ax(1), ax(1)), vec![4, 5]),
        ("eq-pairs-ne", op2(9, ax(1), op2(3, ax(2), ax(2))), vec![4, 5]),
        ("hash", op1(15, ax(2)), vec![7]),
        ("hash-pair", op1(15, ax(1)), vec![7, 8]),
        ("axis0", ax(0), vec![2]),
        ("nested", op2(5, op2(7, ax(2), ax(2)), op2(5, ax(6), q(1))), vec![3, 4]),
    ]
}

#[test]
fn every_opcode_matches_native_nox_and_satisfies_the_relation() {
    for (name, prog, input) in programs() {
        let run = std::panic::catch_unwind(|| check(&prog, &input));
        assert!(run.is_ok(), "{name}");
    }
}

#[test]
fn native_failures_are_machine_failures() {
    let budget = 1 << 20;
    for (prog, input) in [
        (a(5), vec![]),                          // formula atom
        (p(a(77), a(0)), vec![]),               // unknown opcode
        (op2(5, ax(1), q(1)), vec![1]),          // add on a pair
        (ax(4), vec![1]),                        // axis through an atom
        (op1(8, q(0)), vec![]),                  // inverse of zero
        (p(a(4), p(ax(1), p(q(1), q(2)))), vec![3]), // branch on a pair
    ] {
        assert!(native(&prog, &input, budget).is_none());
        assert!(execute(&prog, &input, budget).is_err(), "{prog:?}");
    }
    // the budget: exact cycles pass, one fewer fails
    let prog = op2(5, ax(2), ax(6));
    let (_, cycles) = native(&prog, &[1, 2], 1000).unwrap();
    assert!(execute(&prog, &[1, 2], cycles).is_ok());
    assert!(execute(&prog, &[1, 2], cycles - 1).is_err());
}

#[test]
fn tampered_traces_violate_the_relation() {
    let run = check(&op2(5, ax(2), ax(6)), &[7, 5]);
    let ch = challenges();
    let rows = run.trace.rows();
    let find = |pred: &dyn Fn(&[Goldilocks]) -> bool| {
        (0..rows).find(|&r| pred(run.trace.row(r))).expect("row")
    };
    let one = Goldilocks::ONE;
    let add_ret = find(&|r| r[layout::K_RET] == one && r[layout::F_B2ADD] == one);
    let first_eval = run.constants.p as usize;
    let round = run.start + layout::PH_ROUND0 + 5;
    // a forged result atom, a forged cycle count, a forged frame id, a
    // forged permutation state, a forged init entry
    for (row, col) in [
        (add_ret, layout::slot(3, layout::P0)),
        (first_eval + 1, layout::CYC),
        (first_eval, layout::slot(3, layout::KEY)),
        (round, layout::STATE + 3),
        (2, layout::slot(0, layout::P0)),
    ] {
        let mut t = run.trace.clone();
        t.row_mut(row)[col] += one;
        let m = run.machine(0);
        let (w2, _) = phase2::build(&m, &t, &ch, Fp3::ZERO);
        assert!(first_violation(&m, &t, &w2, &ch).is_some(), "({row}, {col})");
    }
}

pub(crate) fn test_whir() -> lens::WhirParams {
    lens::WhirParams {
        log_inv_rate: 3,
        pow_bits: 16,
        ..lens::WhirParams::default()
    }
}

#[test]
fn a_run_proves_and_verifies_and_a_forged_statement_does_not() {
    let whir = test_whir();
    let prog = op2(3, op2(7, ax(2), ax(2)), op1(15, ax(6)));
    let (st, proof) = prove(&prog, &[3, 4], 1 << 20, &whir).unwrap();
    verify(&st, &proof, &whir).unwrap();
    let mut bad = st.clone();
    bad.cycles += 1;
    bad.budget += 1;
    assert!(verify(&bad, &proof, &whir).is_err());
    let mut bad = st.clone();
    bad.input[0] += 1;
    assert!(verify(&bad, &proof, &whir).is_err());
    let mut bad = st.clone();
    bad.output = statement::tokens(&a(1));
    assert!(verify(&bad, &proof, &whir).is_err());
}

