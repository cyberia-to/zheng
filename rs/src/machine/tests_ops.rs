//! lt, the word opcodes, call, look and axis addresses ≥ 2^32 against
//! native nox (output and cycles, every constraint on every row), native
//! failures, tampered and non-canonical traces, and proofs with state.

use nebu::{Fp3, Goldilocks};

use super::tests::{a, arena, ax, challenges, op1, op2, p, q, read_back, test_whir};
use super::*;
use crate::air::first_violation;
use crate::execution::ExecutionNoun as N;
use crate::execution::state_evidence::{StateEvidence, StateTable};

const P: u64 = nebu::field::P;

/// nox's providers for the comparison: one fixed witness, and looks
/// answered from evidence when the root's first limb matches (nox hands
/// the provider limb 0 only; the subjects below carry the whole root).
struct Native {
    witness: Option<N>,
    state: Option<(StateEvidence, [u64; 4])>,
}

impl nox::LookProvider for Native {
    fn look(&self, limb0: Goldilocks, ns: Goldilocks, key: Goldilocks) -> Option<Goldilocks> {
        let (ev, root) = self.state.as_ref()?;
        if limb0.as_u64() != root[0] {
            return None;
        }
        let cell = ev
            .authenticate(*root)
            .ok()?
            .cell(ns.as_u64(), key.as_u64())?;
        Some(Goldilocks::new(cell))
    }
}

impl nox::CallProvider<8192> for Native {
    fn provide(
        &self,
        r: &mut nox::Reduction<8192>,
        _tag: Goldilocks,
        _object: nox::Order,
    ) -> Option<nox::Order> {
        Some(arena(r, self.witness.as_ref()?))
    }
}

fn native(prog: &N, input: &[u64], budget: u64, prov: &Native) -> Option<(N, u64)> {
    let mut r = Box::new(nox::Reduction::<8192>::new());
    let subject = arena(&mut r, &statement::subject(input));
    let formula = arena(&mut r, prog);
    match nox::reduce(&mut r, subject, formula, budget, prov, &mut nox::NoTrace) {
        nox::Outcome::Ok(o, rem) => Some((read_back(&r, o), budget - rem)),
        _ => None,
    }
}

fn hints<'a>(prov: &'a Native, w: &'a dyn Fn(u64, &N) -> Option<N>) -> Hints<'a> {
    Hints {
        witness: prov.witness.as_ref().map(|_| w),
        state: prov.state.as_ref().map(|(e, r)| (e, *r)),
    }
}

fn run_with(prog: &N, input: &[u64], budget: u64, prov: &Native) -> Result<Run, MachineError> {
    let wit = prov.witness.clone();
    let w = move |_: u64, _: &N| wit.clone();
    execute_hinted(prog, input, budget, SEGMENT_LOG_ROWS, &hints(prov, &w))
}

fn violation(run: &Run, trace: &crate::air::Trace) -> Option<(usize, usize)> {
    let ch = challenges();
    let m = run.machine(0);
    let (w2, _) = phase2::build(&m, trace, &ch, Fp3::ZERO);
    first_violation(&m, trace, &w2, &ch)
}

/// Run, compare with native nox, check every constraint on every row.
fn check_with(prog: &N, input: &[u64], prov: &Native) -> Run {
    let budget = 1 << 40;
    let run = run_with(prog, input, budget, prov).expect("machine run");
    let (out, cycles) = native(prog, input, budget, prov).expect("native run");
    assert_eq!(
        statement::parse(&run.statement.output).unwrap(),
        out,
        "output"
    );
    assert_eq!(run.statement.cycles, cycles, "cycles");
    assert_eq!(run.segments(), 1);
    let ch = challenges();
    let m = run.machine(0);
    let (w2, sum) = phase2::build(&m, &run.trace, &ch, Fp3::ZERO);
    assert_eq!(sum, Fp3::ZERO, "logUp sum closes");
    assert_eq!(first_violation(&m, &run.trace, &w2, &ch), None);
    run
}

const PLAIN: Native = Native {
    witness: None,
    state: None,
};

fn binary_cases() -> Vec<(u64, u64)> {
    vec![
        (3, 5),
        (5, 3),
        (5, 5),
        (0, 0),
        (0, P - 1),
        (P - 1, 0),
        (P - 1, P - 2),
        (1 << 32, (1 << 32) + 1),
        ((1 << 32) + 7, 1 << 33),
        (1 << 63, 0xFFFF_FFFF),
        (0xFFFF_FFFF, 1 << 32),
        (0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_0000_0000),
    ]
}

fn word_cases() -> Vec<(u64, u64)> {
    vec![
        (0b1100, 0b1010),
        (0xFFFF_FFFF, 0x1234_5678),
        (0, 0),
        (0xDEAD_BEEF, 0xFFFF_FFFF),
        (0x8000_0000, 1),
    ]
}

fn shl_cases() -> Vec<(u64, u64)> {
    vec![
        (1, 0),
        (1, 31),
        (0xFFFF_FFFF, 1),
        (0xDEAD_BEEF, 13),
        (0xFFFF_FFFF, 31),
        (5, 32),
        (5, 33),
        (5, 0xFFFF_FFFF),
        (0, 7),
    ]
}

#[test]
fn lt_and_word_opcodes_match_native_nox_and_satisfy_the_relation() {
    let mut n = 0;
    for (u, w) in binary_cases() {
        check_with(&op2(10, ax(2), ax(6)), &[w, u], &PLAIN);
        n += 1;
    }
    for (u, w) in word_cases() {
        for t in [11, 12] {
            check_with(&op2(t, ax(2), ax(6)), &[w, u], &PLAIN);
            n += 1;
        }
        check_with(&op1(13, ax(2)), &[u], &PLAIN);
        n += 1;
    }
    for (u, w) in shl_cases() {
        check_with(&op2(14, ax(2), ax(6)), &[w, u], &PLAIN);
        n += 1;
    }
    // computed operands: xor(and(x, y), not(x)) < shl(y, 3)
    let x = op2(11, op2(12, ax(2), ax(6)), op1(13, ax(2)));
    check_with(&op2(10, x, op2(14, ax(6), q(3))), &[0x0F0F, 0x3C3C], &PLAIN);
    assert_eq!(n, 36);
}

/// A noun whose path to address `addr` (≥ 2) ends in `leaf`; every other
/// child is the atom 0.
fn along(addr: u64, leaf: N) -> N {
    let levels = 63 - addr.leading_zeros();
    let mut node = leaf;
    for k in 0..levels {
        node = if (addr >> k) & 1 == 1 {
            p(a(0), node)
        } else {
            p(node, a(0))
        };
    }
    node
}

fn deep_axis(addr: u64, leaf: u64) -> N {
    // [2 [[1 noun] [1 [0 addr]]]]: axis addr of a quoted noun
    op2(2, p(a(1), along(addr, a(leaf))), p(a(1), ax(addr)))
}

#[test]
fn axis_addresses_up_to_p_match_native_nox() {
    let inputs: Vec<u64> = (100..140).collect();
    // a 40-element list: x_5 at 2^37 − 2, the terminal 0 at 2^41 − 1
    check_with(&ax((1 << 37) - 2), &inputs, &PLAIN);
    check_with(&ax((1 << 41) - 1), &inputs, &PLAIN);
    for addr in [
        (1u64 << 32) + 3,
        1 << 40,
        (1 << 63) + 5,
        P - 1,
        P - 2,
        0xFFFF_FFFE_FFFF_FFFF,
    ] {
        check_with(&deep_axis(addr, 77), &[], &PLAIN);
    }
}

fn witness_prog(check: N) -> N {
    // cons(call(tag 7, check), [0 1]): the witness and the subject
    op2(3, op2(16, q(7), check), ax(1))
}

#[test]
fn call_matches_native_nox_with_atom_and_pair_witnesses() {
    let atom = Native {
        witness: Some(a(99)),
        state: None,
    };
    check_with(&witness_prog(op2(9, ax(2), q(99))), &[4], &atom);
    let pair = p(a(3), p(a(4), p(a(5), a(6))));
    let prov = Native {
        witness: Some(pair.clone()),
        state: None,
    };
    // the check reads the witness (axis 2) and the old subject (axis 3)
    let check = op2(9, ax(2), p(a(1), pair));
    check_with(&witness_prog(check), &[4, 8], &prov);
    let check = op2(9, ax(6), q(4));
    let prov = Native {
        witness: Some(a(1)),
        state: None,
    };
    check_with(&witness_prog(check), &[4], &prov);
}

fn root_formula() -> N {
    // [r0 [r1 [r2 r3]]] from inputs [r3, r2, r1, r0]
    op2(3, ax(2), op2(3, ax(6), op2(3, ax(14), ax(30))))
}

fn with_root(f: N) -> N {
    // compose(cons(root, subject), quote(f)): f runs on [root subject]
    op2(2, op2(3, root_formula(), ax(1)), p(a(1), f))
}

fn state() -> (StateEvidence, [u64; 4]) {
    let ev = StateEvidence::with_tables(vec![
        StateTable::with_body(0, &[11, 12, 13, 14]),
        StateTable::with_body(3, &[P - 1, 0, 7]),
    ]);
    let root = ev.root().unwrap();
    (ev, root)
}

fn root_input(root: [u64; 4]) -> Vec<u64> {
    vec![root[3], root[2], root[1], root[0]]
}

#[test]
fn look_matches_native_nox_on_authenticated_state() {
    let (ev, root) = state();
    let prov = Native {
        witness: None,
        state: Some((ev, root)),
    };
    let input = root_input(root);
    let look = |ns: N, key: N| op2(17, ns, key);
    let run = check_with(&with_root(look(q(0), q(3))), &input, &prov);
    assert_eq!(
        run.statement.state.as_ref().unwrap().reads,
        vec![(0, 3, 11)]
    );
    // two reads, one repeated, a computed key, arithmetic on values
    let prog = with_root(op2(
        3,
        op2(5, look(q(0), q(6)), look(q(3), op2(5, q(1), q(2)))),
        op2(3, look(q(0), q(6)), look(q(3), q(5))),
    ));
    let run = check_with(&prog, &input, &prov);
    assert_eq!(run.statement.state.as_ref().unwrap().reads.len(), 3);
}

#[test]
fn native_failures_of_the_new_opcodes_are_machine_failures() {
    let budget = 1 << 20;
    let (ev, root) = state();
    let st = Native {
        witness: None,
        state: Some((ev.clone(), root)),
    };
    let input = root_input(root);
    let mut other = root;
    other[2] = other[2].wrapping_add(1) % P;
    let cases: Vec<(N, Vec<u64>, &Native)> = vec![
        (op2(10, ax(1), q(1)), vec![1, 2], &PLAIN), // lt on a pair
        (op2(11, ax(2), q(1)), vec![1 << 32], &PLAIN), // xor of a non-word
        (op2(12, q(1), ax(2)), vec![P - 1], &PLAIN), // and of a non-word
        (op1(13, ax(2)), vec![1 << 32], &PLAIN),    // not of a non-word
        (op1(13, ax(1)), vec![1], &PLAIN),          // not of a pair
        (op2(14, ax(2), q(3)), vec![1 << 32], &PLAIN), // shl of a non-word
        (op2(14, q(3), ax(2)), vec![1 << 33], &PLAIN), // shl by a non-word
        (witness_prog(q(0)), vec![1], &PLAIN),      // call: no witness
        (op2(16, ax(1), q(0)), vec![1], &PLAIN),    // call: tag a pair
        (ax((1 << 37) + 6), (0..40).collect(), &PLAIN), // axis through an atom
        (with_root(op2(17, q(0), q(3))), input.clone(), &PLAIN), // look: no state
        (with_root(op2(17, q(10), q(3))), input.clone(), &st), // look: namespace 10
        (with_root(op2(17, q(0), q(99))), input.clone(), &st), // look: key absent
        (with_root(op2(17, q(1), q(3))), input.clone(), &st), // look: table absent
        (with_root(op2(17, ax(1), q(3))), input.clone(), &st), // look: namespace a pair
        (op2(17, q(0), q(3)), input.clone(), &st),  // look: no root noun
    ];
    for (prog, input, prov) in &cases {
        assert!(
            native(prog, input, budget, prov).is_none(),
            "native {prog:?}"
        );
        assert!(
            run_with(prog, input, budget, prov).is_err(),
            "machine {prog:?}"
        );
    }
    // a check that does not return 0 is rejected
    let bad = Native {
        witness: Some(a(98)),
        state: None,
    };
    let prog = witness_prog(op2(9, ax(2), q(99)));
    assert!(native(&prog, &[1], budget, &bad).is_none());
    assert!(run_with(&prog, &[1], budget, &bad).is_err());
    // the machine reads under all four limbs: a subject root that differs
    // from the authenticated root only past limb 0 has no trace
    let prog = with_root(op2(17, q(0), q(3)));
    assert!(run_with(&prog, &root_input(other), budget, &st).is_err());
    // the budget: exact cycles pass, one fewer fails
    for prog in [op2(10, ax(2), ax(6)), op2(14, ax(2), ax(6)), op1(13, ax(2))] {
        let (_, cycles) = native(&prog, &[1, 2], 1 << 20, &PLAIN).unwrap();
        assert!(run_with(&prog, &[1, 2], cycles, &PLAIN).is_ok());
        assert!(run_with(&prog, &[1, 2], cycles - 1, &PLAIN).is_err());
    }
}

fn rows_where(run: &Run, pred: impl Fn(&[Goldilocks]) -> bool) -> Vec<usize> {
    (0..run.trace.rows())
        .filter(|&r| pred(run.trace.row(r)))
        .collect()
}

fn is(r: &[Goldilocks], cols: &[usize]) -> bool {
    cols.iter().all(|&c| r[c] == Goldilocks::ONE)
}

#[test]
fn tampered_traces_of_the_new_opcodes_violate_the_relation() {
    use layout::*;
    let one = Goldilocks::ONE;
    let mut cells: Vec<(Run, usize, usize)> = Vec::new();
    for (prog, input) in [
        (op2(10, ax(2), ax(6)), vec![9, P - 3]),
        (op2(11, ax(2), ax(6)), vec![0x55, 0xF0]),
        (op2(14, ax(2), ax(6)), vec![3, 0xFFFF]),
        (op1(13, ax(2)), vec![0xF0F0]),
    ] {
        let run = check_with(&prog, &input, &PLAIN);
        let ret = rows_where(&run, |r| is(r, &[K_RET, F_B2W]))[0];
        let bits = rows_where(&run, |r| is(r, &[K_AUX, S_WBIT]));
        cells.push((run.clone(), ret, slot(3, P0))); // the result atom
        cells.push((run.clone(), bits[7], G_B2)); // a result bit
        cells.push((run.clone(), bits[3], G_B0)); // an operand bit
        cells.push((run, bits[31], D)); // the result carried
    }
    let run = check_with(&op2(9, op2(5, ax(2), q(1)), ax(6)), &[3, 4], &PLAIN);
    let b1 = rows_where(&run, |r| is(r, &[K_RET, F_B1]));
    assert_eq!(b1.len(), 2);
    cells.push((run.clone(), b1[0], R_OP)); // the frame's op
    cells.push((run, b1[1], R_OPY)); // the op restriction
    let deep = check_with(&deep_axis(P - 1, 5), &[], &PLAIN);
    let walk = rows_where(&deep, |r| r[K_AXW] == one);
    assert_eq!(walk.len(), 63);
    cells.push((deep.clone(), walk[40], A_BIT));
    cells.push((deep.clone(), walk[62], A_AH));
    cells.push((deep, walk[10], X));
    let wit = Native {
        witness: Some(p(a(3), a(4))),
        state: None,
    };
    let run = check_with(
        &witness_prog(op2(9, ax(2), p(a(1), p(a(3), a(4))))),
        &[1],
        &wit,
    );
    let watom = rows_where(&run, |r| is(r, &[K_AUX, S_WATOM]))[0];
    let wpair = rows_where(&run, |r| is(r, &[K_AUX, S_WPAIR]))[0];
    let join = rows_where(&run, |r| is(r, &[K_AUX, S_WJOIN]))[0];
    cells.push((run.clone(), watom, slot(0, P0))); // the witness atom
    cells.push((run.clone(), wpair, slot(2, P0))); // a child
    cells.push((run.clone(), join, slot(1, P0 + 1))); // the subject
    cells.push((run, join, W_SP)); // the stack
    let (ev, root) = state();
    let st = Native {
        witness: None,
        state: Some((ev, root)),
    };
    let run = check_with(&with_root(op2(17, q(0), q(3))), &root_input(root), &st);
    let ret = rows_where(&run, |r| is(r, &[K_RET, F_B2LOOK]))[0];
    let lk = rows_where(&run, |r| is(r, &[K_AUX, S_LOOK]))[0];
    cells.push((run.clone(), ret, slot(3, P0 + 2))); // the value read
    cells.push((run.clone(), lk, slot(2, P0))); // the value written
    cells.push((run.clone(), lk, slot(1, P0 + 3))); // the root digest
    cells.push((run, 0, slot(0, P0 + 2))); // an init entry's third field
    for (run, row, col) in &cells {
        let mut t = run.trace.clone();
        t.row_mut(*row)[*col] += one;
        assert!(violation(run, &t).is_some(), "({row}, {col})");
    }
}

/// The non-canonical alias `v + p` of an lt operand or an axis address is
/// refused by the canonical check exactly: the forged trace satisfies
/// every other constraint.
#[test]
fn non_canonical_aliases_violate_only_the_canonical_check() {
    use layout::*;
    let forge = |prog: &N, input: &[u64]| {
        run_ops::ALIAS.with(|c| c.set(true));
        let run = execute(prog, input, 1 << 30);
        run_ops::ALIAS.with(|c| c.set(false));
        run.expect("forged run")
    };
    // lt: 3 < 5, aliased 3 + p > 5 flips the result
    let run = forge(&op2(10, q(3), q(5)), &[]);
    let last = *rows_where(&run, |r| is(r, &[K_AUX, S_WBIT]))
        .last()
        .unwrap();
    assert_eq!(statement::parse(&run.statement.output).unwrap(), a(1));
    assert_eq!(violation(&run, &run.trace).map(|v| v.0), Some(last));
    // axis 6 walked as 6 + p on a noun that has that path
    let prog = op2(2, p(a(1), along(6 + P, a(9))), p(a(1), ax(6)));
    let run = forge(&prog, &[]);
    let walk = rows_where(&run, |r| r[K_AXW] == Goldilocks::ONE);
    assert_eq!(walk.len(), 63);
    assert_eq!(violation(&run, &run.trace).map(|v| v.0), Some(walk[62]));
}

#[test]
fn a_run_with_every_new_opcode_proves_and_verifies_against_its_state() {
    let whir = test_whir();
    let (ev, root) = state();
    let prov = Native {
        witness: Some(p(a(6), a(7))),
        state: Some((ev.clone(), root)),
    };
    let body = op2(
        3,
        op2(10, op2(17, q(0), q(4)), op2(14, op2(11, q(3), q(5)), q(2))),
        op2(
            3,
            op2(16, q(1), op2(9, ax(5), q(7))),
            op1(13, op2(12, q(0xFF), q(0x0F))),
        ),
    );
    let prog = with_root(body);
    let run = check_with(&prog, &root_input(root), &prov);
    let st = run.statement.clone();
    assert!(st.state.is_some());
    let proof = prove_run(&run, &whir).unwrap();
    verify_with_state(&st, &proof, &whir, Some(&ev)).unwrap();
    // no evidence, evidence of another state, a forged read, another root
    assert!(verify(&st, &proof, &whir).is_err());
    let other = StateEvidence::with_tables(vec![StateTable::with_body(0, &[11, 12, 13, 99])]);
    assert!(verify_with_state(&st, &proof, &whir, Some(&other)).is_err());
    let mut bad = st.clone();
    bad.state.as_mut().unwrap().reads[0].2 += 1;
    assert!(verify_with_state(&bad, &proof, &whir, Some(&ev)).is_err());
    let mut bad = st.clone();
    bad.state.as_mut().unwrap().root = other.root().unwrap();
    assert!(verify_with_state(&bad, &proof, &whir, Some(&other)).is_err());
    // the envelope carries the state and verifies with the evidence only
    let env = crate::envelope::Envelope::Machine {
        params: whir,
        statement: st.clone(),
        proof: Box::new(proof),
    };
    let bytes = env.to_bytes();
    let back = crate::envelope::Envelope::from_bytes(&bytes).unwrap();
    assert_eq!(back, env);
    back.verify(Some(&ev)).unwrap();
    assert!(back.verify(None).is_err());
}
