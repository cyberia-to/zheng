//! Adversarial review of the opcode constraints (zheng #52): forged traces
//! that are consistent everywhere — memory, digests, output — except at the
//! constraint under attack, and the degree / count of the relation.

use nebu::{Fp3, Goldilocks};

use super::run_ops::{FORGE, Forge};
use super::tests::{a, ax, challenges, op1, op2, p, q};
use super::*;
use crate::air::{Air, Vals};
use crate::execution::ExecutionNoun as N;
use crate::execution::state_evidence::{StateEvidence, StateTable};
use layout::*;

const P: u64 = nebu::field::P;

/// Every `(row, constraint)` the trace violates.
fn violations(run: &Run, trace: &crate::air::Trace) -> Vec<(usize, usize)> {
    let ch = challenges();
    let m = run.machine(0);
    let (w2, _) = phase2::build(&m, trace, &ch, Fp3::ZERO);
    let rows = trace.rows();
    let n = rows.trailing_zeros() as usize;
    let pubs: Vec<Vec<Fp3>> = m.publics().iter().map(|p| p.table(n)).collect();
    let row = |r: usize| -> Vec<Fp3> {
        trace
            .row(r)
            .iter()
            .chain(w2.row(r))
            .map(|&x| Fp3::from_base(x))
            .collect()
    };
    let mut out = vec![Fp3::ZERO; m.shape().constraints];
    let mut bad = Vec::new();
    for r in 0..rows {
        let (local, next) = (row(r), row((r + 1) % rows));
        let publics: Vec<Fp3> = pubs.iter().map(|p| p[r]).collect();
        m.eval(
            &Vals {
                local: &local,
                next: &next,
                publics: &publics,
            },
            &ch,
            &mut out,
        );
        bad.extend(
            out.iter()
                .enumerate()
                .filter(|(_, x)| **x != Fp3::ZERO)
                .map(|(c, _)| (r, c)),
        );
    }
    bad
}

fn forged(f: Forge, prog: &N, input: &[u64], hints: &Hints<'_>) -> Run {
    FORGE.with(|c| c.set(f));
    let run = execute_hinted(prog, input, 1 << 30, SEGMENT_LOG_ROWS, hints);
    FORGE.with(|c| c.set(Forge::None));
    run.unwrap_or_else(|e| panic!("forged run {f:?}: {e:?}"))
}

fn rows_where(run: &Run, pred: impl Fn(&[Goldilocks]) -> bool) -> Vec<usize> {
    (0..run.trace.rows())
        .filter(|&r| pred(run.trace.row(r)))
        .collect()
}

fn wbit(run: &Run) -> Vec<usize> {
    let one = Goldilocks::ONE;
    rows_where(run, |r| r[K_AUX] == one && r[S_WBIT] == one)
}

fn output(run: &Run) -> N {
    statement::parse(&run.statement.output).unwrap()
}

/// The rows a forgery violates — exactly one, the attacked row.
fn only_row(run: &Run) -> usize {
    let v = violations(run, &run.trace);
    assert!(!v.is_empty(), "the forgery satisfies the relation");
    let row = v[0].0;
    assert!(v.iter().all(|&(r, _)| r == row), "violations {v:?}");
    row
}

#[test]
fn review_shl_by_32_or_more_cannot_claim_the_mod_32_shift() {
    // nox: shl(5, 33) = 0; the forgery claims 5·2^1 = 10 with z = 1
    let run = forged(
        Forge::ShlWrap,
        &op2(14, ax(2), ax(6)),
        &[33, 5],
        &Hints::default(),
    );
    assert_eq!(output(&run), a(10));
    let bits = wbit(&run);
    assert_eq!(
        only_row(&run),
        bits[5],
        "refused at cnt = 5 (z·(n >> 5) = 0)"
    );
    // n = 2^32 − 1 (a word, n mod 32 = 31)
    let run = forged(
        Forge::ShlWrap,
        &op2(14, ax(2), ax(6)),
        &[0xFFFF_FFFF, 1],
        &Hints::default(),
    );
    assert_eq!(output(&run), a(1 << 31));
    assert_eq!(only_row(&run), wbit(&run)[5]);
}

#[test]
fn review_word_operands_above_32_bits_have_no_peel() {
    let h = Hints::default();
    for prog in [
        op2(11, ax(2), ax(6)),
        op2(12, ax(2), ax(6)),
        op2(14, ax(2), ax(6)),
    ] {
        // first operand 2^32 + 5, then second operand 2^32 + 5
        for input in [[3u64, (1 << 32) + 5], [(1 << 32) + 5, 3]] {
            let run = forged(Forge::WordWide, &prog, &input, &h);
            assert_eq!(
                only_row(&run),
                *wbit(&run).last().unwrap(),
                "{prog:?} {input:?}"
            );
        }
    }
    let run = forged(Forge::WordWide, &op1(13, ax(2)), &[P - 1], &h);
    assert_eq!(output(&run), a(!(P - 1) & 0xFFFF_FFFF));
    assert_eq!(only_row(&run), *wbit(&run).last().unwrap());
}

#[test]
fn review_lt_second_operand_alias_violates_only_its_canonical_check() {
    // 5 < 3 + p: the alias flips lt(5, 3) from 1 to 0
    let run = forged(
        Forge::LtAliasW,
        &op2(10, q(5), q(3)),
        &[],
        &Hints::default(),
    );
    assert_eq!(output(&run), a(0));
    let row = only_row(&run);
    assert_eq!(row, *wbit(&run).last().unwrap());
}

#[test]
fn review_call_check_must_return_the_atom_zero() {
    let w = |_: u64, _: &N| Some(a(98));
    let h = Hints {
        witness: Some(&w),
        state: None,
    };
    // check: eq(witness, 99) returns 1 (unequal); the forgery accepts it
    let prog = op2(3, op2(16, q(7), op2(9, ax(2), q(99))), ax(1));
    let run = forged(Forge::CallAccept, &prog, &[1], &h);
    assert_eq!(output(&run), p(a(98), p(a(1), a(0))));
    let one = Goldilocks::ONE;
    let call2 = rows_where(&run, |r| r[K_RET] == one && r[F_CALL2] == one);
    assert_eq!(only_row(&run), call2[0]);
}

#[test]
fn review_look_under_another_root_is_refused_at_the_look_row() {
    let ev = StateEvidence::with_tables(vec![StateTable::with_body(0, &[11, 12, 13, 14])]);
    let root = ev.root().unwrap();
    let mut other = root;
    other[3] = (other[3] + 1) % P;
    // the subject carries `other`, the read is answered from `root`'s table
    let root_formula = op2(3, ax(2), op2(3, ax(6), op2(3, ax(14), ax(30))));
    let prog = op2(2, op2(3, root_formula, ax(1)), p(a(1), op2(17, q(0), q(3))));
    let h = Hints {
        witness: None,
        state: Some((&ev, root)),
    };
    let input = vec![other[3], other[2], other[1], other[0]];
    let run = forged(Forge::LookRoot, &prog, &input, &h);
    assert_eq!(output(&run), a(11));
    assert_eq!(run.statement.state.as_ref().unwrap().root, root);
    let one = Goldilocks::ONE;
    let lk = rows_where(&run, |r| r[K_AUX] == one && r[S_LOOK] == one);
    assert_eq!(only_row(&run), lk[0]);
}

/// Cells whose tamper must break the relation: the op chain EVAL → B1 →
/// B2W (each frame's tag carries the op), a witness pair pointing at itself
/// (a cycle), a join with a cell left below it, a 64th axis level.
#[test]
fn review_tampered_op_chain_witness_and_walk_cells() {
    let one = Goldilocks::ONE;
    let mut cases: Vec<(Run, crate::air::Trace)> = Vec::new();
    // xor → and: retag the B1 and B2W rows and the WBIT flags consistently
    let run = execute(&op2(11, ax(2), ax(6)), &[0x0F, 0xF0], 1 << 20).unwrap();
    let mut t = run.trace.clone();
    let b1 = rows_where(&run, |r| r[K_RET] == one && r[F_B1] == one)[0];
    let b2 = rows_where(&run, |r| r[K_RET] == one && r[F_B2W] == one)[0];
    t.row_mut(b1)[R_OP] = Goldilocks::new(12);
    t.row_mut(b2)[R_OP] = Goldilocks::new(12);
    for r in wbit(&run) {
        t.row_mut(r)[B_XOR] = Goldilocks::ZERO;
        t.row_mut(r)[B_AND] = one;
    }
    cases.push((run, t));
    // a witness pair whose left child is itself
    let w = |_: u64, _: &N| Some(p(a(3), a(4)));
    let h = Hints {
        witness: Some(&w),
        state: None,
    };
    let prog = op2(
        3,
        op2(16, q(7), op2(9, ax(2), p(a(1), p(a(3), a(4))))),
        ax(1),
    );
    let run = execute_hinted(&prog, &[1], 1 << 20, SEGMENT_LOG_ROWS, &h).unwrap();
    let wp = rows_where(&run, |r| r[K_AUX] == one && r[S_WPAIR] == one)[0];
    let mut t = run.trace.clone();
    t.row_mut(wp)[slot(2, P0)] = t.row(wp)[slot(2, KEY)];
    cases.push((run.clone(), t));
    // the join sees a stack of two cells (the pair's children, unpopped)
    let wj = rows_where(&run, |r| r[K_AUX] == one && r[S_WJOIN] == one)[0];
    let mut t = run.trace.clone();
    t.row_mut(wj)[W_SP] = t.row(wp)[W_SP];
    cases.push((run, t));
    // a 63-level walk's first row relabelled as level 63
    let mut noun = a(5);
    for k in 0..63 {
        noun = if ((P - 1) >> k) & 1 == 1 {
            p(a(0), noun)
        } else {
            p(noun, a(0))
        };
    }
    let run = execute(&op2(2, p(a(1), noun), p(a(1), ax(P - 1))), &[], 1 << 20).unwrap();
    let walk = rows_where(&run, |r| r[K_AXW] == one);
    assert_eq!(walk.len(), 63);
    let mut t = run.trace.clone();
    t.row_mut(walk[0])[A_CNT] = Goldilocks::new(63);
    cases.push((run, t));
    for (i, (run, t)) in cases.iter().enumerate() {
        assert!(!violations(run, t).is_empty(), "case {i}");
    }
}

/// The relation has 604 constraints of degree ≤ 8: each constraint along a
/// random line through (local, next, publics) is a polynomial whose 9th
/// finite difference vanishes.
#[test]
fn review_constraint_count_and_degree() {
    let run = execute(&op2(5, ax(2), q(1)), &[3], 1 << 20).unwrap();
    let m = run.machine(0);
    let k = m.shape().constraints;
    assert_eq!(k, 604);
    assert_eq!(m.shape().degree, 8);
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        Goldilocks::new(seed % P)
    };
    let mut fp3 = || Fp3::new(rnd(), rnd(), rnd());
    let w = W1 + W2;
    let np = air::PUBLICS;
    let base: Vec<Fp3> = (0..2 * w + np).map(|_| fp3()).collect();
    let dir: Vec<Fp3> = (0..2 * w + np).map(|_| fp3()).collect();
    let ch = [fp3(), fp3()];
    let pts = 12usize;
    let mut evals = vec![vec![Fp3::ZERO; k]; pts];
    for (t, ev) in evals.iter_mut().enumerate() {
        let tt = Fp3::from_base(Goldilocks::new(t as u64));
        let x: Vec<Fp3> = base.iter().zip(&dir).map(|(&b, &d)| b + tt * d).collect();
        m.eval(
            &Vals {
                local: &x[..w],
                next: &x[w..2 * w],
                publics: &x[2 * w..],
            },
            &ch,
            ev,
        );
    }
    let mut worst = (0, 0);
    for c in 0..k {
        let mut col: Vec<Fp3> = evals.iter().map(|e| e[c]).collect();
        let mut deg = None;
        for d in 0..pts - 1 {
            if col.iter().all(|&x| x == col[0]) {
                deg = Some(d);
                break;
            }
            col = col.windows(2).map(|w| w[1] - w[0]).collect();
        }
        let deg = deg.unwrap_or(pts);
        assert!(deg <= 8, "constraint {c} has degree {deg}");
        if deg > worst.0 {
            worst = (deg, c);
        }
    }
    println!("max degree {} (constraint {})", worst.0, worst.1);
}

/// Every new row kind (WBIT, AXW, witness, LOOK) crosses a segment
/// boundary in a 2^6-row segmentation; the proof verifies with the
/// evidence, and a forged boundary row inside a WBIT run is refused.
#[test]
fn review_new_row_kinds_cross_segment_boundaries() {
    let whir = super::tests::test_whir();
    let ev = StateEvidence::with_tables(vec![StateTable::with_body(0, &[11, 12, 13, 14])]);
    let root = ev.root().unwrap();
    let w = |_: u64, _: &N| Some(p(a(6), a(7)));
    let h = Hints {
        witness: Some(&w),
        state: Some((&ev, root)),
    };
    let mut leaf = a(5);
    for k in 0..40 {
        leaf = if (((1u64 << 40) + 0x1234_5678) >> k) & 1 == 1 {
            p(a(0), leaf)
        } else {
            p(leaf, a(0))
        };
    }
    let body = op2(
        3,
        op2(10, op2(17, q(0), q(3)), op2(14, op2(11, q(3), q(5)), q(2))),
        op2(
            3,
            op2(16, q(1), op2(9, ax(5), q(7))),
            op2(
                3,
                op1(13, op2(12, q(0xFF), q(0x0F))),
                op2(2, p(a(1), leaf), p(a(1), ax((1u64 << 40) + 0x1234_5678))),
            ),
        ),
    );
    let root_formula = op2(3, ax(2), op2(3, ax(6), op2(3, ax(14), ax(30))));
    let prog = op2(2, op2(3, root_formula, ax(1)), p(a(1), body));
    let input = vec![root[3], root[2], root[1], root[0]];
    let run = execute_hinted(&prog, &input, 1 << 30, 6, &h).unwrap();
    assert_eq!(run.seg_log, 6);
    let segs = run.segments();
    assert!(segs > 4, "{segs} segments");
    let one = Goldilocks::ONE;
    // the first row of a segment continues a run of each kind
    let first = |pred: &dyn Fn(&[Goldilocks]) -> bool| {
        (1..segs).any(|s| {
            let (prev, cur) = (run.trace.row(s * 64 - 1), run.trace.row(s * 64));
            pred(prev) && pred(cur)
        })
    };
    assert!(first(&|r| r[K_AUX] == one && r[S_WBIT] == one), "WBIT");
    assert!(first(&|r| r[K_AXW] == one), "AXW");
    let st = run.statement.clone();
    let proof = prove_run(&run, &whir).unwrap();
    verify_with_state(&st, &proof, &whir, Some(&ev)).unwrap();
    // a forged boundary: flip the remainder of a WBIT row that opens a segment
    let s = (1..segs)
        .find(|&s| {
            let r = run.trace.row(s * 64);
            r[K_AUX] == one && r[S_WBIT] == one && r[B_FIRST] != one
        })
        .expect("a segment opening inside a WBIT run");
    let mut bad = run.clone();
    bad.trace.row_mut(s * 64)[G_R0] += one;
    let forged = prove_run(&bad, &whir);
    assert!(forged.is_err() || verify_with_state(&st, &forged.unwrap(), &whir, Some(&ev)).is_err());
}
