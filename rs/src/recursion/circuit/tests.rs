use nebu::{Fp3, Goldilocks};

use super::air::{CircuitAir, Row, Sink};
use super::builder::Builder;
use super::layout::*;
use super::trace::{Pre, closing_sum, generate, phase2};
use crate::air::Trace;
use crate::recursion::ops::{Arith, Native, Ops};
use crate::recursion::perm::tag;
use crate::recursion::sponge::Sponge;
use crate::recursion::word::{Word, verify_leaf};

fn e(i: u64) -> Fp3 {
    Fp3::new(Goldilocks::new(i * 7 + 1), Goldilocks::new(i + 11), Goldilocks::new(3 * i))
}

/// A little verifier: arithmetic, a transcript, bits, a Merkle opening.
fn program<O: Ops>(o: &mut O, word: &Word, leaf: usize) -> Vec<Fp3> {
    let a = o.witness(e(1));
    let b = o.witness(e(2));
    let c = o.mul_add(a, b, a);
    let d = o.lerp(c, a, b);
    let mut sp = Sponge::new(o, tag::STEP);
    sp.absorb_ext(o, d);
    let f = sp.absorb_free_ext(o, e(5));
    let g = sp.absorb_free(o, Goldilocks::new(9));
    let ch = sp.squeeze_ext(o);
    let h = o.mul(ch, f);
    let h = o.add(h, g);
    o.assert_eq(h, h, "reflexive");
    let lim = sp.squeeze(o);
    let bits = o.bits(lim, 20);
    let s = o.sum(&bits);
    let inv = o.inv(ch, "nonzero");
    let one = o.mul(inv, ch);
    o.assert_const(one, Fp3::ONE, "inverse");
    // open `leaf` of `word`
    let op = word.open(leaf);
    let nb = op.path.len();
    let lb: Vec<O::V> = (0..nb)
        .map(|k| o.witness(Fp3::from_base(Goldilocks::new(((leaf >> k) & 1) as u64))))
        .collect();
    let root: [O::V; 4] = core::array::from_fn(|i| o.witness(Fp3::from_base(word.root()[i])));
    let syms = verify_leaf(o, word.is_ext(), &op, &lb, root, "root");
    let t = o.dot(&syms, &syms);
    vec![o.value(h), o.value(s), o.value(t)]
}

fn check_rows(air: &CircuitAir, t1: &Trace, t2: &Trace, p: &Pre, alpha: Fp3, beta: Fp3) -> Option<(usize, usize)> {
    let rows = t1.rows();
    let lift = |t: &Trace, r: usize| -> Vec<Fp3> { t.row(r).iter().map(|&x| Fp3::from_base(x)).collect() };
    let mut buf = vec![Fp3::ZERO; air.constraints()];
    for r in 0..rows {
        let nx = (r + 1) % rows;
        let (l1, l2, n1, n2) = (lift(t1, r), lift(t2, r), lift(t1, nx), lift(t2, nx));
        let pr = p.row(r);
        let mut s = Sink { buf: &mut buf, i: 0 };
        air.eval(&Row { l1: &l1, l2: &l2, n1: &n1, n2: &n2, p: &pr, pin: &[Fp3::ZERO; PIN], alpha, beta }, &mut s);
        if let Some(c) = buf.iter().position(|&v| v != Fp3::ZERO) {
            return Some((r, c));
        }
    }
    None
}

#[test]
fn a_recorded_run_satisfies_the_circuit_and_agrees_with_native() {
    let layout = lens::rspcs::whir::LeafLayout { log_domain: 8, log_width: 2 };
    let evals: Vec<Goldilocks> = (0..64u64).map(|i| Goldilocks::new(i * 5 + 2)).collect();
    let word = Word::commit_base(layout, &evals);
    let mut nat = Native::new();
    let want = program(&mut nat, &word, 11);
    nat.finish().unwrap();
    let mut b = Builder::new(true);
    let got = program(&mut b, &word, 11);
    b.finish().unwrap();
    assert_eq!(got, want);
    let air = CircuitAir::default();
    let n = (b.rows() + 1).next_power_of_two().trailing_zeros() as usize;
    let (t1, p, _) = generate(&b, &air, n).unwrap();
    let (alpha, beta) = (e(77), e(78));
    let t2 = phase2(&t1, &p, alpha, beta);
    assert_eq!(closing_sum(&t2, &p), Fp3::ZERO, "memory closes");
    assert_eq!(check_rows(&air, &t1, &t2, &p, alpha, beta), None);
    // the same program on other data has the same key
    let mut b2 = Builder::new(true);
    program(&mut b2, &word, 40);
    let (_, p2, _) = generate(&b2, &air, n).unwrap();
    assert_eq!(p.digest(), p2.digest());
    // a tampered cell violates the circuit (or the memory)
    for (r, c) in [(0usize, gate_out(0)), (b.gates.len() / 4 + 1, BACC), (b.rows() - 1, PY8), (b.rows() - 3, PW + 2)] {
        let mut bad = t1.clone();
        bad.row_mut(r)[c] += Goldilocks::ONE;
        let t2b = phase2(&bad, &p, alpha, beta);
        let broken = check_rows(&air, &bad, &t2b, &p, alpha, beta).is_some() || closing_sum(&t2b, &p) != Fp3::ZERO;
        assert!(broken, "tamper at row {r} col {c}");
    }
}

#[test]
fn a_failed_assertion_is_caught_unless_the_step_is_the_base() {
    let run = |live: bool| {
        let mut b = Builder::new(live);
        let x = b.witness(e(3));
        b.assert_const(x, e(4), "x = 4");
        let air = CircuitAir::default();
        let (t1, p, _) = generate(&b, &air, 3).unwrap();
        let t2 = phase2(&t1, &p, e(9), e(10));
        (b.finish(), check_rows(&air, &t1, &t2, &p, e(9), e(10)))
    };
    let (r, v) = run(true);
    assert!(r.is_err() && v.is_some());
    let (r, v) = run(false);
    assert!(r.is_ok() && v.is_none());
}
