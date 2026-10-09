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

/// Constraint violations on rows `rows` only (the rows a cell of row `r`
/// enters: `r − 1` through `next`, `r` through `local`).
fn breaks_at(air: &CircuitAir, t1: &Trace, t2: &Trace, p: &Pre, alpha: Fp3, beta: Fp3, rows: &[usize]) -> bool {
    let n = t1.rows();
    let lift = |t: &Trace, r: usize| -> Vec<Fp3> { t.row(r).iter().map(|&x| Fp3::from_base(x)).collect() };
    let mut buf = vec![Fp3::ZERO; air.constraints()];
    rows.iter().any(|&r| {
        let nx = (r + 1) % n;
        let (l1, l2, n1, n2) = (lift(t1, r), lift(t2, r), lift(t1, nx), lift(t2, nx));
        let pr = p.row(r);
        let mut s = Sink { buf: &mut buf, i: 0 };
        air.eval(&Row { l1: &l1, l2: &l2, n1: &n1, n2: &n2, p: &pr, pin: &[Fp3::ZERO; PIN], alpha, beta }, &mut s);
        buf.iter().any(|&v| v != Fp3::ZERO)
    })
}

/// The cells a row kind leaves free by design: unused gate operands and
/// unread free outputs, the decomposition's scratch columns outside their
/// phase, a block's root/direction cells when no root check or node
/// follows, padding. Everything else must be pinned by a constraint or by
/// memory.
fn free_by_design(p: &Pre, r: usize, c: usize) -> bool {
    let pr = p.row(r);
    let on = |k: usize| pr[k] == Fp3::ONE;
    if c == LIVE {
        return false;
    }
    if on(pre::ARITH) {
        let (g, k) = (c / 12, (c % 12) / 3);
        let unused = pr[pre::E + 4 * g + k] == Fp3::ZERO;
        return if k < 3 { unused } else { unused && pr[pre::gate(g, pre::QCOMP)] == Fp3::ZERO };
    }
    if let Some(ph) = (0..4).find(|&k| on(pre::BITS + k)) {
        return match c {
            c if c < BITS_ROW => false,
            BACC | BVAL => false,
            BLO => ph == 0,
            BMINV => ph != 3,
            BMAX => ph != 3,
            _ => true,
        };
    }
    if let Some(ph) = (0..4).find(|&k| on(pre::PERM + k)) {
        if ph < 3 || c < PRT {
            return false;
        }
        return match c {
            c if c < PRT + 4 => !on(pre::ROOTCHK),
            PBIT => !on(pre::NODE),
            _ => true,
        };
    }
    true
}

/// Every phase-1 and phase-2 cell of an honest run (arithmetic, a
/// transcript with wide and free lanes, a decomposition, a Merkle opening)
/// is tampered by one; the rows it enters or the memory must break unless
/// the cell is free by design. A cell no constraint reads would be a value
/// the prover sets at will under the native verifier's check.
#[test]
fn every_cell_the_circuit_reads_is_constrained() {
    let layout = lens::rspcs::whir::LeafLayout { log_domain: 8, log_width: 2 };
    let evals: Vec<Goldilocks> = (0..64u64).map(|i| Goldilocks::new(i * 5 + 2)).collect();
    let word = Word::commit_base(layout, &evals);
    let mut b = Builder::new(true);
    program(&mut b, &word, 11);
    b.finish().unwrap();
    let air = CircuitAir::default();
    let n = (b.rows() + 1).next_power_of_two().trailing_zeros() as usize;
    let (t1, p, _) = generate(&b, &air, n).unwrap();
    let (alpha, beta) = (e(77), e(78));
    let t2 = phase2(&t1, &p, alpha, beta);
    let rows = t1.rows();
    let mut free = Vec::new();
    let mut pinned = 0usize;
    for r in 0..rows {
        let around = [(r + rows - 1) % rows, r];
        for c in 0..V1 {
            let mut bad = t1.clone();
            bad.row_mut(r)[c] += Goldilocks::ONE;
            let t2b = phase2(&bad, &p, alpha, beta);
            if closing_sum(&t2b, &p) != Fp3::ZERO || breaks_at(&air, &bad, &t2b, &p, alpha, beta, &around) {
                pinned += 1;
            } else if !free_by_design(&p, r, c) {
                free.push((r, c));
            }
        }
        for c in 0..V2 {
            let mut bad = t2.clone();
            bad.row_mut(r)[c] += Goldilocks::ONE;
            let mem = p.row(r)[pre::MEM] == Fp3::ONE;
            if breaks_at(&air, &t1, &bad, &p, alpha, beta, &around) {
                pinned += 1;
            } else if mem || c >= SUM {
                free.push((r, V1 + c));
            }
        }
    }
    assert!(pinned > 1000, "{pinned} pinned cells");
    assert!(free.is_empty(), "unconstrained cells (row, col): {free:?}");
}

/// The decomposition gadget admits exactly the canonical bits: `v + p`
/// written in 64 bits (`hi = 2^32 − 1`, `lo ≠ 0`) satisfies every
/// accumulation constraint and is refused only by canonicity; a
/// non-boolean digit compensated by its neighbour (`3·1 + 1·2 = 5`) is
/// refused by booleanity.
#[test]
fn the_decomposition_refuses_non_canonical_and_non_boolean_digits() {
    let mut b = Builder::new(true);
    let v = b.witness(Fp3::from_base(Goldilocks::new(5)));
    b.bits(v, 0);
    let air = CircuitAir::default();
    let (t1, p, _) = generate(&b, &air, 4).unwrap();
    let (alpha, beta) = (e(5), e(6));
    let r0 = (0..t1.rows()).find(|&r| p.row(r)[pre::BITS] == Fp3::ONE).unwrap();
    let all: Vec<usize> = (0..t1.rows()).collect();
    let t2 = phase2(&t1, &p, alpha, beta);
    assert!(!breaks_at(&air, &t1, &t2, &p, alpha, beta, &all));
    let write = |t: &mut Trace, pattern: [[u64; 16]; 4]| {
        let mut acc = Goldilocks::ZERO;
        let mut lo = Goldilocks::ZERO;
        for (ph, digits) in pattern.iter().enumerate() {
            let row = t.row_mut(r0 + ph);
            let mut chunk = Goldilocks::ZERO;
            for (j, &d) in digits.iter().enumerate() {
                row[j] = Goldilocks::new(d);
                chunk += Goldilocks::new(d) * Goldilocks::new(1 << j);
            }
            acc += chunk * Goldilocks::new(1u64 << (16 * ph));
            row[BACC] = acc;
            if ph == 1 {
                lo = acc;
            }
            if ph >= 1 {
                row[BLO] = lo;
            }
            if ph == 3 {
                let hi = (acc - lo) * Goldilocks::new(1 << 32).inv();
                let d = hi - Goldilocks::new(0xFFFF_FFFF);
                row[BMAX] = if d == Goldilocks::ZERO { Goldilocks::ONE } else { Goldilocks::ZERO };
                row[BMINV] = if d == Goldilocks::ZERO { Goldilocks::ZERO } else { d.inv() };
            }
        }
    };
    let digits = |x: u64| -> [[u64; 16]; 4] { core::array::from_fn(|ph| core::array::from_fn(|j| (x >> (16 * ph + j)) & 1)) };
    // v + p = 2^64 − 2^32 + 6
    let mut t = t1.clone();
    write(&mut t, digits(5u64.wrapping_add(0xFFFF_FFFF_0000_0001)));
    let t2 = phase2(&t, &p, alpha, beta);
    assert!(!breaks_at(&air, &t, &t2, &p, alpha, beta, &[r0, r0 + 1]), "the accumulation rows hold");
    assert!(breaks_at(&air, &t, &t2, &p, alpha, beta, &[r0 + 2, r0 + 3]), "canonicity refuses v + p");
    // 5 = 3·1 + 1·2
    let mut t = t1.clone();
    let mut d = digits(5);
    d[0][0] = 3;
    d[0][1] = 1;
    d[0][2] = 0;
    write(&mut t, d);
    let t2 = phase2(&t, &p, alpha, beta);
    assert!(breaks_at(&air, &t, &t2, &p, alpha, beta, &[r0]), "booleanity refuses a digit 3");
    assert!(!breaks_at(&air, &t, &t2, &p, alpha, beta, &[r0 + 1, r0 + 2, r0 + 3]));
}
