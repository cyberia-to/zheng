//! Adversarial review of the wrap levels (`audit/wrap-review-2026-10.md`):
//! the final mode's linear wiring against the memory argument it
//! replaces, values the native verifier refuses against the circuit's
//! rows in both modes, the binding of a wrap key to the recursive proof
//! it was derived for, and the shipped profiles' ledger.

use nebu::{Fp3, Goldilocks};

use super::program::wiring;
use super::{Mode, Wiring, WrapParams, ledger};
use crate::air::Trace;
use crate::recursion::circuit::air::{CircuitAir, Row, Sink};
use crate::recursion::circuit::builder::Builder;
use crate::recursion::circuit::layout::*;
use crate::recursion::circuit::trace::{Pre, closing_sum, generate, phase2};
use crate::recursion::ops::{Arith, Native, Ops};
use crate::recursion::perm::tag;
use crate::recursion::sponge::Sponge;
use crate::recursion::word::{Arity, Word, verify_leaf};

fn e(i: u64) -> Fp3 {
    Fp3::new(Goldilocks::new(i * 7 + 1), Goldilocks::new(i + 11), Goldilocks::new(3 * i))
}

/// A verifier exercising every operation a wrap level records: gates,
/// free and wide sponge lanes, base and Fp3 outputs, a decomposition, an
/// inverse, a binary and a 4-ary Merkle opening.
fn program<O: Ops>(o: &mut O, w2: &Word, w4: &Word, leaf: usize) {
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
    let lim = sp.squeeze(o);
    let bits = o.bits(lim, 20);
    let s = o.sum(&bits);
    let inv = o.inv(ch, "nonzero");
    let one = o.mul(inv, ch);
    o.assert_const(one, Fp3::ONE, "inverse");
    let k = o.mul(s, h);
    o.assert_eq(k, k, "reflexive");
    for w in [w2, w4] {
        let op = w.open(leaf);
        let nb = w.layout.log_leaves() as usize;
        let lb: Vec<O::V> = (0..nb).map(|k| o.witness(Fp3::from_base(Goldilocks::new(((leaf >> k) & 1) as u64)))).collect();
        let root: [O::V; 4] = core::array::from_fn(|i| o.witness(Fp3::from_base(w.root()[i])));
        let syms = verify_leaf(o, w.is_ext(), w.arity, &op, &lb, root, "root");
        let t = o.dot(&syms, &syms);
        o.assert_eq(t, t, "reflexive");
    }
}

fn words() -> (Word, Word) {
    let layout = lens::rspcs::whir::LeafLayout { log_domain: 9, log_width: 2 };
    let evals: Vec<Goldilocks> = (0..128u64).map(|i| Goldilocks::new(i * 5 + 2)).collect();
    (Word::commit_base_a(layout, &evals, Arity::Two), Word::commit_base_a(layout, &evals, Arity::Four))
}

fn lift(t: &Trace, r: usize) -> Vec<Fp3> {
    t.row(r).iter().map(|&x| Fp3::from_base(x)).collect()
}

/// A local (non-memory) constraint of `rows` is violated.
fn local_breaks(air: &CircuitAir, t1: &Trace, p: &Pre, rows: &[usize]) -> bool {
    let n = t1.rows();
    let z2 = vec![Fp3::ZERO; V2];
    let mut buf = vec![Fp3::ZERO; air.local_constraints()];
    rows.iter().any(|&r| {
        let (l1, n1, pr) = (lift(t1, r), lift(t1, (r + 1) % n), p.row(r));
        let mut s = Sink { buf: &mut buf, i: 0 };
        let row = Row { l1: &l1, l2: &z2, n1: &n1, n2: &z2, p: &pr, pin: &[Fp3::ZERO; PIN], alpha: Fp3::ZERO, beta: Fp3::ZERO };
        air.eval_local(&row, &mut s);
        buf.iter().any(|&v| v != Fp3::ZERO)
    })
}

/// `u_λ` over the word's index `col·2^n + row` (as the prover's table).
fn u_table(w: &Wiring, n: usize, lambda: Fp3) -> Vec<Fp3> {
    let lp = w.powers(lambda);
    let ws = w.write_sums(&lp);
    let mut u = vec![Fp3::ZERO; super::WORD << n];
    for &(i, x, kc) in &w.read_cells {
        u[x as usize] += kc.apply(lp[i as usize]);
    }
    for &(j, x, kc) in &w.write_cells {
        u[x as usize] -= kc.apply(ws[j as usize]);
    }
    u
}

/// `⟨u_λ, W1⟩` over the phase-1 trace.
fn wiring_sum(u: &[Fp3], t1: &Trace) -> Fp3 {
    let rows = t1.rows();
    let mut acc = Fp3::ZERO;
    for r in 0..rows {
        for (c, &x) in t1.row(r).iter().enumerate() {
            acc += u[(c * rows) + r] * Fp3::from_base(x);
        }
    }
    acc
}

/// As `circuit::tests::free_by_design`: unused operands and unread free
/// outputs, scratch columns outside their phase, root and direction cells
/// where no root check or node follows, padding.
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
            BMINV | BMAX => ph != 3,
            _ => true,
        };
    }
    if let Some(ph) = (0..4).find(|&k| on(pre::PERM + k)) {
        if ph < 3 || c < PRT {
            return false;
        }
        return match c {
            c if c < PRT + 4 => !on(pre::ROOTCHK),
            PBIT => !on(pre::NODE) && !on(pre::NODE4),
            PBIT2 => !on(pre::NODE4),
            _ => true,
        };
    }
    true
}

/// The final mode replaces the memory argument by `⟨u_λ, W1⟩ = 0`. Every
/// read the circuit records is wired, an honest run satisfies the form,
/// and every phase-1 cell is pinned by a local constraint or by the
/// wiring exactly where the memory argument pinned it: a cell outside both
/// would be a value the final level's prover sets at will.
#[test]
fn the_linear_wiring_pins_every_cell_the_memory_argument_pins() {
    let (w2, w4) = words();
    let mut b = Builder::new(true);
    program(&mut b, &w2, &w4, 37);
    b.finish().unwrap();
    let mut nat = Native::new();
    program(&mut nat, &w2, &w4, 37);
    nat.finish().unwrap();
    let air = CircuitAir::default();
    let n = (b.rows() + 1).next_power_of_two().trailing_zeros() as usize;
    let (t1, p, _) = generate(&b, &air, n).unwrap();
    let w = wiring(&p);
    let reads: u32 = b.reads.iter().sum();
    assert_eq!(w.reads, reads as usize, "every recorded read is wired");
    let rows = t1.rows();
    for r in 0..rows {
        // the slot values are linear in the row's cells (no constant)
        let z = vec![Fp3::ZERO; V1];
        let v = crate::recursion::circuit::air::slot_values(&z, &p.row(r));
        assert!(v.iter().all(|&x| x == Fp3::ZERO), "row {r}: an affine slot value");
    }
    let u = u_table(&w, n, e(91));
    assert_eq!(wiring_sum(&u, &t1), Fp3::ZERO, "an honest run is wired");
    assert!(!local_breaks(&air, &t1, &p, &(0..rows).collect::<Vec<_>>()));
    let (alpha, beta) = (e(77), e(78));
    let t2 = phase2(&t1, &p, alpha, beta);
    assert_eq!(closing_sum(&t2, &p), Fp3::ZERO);
    let mut free = Vec::new();
    let mut weaker = Vec::new();
    let mut pinned = 0usize;
    for r in 0..rows {
        let around = [(r + rows - 1) % rows, r];
        for c in 0..V1 {
            let mut bad = t1.clone();
            bad.row_mut(r)[c] += Goldilocks::ONE;
            let wired = u[c * rows + r] != Fp3::ZERO;
            let local = local_breaks(&air, &bad, &p, &around);
            if wired || local {
                pinned += 1;
                continue;
            }
            if !free_by_design(&p, r, c) {
                free.push((r, c));
            }
            // the memory argument pins nothing the wiring leaves free
            let t2b = phase2(&bad, &p, alpha, beta);
            if closing_sum(&t2b, &p) != Fp3::ZERO {
                weaker.push((r, c));
            }
        }
    }
    assert!(pinned > 2000, "{pinned} pinned cells");
    assert!(free.is_empty(), "cells neither constrained nor wired (row, col): {free:?}");
    assert!(weaker.is_empty(), "cells the memory argument pins and the wiring does not: {weaker:?}");
}

/// The class of #53's finding: a value the native verifier refuses (an
/// Fp3 value where a base lane is read, a non-bit Merkle direction, a zero
/// inverse) must break the circuit's rows too — in the inner mode (memory
/// argument) and in the final mode (linear wiring) — when the value is
/// computed, so the prover cannot re-choose it.
#[test]
fn values_the_native_verifier_refuses_break_both_wrap_modes() {
    type Case = fn(&mut Builder) -> ();
    fn ext_value<O: Ops>(o: &mut O) -> O::V {
        let mut sp = Sponge::new(o, tag::STEP);
        sp.absorb_free_ext(o, e(3));
        sp.squeeze_ext(o)
    }
    fn native<F: Fn(&mut Native)>(f: F) -> bool {
        let mut o = Native::new();
        f(&mut o);
        o.finish().is_err()
    }
    // each case natively and in the circuit (written twice: closures are
    // not generic over the interpreter)
    let cases: Vec<(&str, Case, bool)> = vec![
        ("an Fp3 challenge absorbed as a base lane", |o| {
            let v = ext_value(o);
            let mut sp = Sponge::new(o, tag::PUBLIC);
            sp.absorb(o, v);
            sp.squeeze(o);
        }, native(|o| {
            let v = ext_value(o);
            let mut sp = Sponge::new(o, tag::PUBLIC);
            sp.absorb(o, v);
            sp.squeeze(o);
        })),
        ("bits of an Fp3 value", |o| {
            let v = ext_value(o);
            o.bits(v, 8);
        }, native(|o| {
            let v = ext_value(o);
            o.bits(v, 8);
        })),
        ("an Fp3 Merkle root", |o| {
            let v = ext_value(o);
            let mut c = o.chain(tag::LEAF);
            let z = o.zero();
            o.permute(&mut c, &[crate::recursion::ops::In::Var(z, true), crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero]);
            o.digest_eq(&c, [v, z, z, z], "root");
        }, native(|o| {
            let v = ext_value(o);
            let mut c = o.chain(tag::LEAF);
            let z = o.zero();
            o.permute(&mut c, &[crate::recursion::ops::In::Var(z, true), crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero, crate::recursion::ops::In::Zero]);
            o.digest_eq(&c, [v, z, z, z], "root");
        })),
        ("a Merkle direction 2", |o| {
            let one = o.one();
            let two = o.add(one, one);
            let mut sp = Sponge::new(o, tag::LEAF);
            sp.absorb(o, one);
            sp.flush(o);
            o.node(&mut sp.chain, two, [Goldilocks::ONE; 4]);
        }, native(|o| {
            let one = o.one();
            let two = o.add(one, one);
            let mut sp = Sponge::new(o, tag::LEAF);
            sp.absorb(o, one);
            sp.flush(o);
            o.node(&mut sp.chain, two, [Goldilocks::ONE; 4]);
        })),
        ("a 4-ary direction 2", |o| {
            let one = o.one();
            let two = o.add(one, one);
            let mut sp = Sponge::new(o, tag::LEAF);
            sp.absorb(o, one);
            sp.flush(o);
            o.node4(&mut sp.chain, [one, two], [[Goldilocks::ONE; 4]; 3]);
        }, native(|o| {
            let one = o.one();
            let two = o.add(one, one);
            let mut sp = Sponge::new(o, tag::LEAF);
            sp.absorb(o, one);
            sp.flush(o);
            o.node4(&mut sp.chain, [one, two], [[Goldilocks::ONE; 4]; 3]);
        })),
        ("the inverse of zero", |o| {
            let one = o.one();
            let z = o.sub(one, one);
            o.inv(z, "nonzero");
        }, native(|o| {
            let one = o.one();
            let z = o.sub(one, one);
            o.inv(z, "nonzero");
        })),
    ];
    let air = CircuitAir::default();
    for (what, case, refused_natively) in cases {
        assert!(refused_natively, "{what}: accepted natively");
        let mut b = Builder::new(true);
        case(&mut b);
        assert!(b.finish().is_err(), "{what}: the builder did not record it");
        let n = (b.rows() + 1).next_power_of_two().trailing_zeros().max(3) as usize;
        let (t1, p, _) = generate(&b, &air, n).unwrap();
        let all: Vec<usize> = (0..t1.rows()).collect();
        let local = local_breaks(&air, &t1, &p, &all);
        let (alpha, beta) = (e(5), e(6));
        let t2 = phase2(&t1, &p, alpha, beta);
        let memory = closing_sum(&t2, &p) != Fp3::ZERO;
        let wired = wiring_sum(&u_table(&wiring(&p), n, e(91)), &t1) != Fp3::ZERO;
        assert!(local || memory, "{what}: the inner mode accepts");
        assert!(local || wired, "{what}: the final mode accepts");
    }
}

/// The shipped chain's levels (`audit/wrap-fastverify-2026-10.md`:
/// `4i,8i,9f:24`, every level grinding at most 24 bits) reach 128 bits on
/// every row; the weakest row of each level and its interactive value
/// (every grinding removed: folds, queries, the combination) as printed
/// in the audit.
#[test]
fn the_shipped_wrap_levels_reach_128_bits_and_their_interactive_rows_are_stated() {
    let base = crate::execution::succinct::params_for(20);
    let mut weakest = Vec::new();
    for (rate, pow, n, mode, reads) in [(4u8, 24u8, 16usize, Mode::Inner, 0usize), (8, 24, 15, Mode::Inner, 0), (9, 24, 14, Mode::Final, 1 << 18)] {
        let mut whir = base;
        whir.log_inv_rate = rate;
        whir.pow_bits = pow;
        let params = WrapParams { whir, n, mode };
        let fresh = crate::accumulate::fresh_ood(&whir, n + super::CBITS).unwrap();
        let (groups, claims): (&[usize], usize) = if mode == Mode::Inner { (&[1, 1, 2], 2 * (fresh + 1) + 2) } else { (&[1], fresh + 3) };
        let cfg = crate::recursion::whir::Config::derive(&whir, n + super::CBITS, groups, claims).unwrap();
        let constraints = super::View(&CircuitAir::default(), mode).constraints();
        let rows = ledger(&params, &cfg, constraints, reads);
        let (name, bits) = rows.iter().cloned().fold((String::new(), f64::INFINITY), |a, r| if r.1 < a.1 { r } else { a });
        assert!(bits >= 128.0, "{rate} {mode:?}: {name} {bits}");
        // the grinding rounds without their grinding: the interactive bound
        let mut inter = f64::INFINITY;
        for (i, rd) in cfg.wc.rounds.iter().enumerate() {
            for (nm, b) in &rows {
                if *nm == format!("fold_{i}") {
                    inter = inter.min(b - f64::from(rd.fold_pow));
                }
                if i > 0 && *nm == format!("shift_{i}") {
                    inter = inter.min(b - f64::from(cfg.wc.rounds[i - 1].query_pow));
                }
            }
        }
        if let Some((_, b)) = rows.iter().find(|r| r.0 == "batch combine") {
            inter = inter.min(b - f64::from(cfg.comb_pow));
        }
        let last = cfg.wc.rounds.last().unwrap();
        if let Some((_, b)) = rows.iter().find(|r| r.0 == "fin") {
            inter = inter.min(b - f64::from(last.query_pow));
        }
        eprintln!("1/{} {mode:?} (pow {pow}, combination {}): weakest {name} {bits:.2}; interactive weakest {inter:.2}", 1u32 << rate, cfg.comb_pow);
        weakest.push((bits, inter));
    }
    // the final level (1/512, 24 bits): fold_1 at 128.40, 104.70
    // interactively; the inner levels 104.00 (1/16: the combination) and
    // 104.29 (1/256)
    assert!((weakest[2].0 - 128.40).abs() < 0.01, "{:?}", weakest[2]);
    assert!((weakest[2].1 - 104.70).abs() < 0.01, "{:?}", weakest[2]);
    assert!(weakest.iter().all(|w| w.1 >= 104.0), "{weakest:?}");
}

/// A wrap key is bound to the recursive proof it was derived for: the
/// outermost proof's header names the step size, and a statement prepared
/// under another (WHIR parameters, step size) is refused before anything
/// is evaluated. Before the review such a header was refused only because
/// the deferred nox-public claim, split at the header's `n + 32` instead
/// of the key's, happened not to evaluate to the carried value (and would
/// have panicked for a key more than five step bits below the header —
/// not reachable today: the step circuit needs `n ≥ 15`).
#[test]
fn a_final_proof_under_another_step_size_is_refused_by_its_key() {
    use crate::recursion::ivc;
    let mut whir = crate::execution::succinct::params_for(20);
    whir.log_inv_rate = 4;
    whir.pow_bits = 24;
    let ikey = ivc::key(&whir, 15).unwrap();
    let k = super::derive_key_ivc(WrapParams { whir, n: 0, mode: Mode::Final }, &ikey).unwrap();
    assert_eq!(k.ivc, (whir, 15));
    // a final-mode level is never verified by a circuit
    assert!(super::derive_key_wrap(WrapParams { whir, n: 0, mode: Mode::Inner }, &k).is_err());
    let (_, prog, input) = crate::machine::tests::programs().into_iter().find(|p| p.0 == "add").unwrap();
    let run = crate::machine::execute_exact(&prog, &input, 1 << 20, 16).unwrap();
    let st = run.statement;
    let derived = st.derive().unwrap();
    let start = (derived.entries.len() as u64 / 32 + 1) * 32;
    let fp = super::FinalProof {
        log_rows: 16,
        start,
        segments: 1,
        chain: [Goldilocks::ZERO; 4],
        pn: crate::recursion::state::ClaimV { point: vec![Fp3::ZERO; k.pn], value: Fp3::ZERO },
        wrap: super::program::dummy_proof(&k),
    };
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| super::verify_statement(&st, &whir, &k, &fp)));
    match r {
        Ok(Err(e)) => assert!(e.contains("another recursive proof"), "{e}"),
        Ok(Ok(())) => panic!("accepted"),
        Err(_) => panic!("the verifier panicked"),
    }
}
