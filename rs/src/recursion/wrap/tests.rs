use nebu::{Fp3, Goldilocks};

use super::*;
use crate::recursion::circuit::builder::Builder;
use crate::recursion::ops::Ops;

#[test]
fn the_wrap_constraint_graph_compiles_to_the_circuit_constraints() {
    for mode in [Mode::Inner, Mode::Final] {
        graph_case(mode);
    }
}

fn graph_case(mode: Mode) {
    let air = CircuitAir::default();
    let (g, k) = g_graph(&air, mode);
    let w = View(&air, mode).width();
    let e = |i: u64| Fp3::new(Goldilocks::new(i * 7 + 1), Goldilocks::new(i * i + 11), Goldilocks::new(3 * i + 2));
    let x: Vec<Fp3> = (0..g_inputs(w) as u64).map(e).collect();
    let mut out = vec![Fp3::ZERO; k];
    let (local, rest) = x.split_at(w);
    let (next, rest) = rest.split_at(w);
    let (pubs, rest) = rest.split_at(pre::COUNT + PIN);
    View(&air, mode).eval_with(local, next, pubs, rest[0], rest[1], &mut out);
    let mut want = Fp3::ZERO;
    let mut m = Fp3::ONE;
    for c in out {
        want += m * c;
        m *= rest[2];
    }
    assert_eq!(g.eval(&x), vec![want]);
    let mut b = Builder::new(true);
    let ins: Vec<_> = x.iter().map(|&v| b.witness(v)).collect();
    let outs = crate::recursion::expr::compile(&mut b, &g, &ins);
    assert_eq!(b.value(outs[0]), want);
    eprintln!("wrap G ({mode:?}): {k} constraints, {} nodes, {} gates", g.nodes.len(), b.gates.len());
}

#[test]
fn every_ledger_row_of_the_wrap_profiles_reaches_128_bits() {
    let base = crate::execution::succinct::params_for(20);
    for (rate, pow, n, mode, reads) in [(4u8, 16u8, 16usize, Mode::Inner, 0usize), (6, 24, 16, Mode::Inner, 0), (8, 24, 15, Mode::Inner, 0), (8, 30, 14, Mode::Final, 1 << 18), (9, 24, 14, Mode::Final, 1 << 18)] {
        let mut whir = base;
        whir.log_inv_rate = rate;
        whir.pow_bits = pow;
        let params = WrapParams { whir, n, mode };
        let fresh = crate::accumulate::fresh_ood(&whir, n + CBITS).unwrap();
        let (groups, claims): (&[usize], usize) = if mode == Mode::Inner { (&[1, 1, 2], 2 * (fresh + 1) + 2) } else { (&[1], fresh + 3) };
        let cfg = whir::Config::derive(&whir, n + CBITS, groups, claims).unwrap();
        let constraints = View(&CircuitAir::default(), mode).constraints();
        for (name, bits) in ledger(&params, &cfg, constraints, reads) {
            eprintln!("rate 1/{} {mode:?}: {name:40} {bits:8.2}", 1u32 << rate);
            assert!(bits >= 128.0, "{name}: {bits}");
        }
    }
}

#[test]
fn a_coefficient_applies_as_the_field_product() {
    let e = |i: u64| Fp3::new(Goldilocks::new(i * 7 + 1), Goldilocks::new(i * i + 11), Goldilocks::new(3 * i + 2));
    let t = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
    for i in 0..5 {
        let v = e(i);
        for c in [Fp3::ONE, t, t * t, e(9)] {
            assert_eq!(Coef::of(c).apply(v), c * v);
        }
    }
    assert_eq!(Coef::of(t), Coef::T);
    assert_eq!(Coef::of(t * t), Coef::T2);
}

/// The shipped chain's outermost proof is ≤ 64 KiB over every transcript
/// (a hard bound from the key's shapes, not a measurement), and the bound
/// is tight: a proof whose queries share no Merkle node reaches it.
#[test]
fn the_shipped_final_proof_is_at_most_64_kib_over_every_transcript() {
    use crate::recursion::ivc;
    let mut whir = crate::execution::succinct::params_for(20);
    whir.log_inv_rate = 4;
    whir.pow_bits = ivc::SHIPPED_POW;
    let ikey = ivc::key(&whir, 15).unwrap();
    let mut prev: Option<WrapKey> = None;
    for l in super::SHIPPED.split(',') {
        let mut parts = l.split(':');
        let head = parts.next().unwrap();
        let (rate, mode) = head.split_at(head.len() - 1);
        let mut w = whir;
        w.log_inv_rate = rate.parse().unwrap();
        w.pow_bits = parts.next().unwrap().parse().unwrap();
        let params = WrapParams { whir: w, n: 0, mode: if mode == "f" { Mode::Final } else { Mode::Inner } };
        prev = Some(match &prev {
            None => super::derive_shape_ivc(params, &ikey).unwrap(),
            Some(p) => super::derive_shape(params, p).unwrap(),
        });
    }
    let k = prev.unwrap();
    let max = super::max_proof_bytes(&k);
    eprintln!("shipped final proof ≤ {max} B");
    assert!(max <= super::MAX_FINAL_BYTES, "{max}");
}

/// The sibling bound is exact: leaves spread over distinct subtrees at
/// every level reach it.
#[test]
fn the_size_bound_is_the_worst_case_encoding() {
    use crate::recursion::whir::wire::max_siblings;
    use crate::recursion::word::Arity;
    // the sibling bound is reached by leaves spread over distinct subtrees
    for (q, d) in [(1usize, 5usize), (3, 6), (8, 10), (24, 25), (5, 3)] {
        // leaves in distinct subtrees at every level they can be
        let top = q.next_power_of_two().trailing_zeros() as usize;
        let spread: Vec<usize> = if top <= d { (0..q).map(|i| nebu::ntt::bit_reverse(i, top as u32) << (d - top)).collect() } else { (0..1 << d).collect() };
        let mut spread = spread;
        spread.sort_unstable();
        let q = spread.len();
        let mut known = spread.clone();
        let mut sib = 0;
        for _ in 0..d {
            let mut par: Vec<usize> = known.iter().map(|x| x / 2).collect();
            par.dedup();
            sib += 2 * par.len() - known.len();
            known = par;
        }
        assert_eq!(sib, max_siblings(q, d, Arity::Two), "{q} {d}");
    }
}
