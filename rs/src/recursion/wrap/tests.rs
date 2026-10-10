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
    for (rate, pow, n, mode, reads) in [(6u8, 24u8, 16usize, Mode::Inner, 0usize), (8, 30, 15, Mode::Inner, 0), (8, 30, 14, Mode::Final, 1 << 18)] {
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
