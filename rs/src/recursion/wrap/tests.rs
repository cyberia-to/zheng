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
