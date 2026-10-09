//! The recursion circuit's program: verify the previous step from the
//! state it started at, select the initial state in the base step, and
//! output the new state's digest as the step's public input.

use nebu::{Fp3, Goldilocks};

use super::acc::AccProof;
use super::ops::Ops;
use super::params::{BV, Params};
use super::relation::{COLS, PUB_NOX, PUB_V};
use super::sponge::Sponge;
use super::perm::tag;
use super::state::{self, CtxParts, State, StateV};
use super::step::{self, StepProof};
use super::word::LeafOpening;
use crate::machine::layout::{W1, W2};

/// Run the program: `prev` (the state the previous step started from) and
/// its proof; `parts` the context's parts (used by the base step). Returns
/// the new state and its digest; the digest's chain is the output row.
pub fn run<O: Ops>(
    o: &mut O,
    p: &Params,
    live: O::V,
    prev: &State,
    proof: &StepProof,
    parts: &CtxParts,
    mark: impl FnOnce(&mut O, &O::Chain),
) -> (StateV<O::V>, [O::V; 4]) {
    let (st, x) = state::absorb_free(o, &p.dims, prev);
    let verified = step::verify(o, p, &st, x, proof);
    let w4 = |o: &mut O, d: [Goldilocks; 4]| -> [O::V; 4] { core::array::from_fn(|i| o.witness(Fp3::from_base(d[i]))) };
    let sd = w4(o, parts.statement);
    let ch = w4(o, parts.chain);
    let g0 = o.witness(parts.g0);
    let pn0 = o.witness(parts.pn0);
    let pv0 = o.witness(parts.pv0);
    let ctx = state::ctx_digest(o, sd, ch, g0, pn0, pv0);
    let init = state::init(o, &p.dims, ctx, p.zero_root, g0, pn0, pv0);
    let out = state::select(o, live, &init, &verified);
    let mut sp = Sponge::new(o, tag::STATE);
    for (v, ext) in out.items() {
        if ext {
            sp.absorb_ext(o, v);
        } else {
            sp.absorb(o, v);
        }
    }
    let d: Vec<O::V> = (0..4).map(|_| sp.squeeze(o)).collect();
    mark(o, &sp.chain);
    (out, [d[0], d[1], d[2], d[3]])
}

/// A state of the right shape (values irrelevant: the base step's input).
pub fn dummy_state(p: &Params) -> State {
    let z = Fp3::ZERO;
    let one = Fp3::ONE;
    let d = &p.dims;
    let mut o = super::ops::Native::new();
    let mut st = state::init(&mut o, d, [z; 4], p.zero_root, z, z, z);
    st.acc.spot = vec![(one, z); d.spot];
    st
}

/// A step proof of the right shape (the base step verifies it with every
/// assertion off).
pub fn dummy_proof(p: &Params) -> StepProof {
    let z = Fp3::ZERO;
    let g = Goldilocks::ZERO;
    let width = 1usize << p.cfg.layout.log_width;
    let depth = p.cfg.layout.log_leaves() as usize;
    let leaf = LeafOpening { symbols: vec![z; width], path: vec![[g; 4]; depth], leaf: None };
    StepProof {
        roots: [[g; 4]; 3],
        ood: core::array::from_fn(|_| vec![z; p.fresh]),
        b_in: vec![g; W1 + W2],
        b_out: vec![g; W1 + W2],
        b_v: vec![g; BV],
        zerocheck: vec![vec![z; p.zc_deg()]; p.n],
        local: vec![z; COLS],
        next: vec![z; COLS],
        pub_nox: vec![z; PUB_NOX],
        pub_v: vec![z; PUB_V],
        fold_g: vec![z; p.g_deg - 1],
        fold_pn: vec![z; p.pn_deg - 1],
        fold_pv: vec![z; p.pv_deg - 1],
        shift: vec![z; 2 * p.n],
        vals: [z; 3],
        acc: AccProof {
            sumcheck: vec![z; 2 * p.vars],
            evals: vec![z; 4],
            comb_nonce: 0,
            root: [g; 4],
            ood: vec![z; p.cfg.ood],
            query_nonce: 0,
            openings: vec![vec![leaf; 4]; p.cfg.queries],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::circuit::builder::Builder;

    #[test]
    #[ignore = "sizes the circuit at the shipped parameters (slow)"]
    fn circuit_size_at_the_shipped_parameters() {
        let whir = crate::execution::succinct::params_for(20);
        for (rate, n) in [(4u8, 15usize), (6, 15)] {
            let mut w = whir;
            w.log_inv_rate = rate;
            let p = Params::new(&w, n).unwrap();
            let mut b = Builder::new(false);
            let live = b.live_var();
            let parts = CtxParts { statement: [Goldilocks::ZERO; 4], chain: [Goldilocks::ZERO; 4], g0: Fp3::ZERO, pn0: Fp3::ZERO, pv0: Fp3::ZERO };
            run(&mut b, &p, live, &dummy_state(&p), &dummy_proof(&p), &parts, |b, c| b.set_output(c));
            let blocks: usize = b.chains.iter().map(|c| c.blocks.len()).sum();
            eprintln!(
                "rate 1/{} n {n}: t {} s {} depth {} · gates {} ({} rows) · bits {} · blocks {} · rows {} of {}",
                1 << rate, p.cfg.queries, p.cfg.ood, p.cfg.layout.log_leaves(),
                b.gates.len(), b.gates.len().div_ceil(4), b.bits.len(), blocks, b.rows(), 1usize << n
            );
        }
    }
}
