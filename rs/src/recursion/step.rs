//! One step's proof and its verifier, written once over [`Ops`]: the
//! final verifier runs it natively, the next step runs it as the
//! recursion circuit (`specs/recursion.md` § step protocol).
//!
//! Transcript (duplex, tag `STEP`), in order:
//!
//! 1. the step's public input `x = H(state)`;
//! 2. word a (pre-committed nox phase 1): root, its OOD answers (points
//!    from its root alone, tag `PRE`); word b: root, `ζ`, answers;
//!    `(α_V, β_V)`; word c: root, `ζ`, answers;
//! 3. the nox boundary rows in and out, the circuit's first row;
//! 4. `τ`, the batching seeds; the zerocheck rounds (degree 9); every
//!    column at `ρ` and its successor, the publics at `ρ`;
//! 5. `γ_n`, `γ_v`; three line folds of the deferred claims (constraints,
//!    nox publics, circuit key), each its line polynomial at `2..=deg`
//!    and a challenge;
//! 6. the shift reduction of the three words to one point, their values,
//!    the boundary challenges;
//! 7. the accumulation step over (accumulator, a, b, c) ([`super::acc`]).

use nebu::{Fp3, Goldilocks};

use super::acc::{self, AccProof, ClaimRef, InstV};
use super::gm;
use super::ops::{Arith, Ops};
use super::params::{BV, CBITS, PN_COLS, Params, STEP_BITS};
use super::perm::tag;
use super::relation::{COLS, PUB_NOX, PUB_V, WORD};
use super::sponge::Sponge;
use super::state::{ClaimV, StateV};
use super::word::Digest;
use crate::machine::layout::{W1, W2};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepProof {
    pub roots: [Digest; 3],
    pub ood: [Vec<Fp3>; 3],
    /// nox columns of the segment's first row, of its successor; the
    /// circuit's first row (phase 1 ‖ phase 2).
    pub b_in: Vec<Goldilocks>,
    pub b_out: Vec<Goldilocks>,
    pub b_v: Vec<Goldilocks>,
    pub zerocheck: Vec<Vec<Fp3>>,
    pub local: Vec<Fp3>,
    pub next: Vec<Fp3>,
    pub pub_nox: Vec<Fp3>,
    pub pub_v: Vec<Fp3>,
    pub fold_g: Vec<Fp3>,
    pub fold_pn: Vec<Fp3>,
    pub fold_pv: Vec<Fp3>,
    pub shift: Vec<Fp3>,
    pub vals: [Fp3; 3],
    pub acc: AccProof,
}

/// The OOD points of a pre-committed word, from its root alone.
pub fn pre_points<O: Ops>(o: &mut O, root: [O::V; 4], s: usize) -> Vec<O::V> {
    let mut sp = Sponge::new(o, tag::PRE);
    sp.absorb_all(o, &root);
    sp.squeeze_exts(o, s)
}

/// The chain of pre-committed roots after one more.
pub fn chain_next<O: Ops>(o: &mut O, chain: [O::V; 4], root: [O::V; 4], answers: &[O::V]) -> [O::V; 4] {
    let mut sp = Sponge::new(o, tag::CHAIN);
    sp.absorb_all(o, &chain);
    sp.absorb_all(o, &root);
    sp.absorb_all_ext(o, answers);
    core::array::from_fn(|_| sp.squeeze(o))
}

/// The boundary row of word `w` from the nox part and the circuit row.
pub fn word_row<V: Copy>(w: usize, nox: &[V], bv: &[V], zero: V) -> Vec<V> {
    match w {
        0 => nox[..W1].to_vec(),
        1 => nox[W1..W1 + W2].iter().chain(&bv[..WORD - W2]).copied().collect(),
        _ => bv[WORD - W2..].iter().copied().chain(core::iter::repeat(zero)).take(WORD).collect(),
    }
}

/// Fold a deferred claim with a new one along their line.
fn fold<O: Ops>(o: &mut O, t: &mut Sponge<O>, old: &ClaimV<O::V>, point: &[O::V], value: O::V, evals: &[Fp3], deg: usize) -> ClaimV<O::V> {
    assert_eq!(evals.len() + 1, deg, "fold: line polynomial");
    assert_eq!(point.len(), old.point.len(), "fold: dimension");
    let mut h = vec![old.value, value];
    h.extend(evals.iter().map(|&e| t.absorb_free_ext(o, e)));
    let r = t.squeeze_ext(o);
    let value = gm::interpolate(o, &h, r);
    let point = old.point.iter().zip(point).map(|(&a, &b)| o.lerp(r, a, b)).collect();
    ClaimV { point, value }
}

fn bind<O: Ops>(o: &mut O, t: &mut Sponge<O>, answers: &[Fp3], vars: usize) -> Vec<ClaimRef<O::V>> {
    let _ = vars;
    answers
        .iter()
        .map(|&y| {
            let z = t.squeeze_ext(o);
            let yv = t.absorb_free_ext(o, y);
            ClaimRef::Uni(z, yv)
        })
        .collect()
}

/// Verify step `st.step` against the state it started from (`x` its
/// digest); returns the state after it.
pub fn verify<O: Ops>(o: &mut O, p: &Params, st: &StateV<O::V>, x: [O::V; 4], pf: &StepProof) -> StateV<O::V> {
    let n = p.n;
    shape(p, pf);
    let mut t = Sponge::new(o, tag::STEP);
    t.absorb_all(o, &x);
    // words
    let root_a: [O::V; 4] = core::array::from_fn(|i| t.absorb_free(o, pf.roots[0][i]));
    let ans_a: Vec<O::V> = pf.ood[0].iter().map(|&y| t.absorb_free_ext(o, y)).collect();
    let za = pre_points(o, root_a, p.fresh);
    let ood_a: Vec<ClaimRef<O::V>> = za.iter().zip(&ans_a).map(|(&z, &y)| ClaimRef::Uni(z, y)).collect();
    let chain = chain_next(o, st.chain, root_a, &ans_a);
    let root_b: [O::V; 4] = core::array::from_fn(|i| t.absorb_free(o, pf.roots[1][i]));
    let ood_b = bind(o, &mut t, &pf.ood[1], p.vars);
    let ch_v = [t.squeeze_ext(o), t.squeeze_ext(o)];
    let root_c: [O::V; 4] = core::array::from_fn(|i| t.absorb_free(o, pf.roots[2][i]));
    let ood_c = bind(o, &mut t, &pf.ood[2], p.vars);
    let b_in: Vec<O::V> = pf.b_in.iter().map(|&b| t.absorb_free(o, b)).collect();
    let b_out: Vec<O::V> = pf.b_out.iter().map(|&b| t.absorb_free(o, b)).collect();
    let b_v: Vec<O::V> = pf.b_v.iter().map(|&b| t.absorb_free(o, b)).collect();
    let tau = t.squeeze_exts(o, n);
    let seeds = t.squeeze_exts(o, p.seeds());
    // zerocheck
    let mut claim = o.zero();
    let mut rho = Vec::with_capacity(n);
    for msg in &pf.zerocheck {
        let m: Vec<O::V> = msg.iter().map(|&h| t.absorb_free_ext(o, h)).collect();
        let a = t.squeeze_ext(o);
        let h1 = o.sub(claim, m[0]);
        let mut h = vec![m[0], h1];
        h.extend_from_slice(&m[1..]);
        claim = gm::interpolate(o, &h, a);
        rho.push(a);
    }
    let local: Vec<O::V> = pf.local.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    let next: Vec<O::V> = pf.next.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    let pub_nox: Vec<O::V> = pf.pub_nox.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    let pub_v: Vec<O::V> = pf.pub_v.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    let e_out = gm::eq_row(o, p.out_row, &rho);
    let pin: Vec<O::V> = x.iter().map(|&xj| o.mul(e_out, xj)).collect();
    let e = gm::eq(o, &tau, &rho);
    let einv = o.inv(e, "eq(τ, ρ) is invertible");
    let c = o.mul(claim, einv);
    // deferred claims
    let gamma_n = t.squeeze_exts(o, PN_COLS);
    let gamma_v = t.squeeze_exts(o, super::circuit::layout::pre::LOG);
    let mut point_g = Vec::with_capacity(p.dims.g);
    for v in [&local, &next, &pub_nox, &pub_v, &pin] {
        point_g.extend_from_slice(v);
    }
    point_g.extend_from_slice(&ch_v);
    point_g.extend_from_slice(&seeds);
    let g = fold(o, &mut t, &st.g, &point_g, c, &pf.fold_g, p.g_deg);
    let step_bits = o.bits(st.step, STEP_BITS);
    let point_n: Vec<O::V> = rho.iter().chain(&step_bits).chain(&gamma_n).copied().collect();
    let vn = gm::mle(o, &pub_nox, &gamma_n);
    let pn = fold(o, &mut t, &st.pn, &point_n, vn, &pf.fold_pn, p.pn_deg);
    let point_v: Vec<O::V> = rho.iter().chain(&gamma_v).copied().collect();
    let vv = gm::mle(o, &pub_v, &gamma_v);
    let pv = fold(o, &mut t, &st.pv, &point_v, vv, &pf.fold_pv, p.pv_deg);
    // shift: the three words' local and successor claims to one point
    let gs: Vec<Vec<O::V>> = (0..3).map(|_| t.squeeze_exts(o, CBITS)).collect();
    let beta = t.squeeze_ext(o);
    let zeta = t.squeeze_ext(o);
    let last = gm::product(o, &rho);
    let zero = o.zero();
    let mut sigma: Option<O::V> = None;
    let zp = gm::powers(o, zeta, 3);
    for w in 0..3 {
        let lw = &local[WORD * w..WORD * (w + 1)];
        let nw = &next[WORD * w..WORD * (w + 1)];
        let bw = word_row(w, &b_out, &b_v, zero);
        let a = gm::mle(o, lw, &gs[w]);
        let nn = gm::mle(o, nw, &gs[w]);
        let bb = gm::mle(o, &bw, &gs[w]);
        let lb = o.mul(last, bb);
        let nx = o.sub(nn, lb);
        let s = o.mul_add(beta, nx, a);
        sigma = Some(match sigma {
            None => s,
            Some(acc) => o.mul_add(zp[w], s, acc),
        });
    }
    let mut claim = sigma.expect("three words");
    let mut rho2 = Vec::with_capacity(n);
    for pair in pf.shift.chunks_exact(2) {
        let h0 = t.absorb_free_ext(o, pair[0]);
        let h2 = t.absorb_free_ext(o, pair[1]);
        let a = t.squeeze_ext(o);
        let h1 = o.sub(claim, h0);
        claim = gm::quadratic(o, h0, h1, h2, a);
        rho2.push(a);
    }
    let vals: Vec<O::V> = pf.vals.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    // k = eq(ρ, ρ2) + β·(nxt(ρ, ρ2) − Π ρ_i(1 − ρ2_i))
    let eqr = gm::eq(o, &rho, &rho2);
    let nxt = gm::next_eval(o, &rho, &rho2);
    let mut wrap: Option<O::V> = None;
    for (&a, &b) in rho.iter().zip(&rho2) {
        let g = super::ops::Gate { qm: -Fp3::ONE, qa: Fp3::ONE, ..Default::default() };
        let f = o.gate(g, a, b, b);
        wrap = Some(match wrap {
            None => f,
            Some(w) => o.mul(w, f),
        });
    }
    let d = o.sub(nxt, wrap.expect("rows"));
    let k = o.mul_add(beta, d, eqr);
    let vz = gm::combine(o, &zp, &vals);
    let lhs = o.mul(k, vz);
    o.assert_eq(lhs, claim, "shift reduction");
    let own: Vec<ClaimRef<O::V>> = (0..3)
        .map(|w| ClaimRef::Multi(rho2.iter().chain(&gs[w]).copied().collect(), vals[w]))
        .collect();
    let gb: Vec<Vec<O::V>> = (0..3).map(|_| t.squeeze_exts(o, CBITS)).collect();
    let mut bnd = Vec::with_capacity(3);
    for (w, gw) in gb.iter().enumerate() {
        let bw = word_row(w, &b_in, &b_v, zero);
        let v = gm::mle(o, &bw, gw);
        let pt: Vec<O::V> = core::iter::repeat_n(zero, n).chain(gw.iter().copied()).collect();
        bnd.push(ClaimRef::Multi(pt, v));
    }
    // boundaries across steps
    let first = is_zero(o, st.step);
    let not_first = o.affine(-Fp3::ONE, first, Fp3::ONE);
    for (&bi, &bl) in b_in.iter().zip(&st.b_last) {
        let g = super::ops::Gate { qm: Fp3::ONE, qs: -Fp3::ONE, ..Default::default() };
        o.assert_gate(g, not_first, bi, bl, "boundary continuity");
    }
    let b_first: Vec<O::V> = st.b_first.iter().zip(&b_in).map(|(&f, &bi)| o.lerp(first, f, bi)).collect();
    // accumulation
    let mut words = Vec::with_capacity(4);
    words.push(st.acc.instance());
    for (w, (root, oods)) in [(root_a, ood_a), (root_b, ood_b), (root_c, ood_c)].into_iter().enumerate() {
        let mut claims = oods;
        claims.push(own[w].clone());
        claims.push(bnd[w].clone());
        words.push(InstV { root, ext: false, claims });
    }
    let acc = acc::verify(o, &p.cfg, &mut t, &words, &pf.acc);
    let step = o.affine(Fp3::ONE, st.step, Fp3::ONE);
    StateV { ctx: st.ctx, step, chain, b_first, b_last: b_out, acc, g, pn, pv }
}

/// `[x = 0]` with a checked inverse witness.
pub fn is_zero<O: Ops>(o: &mut O, x: O::V) -> O::V {
    let xv = o.value(x);
    let inv = o.witness(if xv == Fp3::ZERO { Fp3::ZERO } else { xv.inv() });
    let z = {
        let g = super::ops::Gate { qm: -Fp3::ONE, qk: Fp3::ONE, ..Default::default() };
        o.gate(g, x, inv, inv)
    };
    let g = super::ops::Gate { qm: Fp3::ONE, ..Default::default() };
    o.assert_gate(g, x, z, z, "is_zero");
    z
}

/// Panics on a proof of the wrong shape (callers check shapes first:
/// [`check_shape`]).
fn shape(p: &Params, pf: &StepProof) {
    check_shape(p, pf).expect("step proof shape");
}

pub fn check_shape(p: &Params, pf: &StepProof) -> Result<(), String> {
    let ok = pf.ood.iter().all(|a| a.len() == p.fresh)
        && pf.b_in.len() == W1 + W2
        && pf.b_out.len() == W1 + W2
        && pf.b_v.len() == BV
        && pf.zerocheck.len() == p.n
        && pf.zerocheck.iter().all(|m| m.len() == p.zc_deg())
        && pf.local.len() == COLS
        && pf.next.len() == COLS
        && pf.pub_nox.len() == PUB_NOX
        && pf.pub_v.len() == PUB_V
        && pf.fold_g.len() + 1 == p.g_deg
        && pf.fold_pn.len() + 1 == p.pn_deg
        && pf.fold_pv.len() + 1 == p.pv_deg
        && pf.shift.len() == 2 * p.n
        && pf.acc.sumcheck.len() == 2 * p.vars
        && pf.acc.evals.len() == 4
        && pf.acc.ood.len() == p.cfg.ood
        && pf.acc.comb_nonce < nebu::field::P
        && pf.acc.query_nonce < nebu::field::P
        && pf.acc.openings.len() == p.cfg.queries
        && pf.acc.openings.iter().all(|q| {
            q.len() == 4
                && q.iter().enumerate().all(|(i, l)| {
                    l.symbols.len() == 1 << p.cfg.layout.log_width
                        && l.path.len() == p.cfg.layout.log_leaves() as usize
                        && (i == 0 || l.symbols.iter().all(|s| s.c1 == Goldilocks::ZERO && s.c2 == Goldilocks::ZERO))
                })
        });
    if ok { Ok(()) } else { Err("recursion: step proof shape".into()) }
}
