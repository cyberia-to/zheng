//! The accumulation step of the recursion profile: the protocol of
//! `accumulate::step` (`specs/accumulation.md`) on the field-native
//! transcript and words, its verifier written over [`Ops`].
//!
//! Differences from `accumulate::step`, all forced by running the verifier
//! in the circuit: instances are not re-absorbed (the step transcript
//! already binds them: the state through the step's public input, the
//! fresh claims through the rounds that produced them); positions are
//! never deduplicated (each spot check opens its leaf in every word with a
//! full path); a spot claim keeps its point as `x = ω^s`.

use lens::rspcs::field::root_of_unity;
use nebu::Fp3;

use super::gm;
use super::ops::{Arith, Ops};
use super::sponge::Sponge;
use super::state::AccV;
use super::word::{Digest, LeafOpening, verify_leaf};
use crate::accumulate::AccConfig;

/// A claim on a word's message.
#[derive(Clone, Debug)]
pub enum ClaimRef<V> {
    /// `f(point) = value`.
    Multi(Vec<V>, V),
    /// `f(pow(x)) = value`.
    Uni(V, V),
}

impl<V: Copy> ClaimRef<V> {
    pub fn value(&self) -> V {
        match self {
            ClaimRef::Multi(_, v) | ClaimRef::Uni(_, v) => *v,
        }
    }
}

/// An input instance: root, symbol field, claims.
pub struct InstV<V> {
    pub root: [V; 4],
    pub ext: bool,
    pub claims: Vec<ClaimRef<V>>,
}

impl<V: Copy> AccV<V> {
    pub fn instance(&self) -> InstV<V> {
        let mut claims = vec![ClaimRef::Multi(self.rho.clone(), self.v0)];
        claims.extend(self.ood.iter().map(|&(z, y)| ClaimRef::Uni(z, y)));
        claims.extend(self.spot.iter().map(|&(x, y)| ClaimRef::Uni(x, y)));
        InstV { root: self.root, ext: true, claims }
    }
}

/// What an accumulation step sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccProof {
    pub sumcheck: Vec<Fp3>,
    pub evals: Vec<Fp3>,
    pub comb_nonce: u64,
    pub root: Digest,
    pub ood: Vec<Fp3>,
    pub query_nonce: u64,
    /// `openings[k][i]`: query `k`'s leaf in input word `i`.
    pub openings: Vec<Vec<LeafOpening>>,
}

fn free4<O: Ops>(o: &mut O, t: &mut Sponge<O>, d: Digest) -> [O::V; 4] {
    core::array::from_fn(|i| t.absorb_free(o, d[i]))
}

/// Verify one step over the inputs; returns the new accumulator.
pub fn verify<O: Ops>(o: &mut O, cfg: &AccConfig, t: &mut Sponge<O>, inputs: &[InstV<O::V>], pf: &AccProof) -> AccV<O::V> {
    let m = inputs.len();
    let vars = cfg.num_vars;
    assert!(pf.sumcheck.len() == 2 * vars && pf.evals.len() == m && pf.ood.len() == cfg.ood, "acc: proof shape");
    assert!(pf.openings.len() == cfg.queries && pf.openings.iter().all(|q| q.len() == m), "acc: openings");
    let gamma = t.squeeze_ext(o);
    let all: Vec<&ClaimRef<O::V>> = inputs.iter().flat_map(|i| &i.claims).collect();
    let gp = gm::powers(o, gamma, all.len());
    let vals: Vec<O::V> = all.iter().map(|c| c.value()).collect();
    let mut claim = gm::combine(o, &gp, &vals);
    let mut rho = Vec::with_capacity(vars);
    for pair in pf.sumcheck.chunks_exact(2) {
        let h0 = t.absorb_free_ext(o, pair[0]);
        let h2 = t.absorb_free_ext(o, pair[1]);
        let a = t.squeeze_ext(o);
        let h1 = o.sub(claim, h0);
        claim = gm::quadratic(o, h0, h1, h2, a);
        rho.push(a);
    }
    let mu: Vec<O::V> = pf.evals.iter().map(|&x| t.absorb_free_ext(o, x)).collect();
    let mut e = 0;
    let mut expect: Option<O::V> = None;
    for (inst, &mu_i) in inputs.iter().zip(&mu) {
        let mut w: Option<O::V> = None;
        for c in &inst.claims {
            let ev = match c {
                ClaimRef::Multi(z, _) => gm::eq(o, z, &rho),
                ClaimRef::Uni(x, _) => gm::eq_pow(o, *x, &rho),
            };
            w = Some(match w {
                None => o.mul(gp[e], ev),
                Some(a) => o.mul_add(gp[e], ev, a),
            });
            e += 1;
        }
        let w = w.expect("an instance has claims");
        expect = Some(match expect {
            None => o.mul(w, mu_i),
            Some(a) => o.mul_add(w, mu_i, a),
        });
    }
    o.assert_eq(expect.expect("inputs"), claim, "acc: sumcheck final claim");
    t.grind_check(o, cfg.comb_pow_for(m), pf.comb_nonce);
    let r = t.squeeze_ext(o);
    let coef = gm::powers(o, r, m);
    let v0 = gm::combine(o, &coef, &mu);
    let root = free4(o, t, pf.root);
    let mut ood = Vec::with_capacity(cfg.ood);
    for &y in &pf.ood {
        let z = t.squeeze_ext(o);
        let yv = t.absorb_free_ext(o, y);
        ood.push((z, yv));
    }
    t.grind_check(o, cfg.query_pow, pf.query_nonce);
    let log_domain = cfg.layout.log_domain as usize;
    let log_leaves = cfg.layout.log_leaves() as usize;
    let omega = root_of_unity(cfg.layout.log_domain);
    let idx = t.indices(o, cfg.queries, log_domain);
    let mut spot = Vec::with_capacity(cfg.queries);
    for (bits, ops) in idx.iter().zip(&pf.openings) {
        let mut y: Option<O::V> = None;
        for ((inst, op), &c) in inputs.iter().zip(ops).zip(&coef) {
            let syms = verify_leaf(o, inst.ext, op, &bits[..log_leaves], inst.root, "acc: opening");
            let u = gm::mux(o, &syms, &bits[log_leaves..]);
            y = Some(match y {
                None => o.mul(c, u),
                Some(a) => o.mul_add(c, u, a),
            });
        }
        let x = gm::pow_bits(o, omega, bits);
        spot.push((x, y.expect("inputs")));
    }
    AccV { root, rho, v0, ood, spot }
}
