//! The IVC state a step's verifier outputs and the next step's verifier
//! reads, its digest (the step's public input), the initial state and the
//! zero accumulator it starts from.
//!
//! ```text
//! ctx      digest of the statement, the pre-committed roots, the initial
//!          deferred values
//! step     steps verified so far (= index of the next segment)
//! chain    running digest of the verified steps' pre-committed roots
//! b_first  the first segment's first row (nox columns)
//! b_last   the last verified segment's successor row
//! acc      the accumulator: root, (ρ, v), OOD claims, spot claims (ω^s, y)
//! g pn pv  deferred claims: constraints, nox publics, circuit key
//! ```

use lens::rspcs::whir::LeafLayout;
use nebu::Fp3;

use super::ops::{Arith, Ops};
use super::perm::{self, tag};
use super::sponge::Sponge;
use super::word::{Digest, LeafOpening, leaf_digest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimV<V> {
    pub point: Vec<V>,
    pub value: V,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccV<V> {
    pub root: [V; 4],
    pub rho: Vec<V>,
    pub v0: V,
    pub ood: Vec<(V, V)>,
    /// `(ω^s, y)`: base point, Fp3 value.
    pub spot: Vec<(V, V)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateV<V> {
    pub ctx: [V; 4],
    pub step: V,
    pub chain: [V; 4],
    pub b_first: Vec<V>,
    pub b_last: Vec<V>,
    pub acc: AccV<V>,
    pub g: ClaimV<V>,
    pub pn: ClaimV<V>,
    pub pv: ClaimV<V>,
}

/// A state's values.
pub type State = StateV<Fp3>;

/// The sizes of a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dims {
    pub boundary: usize,
    pub vars: usize,
    pub ood: usize,
    pub spot: usize,
    pub g: usize,
    pub pn: usize,
    pub pv: usize,
}

impl<V: Copy> StateV<V> {
    /// Every element in hashing order, with its width (Fp3 or base).
    pub fn items(&self) -> Vec<(V, bool)> {
        let mut out = Vec::new();
        let base = |out: &mut Vec<(V, bool)>, v: V| out.push((v, false));
        let ext = |out: &mut Vec<(V, bool)>, v: V| out.push((v, true));
        for &v in &self.ctx {
            base(&mut out, v);
        }
        base(&mut out, self.step);
        for &v in &self.chain {
            base(&mut out, v);
        }
        for &v in self.b_first.iter().chain(&self.b_last) {
            base(&mut out, v);
        }
        for &v in &self.acc.root {
            base(&mut out, v);
        }
        for &v in &self.acc.rho {
            ext(&mut out, v);
        }
        ext(&mut out, self.acc.v0);
        for &(z, y) in &self.acc.ood {
            ext(&mut out, z);
            ext(&mut out, y);
        }
        for &(x, y) in &self.acc.spot {
            base(&mut out, x);
            ext(&mut out, y);
        }
        for c in [&self.g, &self.pn, &self.pv] {
            for &v in &c.point {
                ext(&mut out, v);
            }
            ext(&mut out, c.value);
        }
        out
    }

    /// Rebuild from items in [`Self::items`] order.
    pub fn from_items(d: &Dims, items: &[V]) -> Self {
        let mut it = items.iter().copied();
        let mut take = |k: usize| -> Vec<V> { (0..k).map(|_| it.next().expect("state item")).collect() };
        let four = |v: Vec<V>| -> [V; 4] { [v[0], v[1], v[2], v[3]] };
        let ctx = four(take(4));
        let step = take(1)[0];
        let chain = four(take(4));
        let b_first = take(d.boundary);
        let b_last = take(d.boundary);
        let root = four(take(4));
        let rho = take(d.vars);
        let v0 = take(1)[0];
        let ood = (0..d.ood).map(|_| { let v = take(2); (v[0], v[1]) }).collect();
        let spot = (0..d.spot).map(|_| { let v = take(2); (v[0], v[1]) }).collect();
        let mut claim = |k: usize| {
            let point = take(k);
            let value = take(1)[0];
            ClaimV { point, value }
        };
        let g = claim(d.g);
        let pn = claim(d.pn);
        let pv = claim(d.pv);
        Self { ctx, step, chain, b_first, b_last, acc: AccV { root, rho, v0, ood, spot }, g, pn, pv }
    }
}

/// The digest of a state (variables already computed).
pub fn digest<O: Ops>(o: &mut O, st: &StateV<O::V>) -> [O::V; 4] {
    let mut sp = Sponge::new(o, tag::STATE);
    for (v, ext) in st.items() {
        if ext {
            sp.absorb_ext(o, v);
        } else {
            sp.absorb(o, v);
        }
    }
    let d: Vec<O::V> = (0..4).map(|_| sp.squeeze(o)).collect();
    [d[0], d[1], d[2], d[3]]
}

/// Absorb a state the prover supplies; returns its variables, its digest
/// and the hashing chain (so the caller can mark it).
pub fn absorb_free<O: Ops>(o: &mut O, d: &Dims, st: &State) -> (StateV<O::V>, [O::V; 4]) {
    let mut sp = Sponge::new(o, tag::STATE);
    let vars: Vec<O::V> = st
        .items()
        .into_iter()
        .map(|(v, ext)| if ext { sp.absorb_free_ext(o, v) } else { sp.absorb_free(o, v.c0) })
        .collect();
    let dg: Vec<O::V> = (0..4).map(|_| sp.squeeze(o)).collect();
    (StateV::from_items(d, &vars), [dg[0], dg[1], dg[2], dg[3]])
}

/// Whether every base item of a state is a base value (zero extension
/// coefficients). The circuit absorbs a base item as one lane, so a state
/// that fails this has no circuit counterpart.
pub fn is_canonical(st: &State) -> bool {
    st.items().iter().all(|&(v, ext)| ext || (v.c1 == nebu::Goldilocks::ZERO && v.c2 == nebu::Goldilocks::ZERO))
}

/// The native digest; `Err` when a base item holds an extension value (the
/// native sponge stops hashing at the first failed check, so its output
/// would be raw rate lanes, not a digest).
pub fn digest_native(st: &State) -> Result<Digest, String> {
    let mut o = super::ops::Native::new();
    let d = digest(&mut o, st);
    o.finish()?;
    Ok([d[0].c0, d[1].c0, d[2].c0, d[3].c0])
}

/// The all-zero Fp3 word of a layout: its root and any leaf's opening.
pub struct ZeroWord {
    pub root: Digest,
    pub opening: LeafOpening,
}

impl ZeroWord {
    pub fn new(layout: &LeafLayout) -> Self {
        let width = 1usize << layout.log_width;
        let symbols = vec![Fp3::ZERO; width];
        let mut d = leaf_digest(true, &symbols);
        let mut path = Vec::new();
        for _ in 0..layout.log_leaves() {
            path.push(d);
            d = perm::head(&perm::node_state(d, d));
        }
        Self { root: d, opening: LeafOpening { symbols, path, leaf: None } }
    }
}

/// The initial deferred values and the context they hash to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtxParts {
    /// The statement (program, input, output, geometry).
    pub statement: Digest,
    /// The chain of pre-committed roots.
    pub chain: Digest,
    /// `G`, `P̄_nox`, `P̄_V` at the zero point.
    pub g0: Fp3,
    pub pn0: Fp3,
    pub pv0: Fp3,
}

/// The context digest, generically (the base step recomputes it).
pub fn ctx_digest<O: Ops>(o: &mut O, statement: [O::V; 4], chain: [O::V; 4], g0: O::V, pn0: O::V, pv0: O::V) -> [O::V; 4] {
    let mut sp = Sponge::new(o, tag::CTX);
    sp.absorb_all(o, &statement);
    sp.absorb_all(o, &chain);
    sp.absorb_all_ext(o, &[g0, pn0, pv0]);
    let d: Vec<O::V> = (0..4).map(|_| sp.squeeze(o)).collect();
    [d[0], d[1], d[2], d[3]]
}

pub fn ctx_native(p: &CtxParts) -> Digest {
    let mut o = super::ops::Native::new();
    let f = |d: Digest| d.map(Fp3::from_base);
    let d = ctx_digest(&mut o, f(p.statement), f(p.chain), p.g0, p.pn0, p.pv0);
    [d[0].c0, d[1].c0, d[2].c0, d[3].c0]
}

/// The initial state of a context: no step verified, the zero
/// accumulator, deferred claims at the zero point.
pub fn init<O: Ops>(o: &mut O, d: &Dims, ctx: [O::V; 4], zero_root: Digest, g0: O::V, pn0: O::V, pv0: O::V) -> StateV<O::V> {
    let z = o.zero();
    let one = o.one();
    let root = zero_root.map(|x| o.constant(Fp3::from_base(x)));
    StateV {
        ctx,
        step: z,
        chain: [z; 4],
        b_first: vec![z; d.boundary],
        b_last: vec![z; d.boundary],
        acc: AccV {
            root,
            rho: vec![z; d.vars],
            v0: z,
            ood: vec![(z, z); d.ood],
            spot: vec![(one, z); d.spot],
        },
        g: ClaimV { point: vec![z; d.g], value: g0 },
        pn: ClaimV { point: vec![z; d.pn], value: pn0 },
        pv: ClaimV { point: vec![z; d.pv], value: pv0 },
    }
}

/// `live ? verified : init`, element by element (`live` boolean).
pub fn select<O: Ops>(o: &mut O, live: O::V, init: &StateV<O::V>, verified: &StateV<O::V>) -> StateV<O::V> {
    let a = init.items();
    let b = verified.items();
    let vars: Vec<O::V> = a.iter().zip(&b).map(|(&(x, _), &(y, _))| o.lerp(live, x, y)).collect();
    let d = Dims {
        boundary: init.b_first.len(),
        vars: init.acc.rho.len(),
        ood: init.acc.ood.len(),
        spot: init.acc.spot.len(),
        g: init.g.point.len(),
        pn: init.pn.point.len(),
        pv: init.pv.point.len(),
    };
    StateV::from_items(&d, &vars)
}
