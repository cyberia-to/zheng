//! The batched field-native WHIR verifier over [`Ops`].

use lens::rspcs::field::root_of_unity;
use lens::rspcs::whir::RoundSpec;
use nebu::{Fp3, Goldilocks};

use super::{ClaimRef, Config, InstV, Proof};
use crate::recursion::gm;
use crate::recursion::ops::{Arith, Gate, Ops};
use crate::recursion::sponge::Sponge;
use crate::recursion::word::{LeafOpening, verify_leaf};

/// A weight term `coef·Z·eq(point, X)` of WHIR's closing check.
enum Point<V> {
    /// A point of the round's variables.
    Multi(Vec<V>),
    /// `pow(x)` over the round's variables.
    Pow(V),
}

struct Constraint<V> {
    round: usize,
    point: Point<V>,
    coef: V,
}

/// The batch: claims of every input reduced to one point; returns the
/// point and every word's value there.
pub fn batch<O: Ops>(o: &mut O, t: &mut Sponge<O>, inputs: &[InstV<O::V>], sumcheck: &[Fp3], evals: &[Fp3]) -> (Vec<O::V>, Vec<O::V>) {
    let gamma = t.squeeze_ext(o);
    let all: Vec<&ClaimRef<O::V>> = inputs.iter().flat_map(|i| &i.claims).collect();
    let gp = gm::powers(o, gamma, all.len());
    let vals: Vec<O::V> = all.iter().map(|c| c.value()).collect();
    let mut claim = gm::combine(o, &gp, &vals);
    let mut rho = Vec::with_capacity(sumcheck.len() / 2);
    for pair in sumcheck.chunks_exact(2) {
        let h0 = t.absorb_free_ext(o, pair[0]);
        let h2 = t.absorb_free_ext(o, pair[1]);
        let a = t.squeeze_ext(o);
        let h1 = o.sub(claim, h0);
        claim = gm::quadratic(o, h0, h1, h2, a);
        rho.push(a);
    }
    let mu: Vec<O::V> = evals.iter().map(|&x| t.absorb_free_ext(o, x)).collect();
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
        let w = w.expect("an input carries a claim");
        expect = Some(match expect {
            None => o.mul(w, mu_i),
            Some(a) => o.mul_add(w, mu_i, a),
        });
    }
    o.assert_eq(expect.expect("inputs"), claim, "whir: batch final claim");
    (rho, mu)
}

/// WHIR's folding sumcheck: `rounds` rounds of `(h(0), h(2))`, grinding
/// before each challenge; updates `sigma`.
fn fold_rounds<O: Ops>(o: &mut O, t: &mut Sponge<O>, sigma: &mut O::V, msgs: &[Fp3], nonces: &[u64], pow: u32) -> Vec<O::V> {
    let mut alphas = Vec::with_capacity(msgs.len() / 2);
    for (l, pair) in msgs.chunks_exact(2).enumerate() {
        let h0 = t.absorb_free_ext(o, pair[0]);
        let h2 = t.absorb_free_ext(o, pair[1]);
        t.grind_check(o, pow, nonces.get(l).copied().unwrap_or(0));
        let a = t.squeeze_ext(o);
        let h1 = o.sub(*sigma, h0);
        *sigma = gm::quadratic(o, h0, h1, h2, a);
        alphas.push(a);
    }
    alphas
}

/// The leaf indices of a round's queries, as bits (low first).
fn query_bits<O: Ops>(o: &mut O, t: &mut Sponge<O>, s: &RoundSpec) -> Vec<Vec<O::V>> {
    let depth = s.log_leaves() as usize;
    if s.opens_all() {
        let (zero, one) = (o.zero(), o.one());
        return (0..1usize << depth).map(|j| (0..depth).map(|k| if (j >> k) & 1 == 1 { one } else { zero }).collect()).collect();
    }
    t.indices(o, s.queries, depth)
}

/// `Fold(f, α)` at the shift point of the leaf whose index has `bits`
/// (lens `whir::fold::fold_leaf`): each step pairs `x` with `−x`,
/// `f'(x²) = (f(x)+f(−x))/2 + α·(f(x)−f(−x))/(2x)`.
fn fold_leaf<O: Ops>(o: &mut O, vals: &[O::V], alphas: &[O::V], log_n: u32, bits: &[O::V]) -> O::V {
    let width = vals.len();
    let omega = root_of_unity(log_n);
    let leaves = (1usize << log_n) / width;
    let half = Goldilocks::new(2).inv();
    let mut x0_inv = gm::pow_bits(o, omega.inv(), bits);
    let mut zeta_inv = omega.exp(leaves as u64).inv();
    let mut cur = vals.to_vec();
    let mut w = width;
    for &alpha in alphas {
        let h = w / 2;
        let mut scale = Goldilocks::ONE;
        let mut next = Vec::with_capacity(h);
        for t in 0..h {
            let (a, b) = (cur[t], cur[t + h]);
            // d = (a − b)·x_inv/2, x_inv = x0_inv·ζ^{-t}
            let g = Gate { qm: Fp3::from_base(half * scale), qs: -Fp3::ONE, ..Gate::default() };
            let d = o.gate(g, x0_inv, a, b);
            let g = Gate { qa: Fp3::from_base(half), qb: Fp3::from_base(half), ..Gate::default() };
            let even = o.gate(g, a, b, b);
            next.push(o.mul_add(alpha, d, even));
            scale *= zeta_inv;
        }
        cur = next;
        w = h;
        x0_inv = o.mul(x0_inv, x0_inv);
        zeta_inv = zeta_inv * zeta_inv;
    }
    cur[0]
}

/// Open every query of round `spec`'s function (its words: the inputs
/// when `roots.len() > 1` or it is `f_0`), combine with `coef`, fold.
#[allow(clippy::too_many_arguments)]
fn open_fold<O: Ops>(
    o: &mut O,
    spec: &RoundSpec,
    roots: &[([O::V; 4], bool)],
    coef: &[O::V],
    bits: &[Vec<O::V>],
    open: &[Vec<LeafOpening>],
    alphas: &[O::V],
) -> Vec<O::V> {
    bits.iter()
        .zip(open)
        .map(|(b, ops)| {
            let mut leaf: Option<Vec<O::V>> = None;
            for ((root, ext), (op, &c)) in roots.iter().zip(ops.iter().zip(coef)) {
                let syms = verify_leaf(o, *ext, op, b, *root, "whir: opening");
                leaf = Some(match leaf {
                    None => syms,
                    Some(acc) => acc.iter().zip(&syms).map(|(&a, &s)| o.mul_add(c, s, a)).collect(),
                });
            }
            fold_leaf(o, &leaf.expect("a word"), alphas, spec.log_domain, b)
        })
        .collect()
}

/// Panics on a proof of the wrong shape (callers check first).
pub fn check_shape(cfg: &Config, inputs: usize, pf: &Proof) -> Result<(), String> {
    let wc = &cfg.wc;
    let ell = wc.num_vars;
    let s0 = wc.rounds[0];
    let fold_n = |s: &RoundSpec| if s.fold_pow > 0 { s.fold } else { 0 };
    let leaf_ok = |s: &RoundSpec, l: &LeafOpening, ext: Option<bool>| {
        l.symbols.len() == 1 << s.fold
            && l.path.len() == s.log_leaves() as usize
            && (ext != Some(false) || l.symbols.iter().all(|x| x.c1 == Goldilocks::ZERO && x.c2 == Goldilocks::ZERO))
    };
    let q = |s: &RoundSpec| if s.opens_all() { 1usize << s.log_leaves() } else { s.queries };
    let opens = |s: &RoundSpec, first: bool, open: &[Vec<LeafOpening>]| {
        open.len() == q(s)
            && open.iter().all(|ws| ws.len() == if first { inputs } else { 1 } && ws.iter().all(|l| leaf_ok(s, l, if first { None } else { Some(true) })))
    };
    let mut ok = inputs == cfg.inputs
        && pf.batch.sumcheck.len() == 2 * ell
        && pf.batch.evals.len() == inputs
        && pf.ood0.len() == s0.ood
        && pf.sumcheck0.len() == 2 * s0.fold
        && pf.fold_nonces0.len() == fold_n(&s0)
        && pf.rounds.len() + 1 == wc.rounds.len()
        && pf.final_poly.len() == 1 << wc.final_vars;
    for (i, rp) in pf.rounds.iter().enumerate() {
        let (prev, s) = (wc.rounds[i], wc.rounds[i + 1]);
        ok &= rp.ood.len() == s.ood
            && rp.sumcheck.len() == 2 * s.fold
            && rp.fold_nonces.len() == fold_n(&s)
            && opens(&prev, i == 0, &rp.open);
    }
    let last = *wc.rounds.last().expect("a round");
    ok &= opens(&last, wc.rounds.len() == 1, &pf.final_open);
    // nonces are field elements (absorbed as one limb)
    let p = nebu::field::P;
    ok &= pf.batch.comb_nonce < p && pf.final_nonce < p && pf.fold_nonces0.iter().all(|&x| x < p);
    ok &= pf.rounds.iter().all(|rp| rp.query_nonce < p && rp.fold_nonces.iter().all(|&x| x < p));
    // a nonce no grinding reads must be zero (one encoding per proof)
    ok &= (cfg.comb_pow > 0 || pf.batch.comb_nonce == 0) && (last.query_pow > 0 || pf.final_nonce == 0);
    for (i, rp) in pf.rounds.iter().enumerate() {
        ok &= wc.rounds[i].query_pow > 0 || rp.query_nonce == 0;
    }
    if ok { Ok(()) } else { Err("whir: proof shape".into()) }
}

/// Verify a batched opening of `inputs` (each word in round 0's layout).
pub fn verify<O: Ops>(o: &mut O, cfg: &Config, t: &mut Sponge<O>, inputs: &[InstV<O::V>], pf: &Proof) {
    check_shape(cfg, inputs.len(), pf).expect("whir: proof shape");
    let wc = &cfg.wc;
    let m = inputs.len();
    // batch
    let (rho, mu) = batch(o, t, inputs, &pf.batch.sumcheck, &pf.batch.evals);
    t.grind_check(o, cfg.comb_pow, pf.batch.comb_nonce);
    let r = t.squeeze_ext(o);
    let coef = gm::powers(o, r, m);
    let value = gm::combine(o, &coef, &mu);
    // round 0 on f_0 = Σ r^i f_i
    let s0 = wc.rounds[0];
    let mut cons: Vec<Constraint<O::V>> = vec![Constraint { round: 0, point: Point::Multi(rho), coef: o.one() }];
    let zs: Vec<(O::V, O::V)> = pf
        .ood0
        .iter()
        .map(|&y| {
            let z = t.squeeze_ext(o);
            (z, t.absorb_free_ext(o, y))
        })
        .collect();
    let gamma = t.squeeze_ext(o);
    let mut sigma = value;
    let mut g = gamma;
    for &(z, y) in &zs {
        sigma = o.mul_add(g, y, sigma);
        cons.push(Constraint { round: 0, point: Point::Pow(z), coef: g });
        g = o.mul(g, gamma);
    }
    let mut alphas = fold_rounds(o, t, &mut sigma, &pf.sumcheck0, &pf.fold_nonces0, s0.fold_pow);
    let mut roots: Vec<([O::V; 4], bool)> = inputs.iter().map(|i| (i.root, i.ext)).collect();
    let mut prev_coef = coef;
    let mut prev = s0;
    for (i, rp) in pf.rounds.iter().enumerate() {
        let i = i + 1;
        let s = wc.rounds[i];
        let root: [O::V; 4] = core::array::from_fn(|k| t.absorb_free(o, rp.root[k]));
        let zs: Vec<(O::V, O::V)> = rp
            .ood
            .iter()
            .map(|&y| {
                let z = t.squeeze_ext(o);
                (z, t.absorb_free_ext(o, y))
            })
            .collect();
        t.grind_check(o, prev.query_pow, rp.query_nonce);
        let bits = query_bits(o, t, &prev);
        let gamma = t.squeeze_ext(o);
        let pa = alphas[alphas.len() - prev.fold..].to_vec();
        let folded = open_fold(o, &prev, &roots, &prev_coef, &bits, &rp.open, &pa);
        let mut g = gamma;
        for &(z, y) in &zs {
            sigma = o.mul_add(g, y, sigma);
            cons.push(Constraint { round: i, point: Point::Pow(z), coef: g });
            g = o.mul(g, gamma);
        }
        let omega_l = root_of_unity(prev.log_leaves());
        for (b, &v) in bits.iter().zip(&folded) {
            sigma = o.mul_add(g, v, sigma);
            let x = gm::pow_bits(o, omega_l, b);
            cons.push(Constraint { round: i, point: Point::Pow(x), coef: g });
            g = o.mul(g, gamma);
        }
        alphas.extend(fold_rounds(o, t, &mut sigma, &rp.sumcheck, &rp.fold_nonces, s.fold_pow));
        roots = vec![(root, true)];
        prev_coef = vec![o.one()];
        prev = s;
    }
    // the final polynomial and queries
    let fin: Vec<O::V> = pf.final_poly.iter().map(|&c| t.absorb_free_ext(o, c)).collect();
    t.grind_check(o, prev.query_pow, pf.final_nonce);
    let bits = query_bits(o, t, &prev);
    let pa = alphas[alphas.len() - prev.fold..].to_vec();
    let folded = open_fold(o, &prev, &roots, &prev_coef, &bits, &pf.final_open, &pa);
    let omega_l = root_of_unity(prev.log_leaves());
    for (b, &v) in bits.iter().zip(&folded) {
        let x = gm::pow_bits(o, omega_l, b);
        let f = gm::horner(o, &fin, x);
        o.assert_eq(f, v, "whir: final queries");
    }
    if t.has_pending() {
        t.flush(o);
    }
    // closing: σ = Σ_c coef·eq(point[..pre], α)·f̂_M(point[pre..])
    let fv = wc.final_vars;
    let mut expected: Option<O::V> = None;
    for c in &cons {
        let off = wc.alpha_offset(c.round);
        let nv = wc.rounds[c.round].num_vars;
        let pre = nv - fv;
        let a = &alphas[off..off + pre];
        let (e, f) = match &c.point {
            Point::Multi(p) => {
                let e = gm::eq(o, &p[..pre], a);
                (e, gm::monomial(o, &fin, &p[pre..]))
            }
            Point::Pow(x) => {
                let e = gm::eq_pow(o, *x, a);
                let xs = gm::pow2k(o, *x, pre);
                (e, gm::horner(o, &fin, xs))
            }
        };
        let ef = o.mul(e, f);
        expected = Some(match expected {
            None => o.mul(c.coef, ef),
            Some(acc) => o.mul_add(c.coef, ef, acc),
        });
    }
    o.assert_eq(expected.expect("a constraint"), sigma, "whir: closing check");
}
