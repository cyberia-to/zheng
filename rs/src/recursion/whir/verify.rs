//! The batched field-native WHIR verifier over [`Ops`].

use lens::rspcs::field::root_of_unity;
use lens::rspcs::whir::RoundSpec;
use nebu::{Fp3, Goldilocks};

use super::{ClaimRef, Config, InstV, NativeWeight, Proof, Weight};
use crate::recursion::gm;
use crate::recursion::ops::{Arith, Gate, Ops};
use crate::recursion::sponge::Sponge;
use crate::recursion::word::{Arity, LeafOpening, verify_leaf};

/// A weight term of WHIR's closing check: `coef·Z·eq(point, X)`, or a
/// direct claim's weight (round 0).
enum Point<V> {
    /// A point of the round's variables.
    Multi(Vec<V>),
    /// `pow(x)` over the round's variables.
    Pow(V),
    RowCol { next: bool, rho: Vec<V>, col: Vec<V> },
    Native(usize),
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
fn fold_leaf<O: Ops>(o: &mut O, vals: &[O::V], alphas: &[O::V], log_n: u32, x0_inv: O::V) -> O::V {
    let width = vals.len();
    let omega = root_of_unity(log_n);
    let leaves = (1usize << log_n) / width;
    let half = Goldilocks::new(2).inv();
    let mut x0_inv = x0_inv;
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

/// Open every query of round `spec`'s function (its trees: `(root, ext,
/// words)`; the round-0 trees when it is `f_0`), combine the words with
/// `coef`, fold; returns every query's folded value and shift point
/// `ω^{jW}` (from `x = ω^j`: one power, an inverse, `k` squarings).
#[allow(clippy::too_many_arguments)]
fn open_fold<O: Ops>(
    o: &mut O,
    spec: &RoundSpec,
    trees: &[([O::V; 4], bool, usize)],
    arity: Arity,
    coef: &[O::V],
    bits: &[Vec<O::V>],
    open: &[Vec<LeafOpening>],
    alphas: &[O::V],
) -> Vec<(O::V, O::V)> {
    let width = 1usize << spec.fold;
    let omega = root_of_unity(spec.log_domain);
    bits.iter()
        .zip(open)
        .map(|(b, ops)| {
            let mut leaf: Option<Vec<O::V>> = None;
            let mut c = coef.iter();
            for (&(root, ext, members), op) in trees.iter().zip(ops) {
                let syms = verify_leaf(o, ext, arity, op, b, root, "whir: opening");
                for part in syms.chunks(width).take(members) {
                    let k = *c.next().expect("a coefficient per word");
                    leaf = Some(match leaf {
                        None => part.to_vec(),
                        Some(acc) => acc.iter().zip(part).map(|(&a, &s)| o.mul_add(k, s, a)).collect(),
                    });
                }
            }
            let x = gm::pow_bits(o, omega, b);
            let x_inv = o.inv(x, "whir: a domain point is invertible");
            let shift = gm::pow2k(o, x, spec.fold);
            (fold_leaf(o, &leaf.expect("a word"), alphas, spec.log_domain, x_inv), shift)
        })
        .collect()
}

/// Panics on a proof of the wrong shape (callers check first).
pub fn check_shape(cfg: &Config, inputs: usize, pf: &Proof) -> Result<(), String> {
    let wc = &cfg.wc;
    let ell = wc.num_vars;
    let s0 = wc.rounds[0];
    let fold_n = |s: &RoundSpec| if s.fold_pow > 0 { s.fold } else { 0 };
    let leaf_ok = |s: &RoundSpec, l: &LeafOpening, m: usize, ext: Option<bool>| {
        l.symbols.len() == m << s.fold
            && l.path.len() == cfg.arity.path_len(s.log_leaves() as usize)
            && (ext != Some(false) || l.symbols.iter().all(|x| x.c1 == Goldilocks::ZERO && x.c2 == Goldilocks::ZERO))
    };
    let q = |s: &RoundSpec| if s.opens_all() { 1usize << s.log_leaves() } else { s.queries };
    let one = [1usize];
    let opens = |s: &RoundSpec, first: bool, open: &[Vec<LeafOpening>]| {
        let g: &[usize] = if first { &cfg.groups } else { &one };
        open.len() == q(s)
            && open.iter().all(|ws| ws.len() == g.len() && ws.iter().zip(g).all(|(l, &m)| leaf_ok(s, l, m, if first { None } else { Some(true) })))
    };
    let batch = if cfg.direct() { 0 } else { 1 };
    let mut ok = inputs == cfg.inputs
        && pf.batch.sumcheck.len() == 2 * ell * batch
        && pf.batch.evals.len() == inputs * batch
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
    assert!(!cfg.direct(), "whir: one word opens directly");
    let m = inputs.len();
    // batch
    let (rho, mu) = batch(o, t, inputs, &pf.batch.sumcheck, &pf.batch.evals);
    t.grind_check(o, cfg.comb_pow, pf.batch.comb_nonce);
    let r = t.squeeze_ext(o);
    let coef = gm::powers(o, r, m);
    let value = gm::combine(o, &coef, &mu);
    let mut roots: Vec<([O::V; 4], bool, usize)> = Vec::with_capacity(cfg.groups.len());
    let mut at = 0;
    for &m in &cfg.groups {
        roots.push((inputs[at].root, inputs[at].ext, m));
        at += m;
    }
    let one = o.one();
    let cons = vec![Constraint { round: 0, point: Point::Multi(rho), coef: one }];
    core(o, cfg, t, roots, coef, cons, value, &[], pf);
}

/// Verify an opening of one word whose claims are given by their weights
/// (`Σ_x w(x)·f(x) = v`); [`Weight::Native`] indexes `natives` (a native
/// interpreter only: it evaluates them in the field).
#[allow(clippy::too_many_arguments)]
pub fn verify_direct<O: Ops>(
    o: &mut O,
    cfg: &Config,
    t: &mut Sponge<O>,
    root: [O::V; 4],
    ext: bool,
    claims: Vec<(Weight<O::V>, O::V)>,
    natives: &[&dyn NativeWeight],
    pf: &Proof,
) {
    check_shape(cfg, 1, pf).expect("whir: proof shape");
    assert!(cfg.direct() && claims.len() <= cfg.claims, "whir: a direct opening");
    let gamma = t.squeeze_ext(o);
    let mut g = o.one();
    let mut sigma = o.zero();
    let mut cons = Vec::with_capacity(claims.len());
    for (w, v) in claims {
        sigma = o.mul_add(g, v, sigma);
        let point = match w {
            Weight::Eq(p) => Point::Multi(p),
            Weight::Pow(x) => Point::Pow(x),
            Weight::RowCol { next, rho, col } => Point::RowCol { next, rho, col },
            Weight::Native(i) => Point::Native(i),
        };
        cons.push(Constraint { round: 0, point, coef: g });
        g = o.mul(g, gamma);
    }
    let one = o.one();
    core(o, cfg, t, vec![(root, ext, 1)], vec![one], cons, sigma, natives, pf);
}

/// WHIR on `f_0 = Σ coef_i·f_i` from its initial constraints and claimed
/// sum.
#[allow(clippy::too_many_arguments)]
fn core<O: Ops>(
    o: &mut O,
    cfg: &Config,
    t: &mut Sponge<O>,
    mut roots: Vec<([O::V; 4], bool, usize)>,
    coef: Vec<O::V>,
    mut cons: Vec<Constraint<O::V>>,
    value: O::V,
    natives: &[&dyn NativeWeight],
    pf: &Proof,
) {
    let wc = &cfg.wc;
    let lap = crate::recursion::ivc::timer_pub("        whir ");
    let s0 = wc.rounds[0];
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
        let folded = open_fold(o, &prev, &roots, cfg.arity, &prev_coef, &bits, &rp.open, &pa);
        let mut g = gamma;
        for &(z, y) in &zs {
            sigma = o.mul_add(g, y, sigma);
            cons.push(Constraint { round: i, point: Point::Pow(z), coef: g });
            g = o.mul(g, gamma);
        }
        for &(v, x) in &folded {
            sigma = o.mul_add(g, v, sigma);
            cons.push(Constraint { round: i, point: Point::Pow(x), coef: g });
            g = o.mul(g, gamma);
        }
        alphas.extend(fold_rounds(o, t, &mut sigma, &rp.sumcheck, &rp.fold_nonces, s.fold_pow));
        roots = vec![(root, true, 1)];
        prev_coef = vec![o.one()];
        prev = s;
    }
    lap("rounds");
    // the final polynomial and queries
    // one word (a native verifier): the final polynomial as a digest
    let fin: Vec<O::V> = if cfg.direct() {
        crate::recursion::msg::absorb(o, t, &pf.final_poly)
    } else {
        pf.final_poly.iter().map(|&c| t.absorb_free_ext(o, c)).collect()
    };
    t.grind_check(o, prev.query_pow, pf.final_nonce);
    let bits = query_bits(o, t, &prev);
    let pa = alphas[alphas.len() - prev.fold..].to_vec();
    let folded = open_fold(o, &prev, &roots, cfg.arity, &prev_coef, &bits, &pf.final_open, &pa);
    for &(v, x) in &folded {
        let f = gm::horner(o, &fin, x);
        o.assert_eq(f, v, "whir: final queries");
    }
    if t.has_pending() {
        t.flush(o);
    }
    lap("final queries");
    // closing: σ = Σ_c coef·Σ_b w_c(α, b)·f_M(b) — for eq weights
    // eq(point[..pre], α)·f̂_M(point[pre..])
    let fv = wc.final_vars;
    let mut cube: Option<Vec<O::V>> = None;
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
            Point::RowCol { next, rho, col } => {
                let n = rho.len();
                assert!(col.len() << n == 1 << nv, "whir: a row-column weight");
                let fm = cube.get_or_insert_with(|| cube_values(o, &fin)).clone();
                if pre >= n {
                    // the rows inside α: one row factor, the columns split
                    let e = if *next { gm::next_eval(o, rho, &a[..n]) } else { gm::eq(o, rho, &a[..n]) };
                    let lo = pre - n;
                    let mut acc: Option<O::V> = None;
                    for (c, &w) in col.iter().enumerate() {
                        let ec = gm::eq_row(o, c & ((1 << lo) - 1), &a[n..pre]);
                        let wc = o.mul(w, ec);
                        acc = Some(match acc {
                            None => o.mul(wc, fm[c >> lo]),
                            Some(s) => o.mul_add(wc, fm[c >> lo], s),
                        });
                    }
                    (e, acc.expect("columns"))
                } else {
                    // the last rows and every column among the final
                    // variables: the row factor per final row value
                    let rb = n - pre;
                    let (zero, one) = (o.zero(), o.one());
                    let mut acc: Option<O::V> = None;
                    for br in 0..1usize << rb {
                        let pt: Vec<O::V> = a.iter().copied().chain((0..rb).map(|i| if (br >> i) & 1 == 1 { one } else { zero })).collect();
                        let rv = if *next { gm::next_eval(o, rho, &pt) } else { gm::eq(o, rho, &pt) };
                        for (c, &w) in col.iter().enumerate() {
                            let rw = o.mul(rv, w);
                            let f = fm[br + (c << rb)];
                            acc = Some(match acc {
                                None => o.mul(rw, f),
                                Some(s) => o.mul_add(rw, f, s),
                            });
                        }
                    }
                    (one, acc.expect("rows"))
                }
            }
            Point::Native(i) => {
                let av: Vec<Fp3> = a.iter().map(|&v| o.value(v)).collect();
                let fins: Vec<Fp3> = fin.iter().map(|&v| o.value(v)).collect();
                let fm = cube_native(&fins);
                let v = natives[*i].closing(&av, &fm);
                (o.one(), o.constant(v))
            }
        };
        let ef = o.mul(e, f);
        expected = Some(match expected {
            None => o.mul(c.coef, ef),
            Some(acc) => o.mul_add(c.coef, ef, acc),
        });
    }
    o.assert_eq(expected.expect("a constraint"), sigma, "whir: closing check");
    lap("closing");
}

/// The final polynomial's values on the cube from its monomial
/// coefficients (the zeta transform: `f(b) = Σ_{S ⊆ b} c_S`).
fn cube_values<O: Ops>(o: &mut O, coeffs: &[O::V]) -> Vec<O::V> {
    let mut v = coeffs.to_vec();
    let mut h = 1;
    while h < v.len() {
        for i in 0..v.len() {
            if i & h != 0 {
                v[i] = o.add(v[i], v[i ^ h]);
            }
        }
        h <<= 1;
    }
    v
}

fn cube_native(coeffs: &[Fp3]) -> Vec<Fp3> {
    let mut v = coeffs.to_vec();
    let mut h = 1;
    while h < v.len() {
        for i in 0..v.len() {
            if i & h != 0 {
                v[i] = v[i] + v[i ^ h];
            }
        }
        h <<= 1;
    }
    v
}
