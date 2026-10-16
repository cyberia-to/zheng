//! The veil-r verifier over [`Ops`]: natively the field-native zk
//! profile's verifier, in the recursion circuit the aggregation step's
//! check of one transaction proof.
//!
//! Every check of veil's verifier (`protocol::verify`, `hiding::verify`)
//! is here, in the same order, on the duplex transcript:
//!
//! 1. the masked outer sumcheck from `ρ1·Σg1`, `ρ1 ≠ 0`; the CCS gate at
//!    the matrix evaluations gives `g1(ρ_x)`;
//! 2. the masked inner sumcheck from `Σ γ^i v_i − P + ρ2·Σg2`, with `P`
//!    the pinned half (the pins enter as values);
//! 3. the final claim's functional: `A(0, r)` (the free half's combined
//!    matrix weight, from the key's sparse rows) and the Libra weights;
//! 4. the hiding opening: `q[k − 1] = V + ρ_L·μ`, grinding, per query the
//!    salted leaf and its path, the row test `p_P(ω^j) = Σ α^i col_i` and
//!    the linear test `q(ω^j) = Σ Λ'_i(ω^j)·col_i + ρ_L·(m_a + X^K m_b)`.
//!
//! The sparse sums (`A(0, r)` and `P`) cost one gate per two matrix
//! entries, one per row and matrix, and the column `eq` table
//! (`2^{ℓ+1}` gates); the row `eq` is split in two tensor halves.

use nebu::{Fp3, Goldilocks};

use super::{ARITY, RecKey, RecProof, SparseRow, header};
use crate::execution::veil::hiding::SALT;
use crate::execution::veil::libra::limb_basis;
use crate::recursion::gm;
use crate::recursion::ops::{Arith, Gate, Ops};
use crate::recursion::perm::tag;
use crate::recursion::sponge::Sponge;
use crate::recursion::word;

/// `eq(p, ·)` over `2^p.len()` entries, MSB-first point (`p[0]` ↔ the top
/// index bit); two gates an entry.
pub fn eq_table<O: Ops>(o: &mut O, p: &[O::V]) -> Vec<O::V> {
    let mut t = vec![o.one()];
    for &x in p {
        let mut next = Vec::with_capacity(2 * t.len());
        for &e in &t {
            let hi = o.mul(e, x);
            let lo = o.sub(e, hi);
            next.push(lo);
            next.push(hi);
        }
        t = next;
    }
    t
}

/// `Σ c_i·x_i + k` for constants `c_i`, two terms a gate.
fn lin_const<O: Ops>(o: &mut O, terms: &[(Goldilocks, O::V)], k: Fp3) -> O::V {
    let mut acc: Option<O::V> = None;
    let mut it = terms.chunks(2);
    for pair in &mut it {
        let (c1, x1) = (Fp3::from_base(pair[0].0), pair[0].1);
        let (c2, x2) = pair.get(1).map_or((Fp3::ZERO, x1), |&(c, x)| (Fp3::from_base(c), x));
        acc = Some(match acc {
            None => o.gate(Gate { qa: c1, qb: c2, qk: k, ..Gate::default() }, x1, x2, x2),
            Some(a) => o.gate(Gate { qa: c1, qb: c2, qc: Fp3::ONE, ..Gate::default() }, x1, x2, a),
        });
    }
    acc.unwrap_or_else(|| o.constant(k))
}

/// `eq(ρ_x, row)` as two tensor halves: `eq_hi[row >> lo]·eq_lo[row mod 2^lo]`.
struct RowEq<V> {
    hi: Vec<V>,
    lo: Vec<V>,
    lo_bits: usize,
}

fn row_eq<O: Ops>(o: &mut O, rho_x: &[O::V]) -> RowEq<O::V> {
    let lo_bits = rho_x.len() / 2;
    let hi = eq_table(o, &rho_x[..rho_x.len() - lo_bits]);
    let lo = eq_table(o, &rho_x[rho_x.len() - lo_bits..]);
    RowEq { hi, lo, lo_bits }
}

/// `Σ_i γ^i Σ_row eq(ρ_x, row)·row_i(row)` with `row_i` a linear form of
/// the row's entries (`None`: the row contributes nothing).
fn row_sum<O: Ops>(o: &mut O, key: &RecKey, eq: &RowEq<O::V>, gp: &[O::V], mut row_value: impl FnMut(&mut O, &SparseRow) -> Option<O::V>) -> O::V {
    let mut total: Option<O::V> = None;
    for (rows, &g) in key.sparse.iter().zip(gp) {
        let mut s: Option<O::V> = None;
        let mut i = 0;
        while i < rows.len() {
            let hi = rows[i].row >> eq.lo_bits;
            let mut a: Option<O::V> = None;
            while i < rows.len() && rows[i].row >> eq.lo_bits == hi {
                let row = &rows[i];
                if let Some(v) = row_value(o, row) {
                    let el = eq.lo[row.row & ((1 << eq.lo_bits) - 1)];
                    a = Some(match a {
                        None => o.mul(el, v),
                        Some(acc) => o.mul_add(el, v, acc),
                    });
                }
                i += 1;
            }
            if let Some(v) = a {
                s = Some(match s {
                    None => o.mul(eq.hi[hi], v),
                    Some(acc) => o.mul_add(eq.hi[hi], v, acc),
                });
            }
        }
        if let Some(v) = s {
            total = Some(match total {
                None => o.mul(g, v),
                Some(acc) => o.mul_add(g, v, acc),
            });
        }
    }
    total.unwrap_or_else(|| o.zero())
}

/// `P = Σ_i γ^i Σ_row eq(ρ_x, row)·Σ_pinned M_i[row][c]·p_c` (pin 0 is the
/// constant 1).
fn pinned_part<O: Ops>(o: &mut O, key: &RecKey, eq: &RowEq<O::V>, gp: &[O::V], pins: &[O::V]) -> O::V {
    row_sum(o, key, eq, gp, |o, row| {
        if row.pinned.is_empty() {
            return None;
        }
        let k = row.pinned.iter().filter(|&&(s, _)| s == 0).fold(Goldilocks::ZERO, |a, &(_, v)| a + v);
        let terms: Vec<(Goldilocks, O::V)> = row.pinned.iter().filter(|&&(s, _)| s != 0).map(|&(s, v)| (v, pins[s - 1])).collect();
        Some(lin_const(o, &terms, Fp3::from_base(k)))
    })
}

/// `A(0, r) = Σ_i γ^i M̃'_i(ρ_x, (0, r))`: the free half's columns only.
fn free_weight<O: Ops>(o: &mut O, key: &RecKey, eq: &RowEq<O::V>, gp: &[O::V], r: &[O::V]) -> O::V {
    let eq_col = eq_table(o, r);
    row_sum(o, key, eq, gp, |o, row| {
        if row.free.is_empty() {
            return None;
        }
        let terms: Vec<(Goldilocks, O::V)> = row.free.iter().map(|&(c, v)| (v, eq_col[c])).collect();
        Some(lin_const(o, &terms, Fp3::ZERO))
    })
}

/// One sumcheck: absorb each round's compressed coefficients, restore
/// `c_1 = claim − 2c_0 − Σ_{i≥2} c_i`, fold at the challenge.
fn rounds<O: Ops>(o: &mut O, t: &mut Sponge<O>, mut claim: O::V, msgs: &[Vec<Fp3>]) -> (O::V, Vec<O::V>) {
    let mut pts = Vec::with_capacity(msgs.len());
    for m in msgs {
        let c: Vec<O::V> = m.iter().map(|&x| t.absorb_free_ext(o, x)).collect();
        let r = t.squeeze_ext(o);
        // c1 = claim − 2c0 − Σ_{i≥2} c_i
        let mut terms: Vec<(Fp3, O::V)> = vec![(Fp3::ONE, claim), (-Fp3::from_base(Goldilocks::new(2)), c[0])];
        terms.extend(c[1..].iter().map(|&x| (-Fp3::ONE, x)));
        let c1 = o.lin(&terms);
        let mut full = vec![c[0], c1];
        full.extend_from_slice(&c[1..]);
        claim = gm::horner(o, &full, r);
        pts.push(r);
    }
    (claim, pts)
}

/// `Σ_k coeff_k Π_{i∈S_k} v_i` (the CCS gate).
fn ccs_gate<O: Ops>(o: &mut O, key: &RecKey, v: &[O::V]) -> O::V {
    let inst = &key.pk.setup.instance;
    let mut acc = o.zero();
    for (set, &c) in inst.multisets.iter().zip(&inst.coeffs) {
        let prod = gm::product(o, &set.iter().map(|&i| v[i]).collect::<Vec<_>>());
        acc = o.scale_add(Fp3::from_base(c), prod, acc);
    }
    acc
}

/// `eq(τ, ρ_x)` with `τ_j` paired to `ρ_x[log m − 1 − j]`.
fn eq_tau_rho<O: Ops>(o: &mut O, tau: &[O::V], rho_x: &[O::V]) -> O::V {
    let rev: Vec<O::V> = rho_x.iter().rev().copied().collect();
    gm::eq(o, tau, &rev)
}

/// The Libra weights `scale·x_i^d·t^l` of one mask, round-major.
fn libra_weights<O: Ops>(o: &mut O, point: &[O::V], degree: usize, scale: O::V) -> Vec<O::V> {
    let basis = [limb_basis(1), limb_basis(2)];
    let mut out = Vec::with_capacity(point.len() * (degree + 1) * 3);
    for &x in point {
        let mut power = scale;
        for d in 0..=degree {
            out.push(power);
            for b in basis {
                out.push(o.affine(b, power, Fp3::ZERO));
            }
            if d < degree {
                power = o.mul(power, x);
            }
        }
    }
    out
}

/// Verify `pf` for the pinned values `pins` (the constant excluded, base
/// values the caller has bound). Panics on a shape the caller should have
/// refused (`wire::check_shape`).
pub fn verify<O: Ops>(o: &mut O, key: &RecKey, pins: &[O::V], pf: &RecProof) {
    let s = &key.pk.setup;
    assert_eq!(pins.len(), key.pins(), "veil-r: pins");
    let mut t = Sponge::new(o, tag::VEIL);
    for h in header(key) {
        let c = o.constant(Fp3::from_base(h));
        t.absorb(o, c);
    }
    t.absorb_all(o, pins);
    let root: [O::V; 4] = core::array::from_fn(|i| t.absorb_free(o, pf.root[i]));
    // outer: from ρ1·Σg1, ρ1 ≠ 0
    let tau = t.squeeze_exts(o, s.log_m);
    let g1 = t.absorb_free_ext(o, pf.g1);
    let rho1 = t.squeeze_ext(o);
    let rho1_inv = o.inv(rho1, "veil-r: degenerate challenge");
    let c0 = o.mul(rho1, g1);
    let (c1, rho_x) = rounds(o, &mut t, c0, &pf.outer);
    let evals: Vec<O::V> = pf.evals.iter().map(|&e| t.absorb_free_ext(o, e)).collect();
    // g1(ρ_x) = (C1 − eq(τ, ρ_x)·G(v)) / ρ1
    let eq = eq_tau_rho(o, &tau, &rho_x);
    let gv = ccs_gate(o, key, &evals);
    let eg = o.mul(eq, gv);
    let d = o.sub(c1, eg);
    let g1_at = o.mul(d, rho1_inv);
    // inner: from Σ γ^i v_i − P + ρ2·Σg2
    let gamma = t.squeeze_ext(o);
    let gp = gm::powers(o, gamma, evals.len());
    let batched = gm::combine(o, &gp, &evals);
    let req = row_eq(o, &rho_x);
    let p = pinned_part(o, key, &req, &gp, pins);
    let g2 = t.absorb_free_ext(o, pf.g2);
    let rho2 = t.squeeze_ext(o);
    let claim2 = o.sub(batched, p);
    let start = o.mul_add(rho2, g2, claim2);
    let (c2, r) = rounds(o, &mut t, start, &pf.inner);
    let lambda = t.squeeze_ext(o);
    let a0 = free_weight(o, key, &req, &gp, &r);
    let value = o.mul_add(lambda, g1_at, c2);
    opening(o, key, &mut t, root, pf, OpenArgs { a0, r: &r, lambda, rho_x: &rho_x, rho2, value });
}

struct OpenArgs<'a, V> {
    a0: V,
    r: &'a [V],
    lambda: V,
    rho_x: &'a [V],
    rho2: V,
    value: V,
}

/// The hiding opening of the functional
/// `a0·eq(r, ·)` on the free half plus the Libra weights
/// `λ·g1(ρ_x) + ρ2·g2(r)` on the masks, at `value`.
fn opening<O: Ops>(o: &mut O, key: &RecKey, t: &mut Sponge<O>, root: [O::V; 4], pf: &RecProof, a: OpenArgs<'_, O::V>) {
    let s = &key.pk.setup;
    let cfg = key.cfg;
    let (k, big_k, rows, tr) = (cfg.k, cfg.big_k(), cfg.rows, cfg.total_rows());
    // the functional: tensor block over the free half, explicit weights
    // on the masks from entry 2^ℓ on
    let lo = a.r.len().min(k.trailing_zeros() as usize);
    let hi = a.r.len() - lo;
    let row_w: Vec<O::V> = eq_table(o, &a.r[..hi]).into_iter().map(|w| o.mul(a.a0, w)).collect();
    let lo_point = &a.r[hi..];
    let mut explicit = libra_weights(o, a.rho_x, s.degree, a.lambda);
    explicit.extend(libra_weights(o, a.r, 2, a.rho2));
    let start = s.half();
    // per row of the explicit block: (row, first column, weights)
    let mut blocks: Vec<(usize, usize, Vec<O::V>)> = Vec::new();
    for (i, &w) in explicit.iter().enumerate() {
        let e = start + i;
        match blocks.last_mut() {
            Some(b) if b.0 == e / k => b.2.push(w),
            _ => blocks.push((e / k, e % k, vec![w])),
        }
    }
    // q[k − 1] = V + ρ_L·μ
    let mu = t.absorb_free_ext(o, pf.mu);
    let alpha = t.squeeze_ext(o);
    let rho_l = t.squeeze_ext(o);
    let row_test: Vec<O::V> = pf.row_test.iter().map(|&c| t.absorb_free_ext(o, c)).collect();
    let linear: Vec<O::V> = pf.linear.iter().map(|&c| t.absorb_free_ext(o, c)).collect();
    let want = o.mul_add(rho_l, mu, a.value);
    o.assert_eq(linear[k - 1], want, "veil-r: linear claim");
    t.grind_check(o, cfg.pow_bits, pf.nonce);
    let idx = t.indices(o, cfg.queries, cfg.log_n as usize);
    let alpha_pows = gm::powers(o, alpha, tr);
    let omega = lens::rspcs::field::root_of_unity(cfg.log_n);
    let lk = k.trailing_zeros() as usize;
    for (bits, op) in idx.iter().zip(&pf.openings) {
        let col = word::verify_leaf(o, false, ARITY, op, bits, root, "veil-r: merkle");
        let col = &col[..tr];
        let x = gm::pow_bits(o, omega, bits);
        let y = o.inv(x, "veil-r: a root of unity is invertible");
        let xk = gm::pow2k(o, x, lk);
        let x_big_k = o.mul(xk, xk);
        let xk1 = o.mul(xk, y);
        // row test: p_P(x) = Σ α^i col_i
        let test = gm::combine(o, &alpha_pows, col);
        let pp = gm::horner(o, &row_test, x);
        o.assert_eq(pp, test, "veil-r: proximity column");
        // E(x) = x^{k−1} Π_t ((1 − p_t) + p_t·y^{2^{lo−1−t}})
        let mut ypow = Vec::with_capacity(lo);
        let mut yp = y;
        for _ in 0..lo {
            ypow.push(yp);
            yp = o.mul(yp, yp);
        }
        let mut e = xk1;
        for (ti, &p) in lo_point.iter().enumerate() {
            let yy = ypow[lo - 1 - ti];
            // 1 + p·(y' − 1)
            let one = o.one();
            let f = o.gate(Gate { qm: Fp3::ONE, qs: -Fp3::ONE, qk: Fp3::ONE, ..Gate::default() }, p, yy, one);
            e = o.mul(e, f);
        }
        let tensor = gm::combine(o, &row_w, &col[..row_w.len()]);
        let mut lin = o.mul(e, tensor);
        // explicit weights: Σ_row col_row · x^{k−1}·Σ_c w_c y^c
        let mut ex: Option<O::V> = None;
        for (row, c0, ws) in &blocks {
            let mut h = gm::horner(o, ws, y);
            if *c0 > 0 {
                let mut yc = o.one();
                for _ in 0..*c0 {
                    yc = o.mul(yc, y);
                }
                h = o.mul(h, yc);
            }
            ex = Some(match ex {
                None => o.mul(col[*row], h),
                Some(acc) => o.mul_add(col[*row], h, acc),
            });
        }
        if let Some(v) = ex {
            lin = o.mul_add(xk1, v, lin);
        }
        // ρ_L·(m_a(x) + x^K·m_b(x))
        let mb = o.mul(x_big_k, col[rows + 1]);
        let m = o.add(col[rows], mb);
        lin = o.mul_add(rho_l, m, lin);
        let q = gm::horner(o, &linear, x);
        o.assert_eq(q, lin, "veil-r: linear column");
    }
    let _ = (big_k, SALT);
}
