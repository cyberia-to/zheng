//! Verifier arithmetic over [`Ops`]: `eq`, multilinear folds, univariate
//! interpolation, powers — the pieces every sumcheck verifier needs,
//! written once for the native verifier and the circuit.

use nebu::{Fp3, Goldilocks};

use super::ops::{Arith, Gate, Ops};

fn k(v: i64) -> Fp3 {
    if v >= 0 {
        Fp3::from_base(Goldilocks::new(v as u64))
    } else {
        -Fp3::from_base(Goldilocks::new((-v) as u64))
    }
}

/// `eq(a, b) = Π (a_i b_i + (1 − a_i)(1 − b_i))`.
pub fn eq<O: Ops>(o: &mut O, a: &[O::V], b: &[O::V]) -> O::V {
    assert_eq!(a.len(), b.len());
    let mut acc: Option<O::V> = None;
    for (&x, &y) in a.iter().zip(b) {
        let g = Gate { qm: k(2), qa: k(-1), qb: k(-1), qk: Fp3::ONE, ..Gate::default() };
        let f = o.gate(g, x, y, y);
        acc = Some(match acc {
            None => f,
            Some(p) => o.mul(p, f),
        });
    }
    acc.unwrap_or_else(|| o.one())
}

/// `eq(pow(x), b)` with `pow(x) = (x, x², x⁴, …)`.
pub fn eq_pow<O: Ops>(o: &mut O, x: O::V, b: &[O::V]) -> O::V {
    let mut xi = x;
    let mut acc: Option<O::V> = None;
    for (i, &y) in b.iter().enumerate() {
        if i > 0 {
            xi = o.mul(xi, xi);
        }
        let g = Gate { qm: k(2), qa: k(-1), qb: k(-1), qk: Fp3::ONE, ..Gate::default() };
        let f = o.gate(g, xi, y, y);
        acc = Some(match acc {
            None => f,
            Some(p) => o.mul(p, f),
        });
    }
    acc.unwrap_or_else(|| o.one())
}

/// `eq(row_point(r), b)` for a constant row `r`: `Π (b_i or 1 − b_i)`
/// (the gate count is independent of `r`).
pub fn eq_row<O: Ops>(o: &mut O, r: usize, b: &[O::V]) -> O::V {
    let mut acc: Option<O::V> = None;
    for (i, &y) in b.iter().enumerate() {
        let f = if (r >> i) & 1 == 1 {
            o.affine(Fp3::ONE, y, Fp3::ZERO)
        } else {
            o.affine(-Fp3::ONE, y, Fp3::ONE)
        };
        acc = Some(match acc {
            None => f,
            Some(p) => o.mul(p, f),
        });
    }
    acc.unwrap_or_else(|| o.one())
}

/// The multilinear extension of `vals` (lens order: variable `i` ↔ bit
/// `i`, `vals.len() ≤ 2^point.len()`, zeros beyond) at `point`.
pub fn mle<O: Ops>(o: &mut O, vals: &[O::V], point: &[O::V]) -> O::V {
    assert!(vals.len() <= 1 << point.len());
    let mut cur: Vec<O::V> = vals.to_vec();
    let mut zero: Option<O::V> = None;
    for &r in point {
        let mut next = Vec::with_capacity(cur.len().div_ceil(2));
        for pair in cur.chunks(2) {
            if pair.len() == 2 {
                next.push(o.lerp(r, pair[0], pair[1]));
            } else {
                // (a, 0): a·(1 − r)
                let g = Gate { qm: -Fp3::ONE, qa: Fp3::ONE, ..Gate::default() };
                next.push(o.gate(g, pair[0], r, r));
            }
        }
        if next.is_empty() {
            let z = *zero.get_or_insert_with(|| o.zero());
            next.push(z);
        }
        cur = next;
    }
    cur[0]
}

/// The polynomial through `(i, vals[i])`, `i = 0..len`, at `x`.
pub fn interpolate<O: Ops>(o: &mut O, vals: &[O::V], x: O::V) -> O::V {
    let n = vals.len();
    // prefix[i] = Π_{j<i} (x − j), suffix[i] = Π_{j>i} (x − j)
    let mut prefix = Vec::with_capacity(n);
    let mut p: Option<O::V> = None;
    for j in 0..n {
        prefix.push(p);
        let f = o.affine(Fp3::ONE, x, k(-(j as i64)));
        p = Some(match p {
            None => f,
            Some(q) => o.mul(q, f),
        });
    }
    let mut suffix = vec![None; n];
    let mut s: Option<O::V> = None;
    for j in (0..n).rev() {
        suffix[j] = s;
        let f = o.affine(Fp3::ONE, x, k(-(j as i64)));
        s = Some(match s {
            None => f,
            Some(q) => o.mul(q, f),
        });
    }
    let mut acc: Option<O::V> = None;
    for i in 0..n {
        let mut den = Goldilocks::ONE;
        for j in 0..n {
            if j != i {
                den *= Goldilocks::new(i as u64) - Goldilocks::new(j as u64);
            }
        }
        let c = Fp3::from_base(den.inv());
        let w = match (prefix[i], suffix[i]) {
            (None, None) => o.constant(c),
            (Some(a), None) | (None, Some(a)) => o.affine(c, a, Fp3::ZERO),
            (Some(a), Some(b)) => {
                let g = Gate { qm: c, ..Gate::default() };
                o.gate(g, a, b, b)
            }
        };
        acc = Some(match acc {
            None => o.mul(vals[i], w),
            Some(t) => o.mul_add(vals[i], w, t),
        });
    }
    acc.expect("at least one value")
}

/// The quadratic through `(0, h0), (1, h1), (2, h2)` at `x`:
/// `h0 + x(h1 − h0) + x(x − 1)/2·(h2 − 2h1 + h0)`.
pub fn quadratic<O: Ops>(o: &mut O, h0: O::V, h1: O::V, h2: O::V, x: O::V) -> O::V {
    let half = Fp3::from_base(Goldilocks::new(2).inv());
    let d1 = o.sub(h1, h0);
    let g = Gate { qa: Fp3::ONE, qb: k(-2), qc: Fp3::ONE, ..Gate::default() };
    let d2 = o.gate(g, h2, h1, h0);
    let xx = o.mul_const_add(x, x, Fp3::ZERO);
    let g = Gate { qa: half, qb: -half, ..Gate::default() };
    let tri = o.gate(g, xx, x, x);
    let a = o.mul_add(x, d1, h0);
    o.mul_add(tri, d2, a)
}

/// `nxt(x, y)`: 1 iff `y = x + 1 mod 2^n` on the cube (`air::public::next_eval`).
pub fn next_eval<O: Ops>(o: &mut O, x: &[O::V], y: &[O::V]) -> O::V {
    let n = x.len();
    let mut suffix: Vec<Option<O::V>> = vec![None; n + 1];
    for i in (0..n).rev() {
        let g = Gate { qm: k(2), qa: k(-1), qb: k(-1), qk: Fp3::ONE, ..Gate::default() };
        let e = o.gate(g, x[i], y[i], y[i]);
        suffix[i] = Some(match suffix[i + 1] {
            None => e,
            Some(s) => o.mul(s, e),
        });
    }
    let mut carry: Option<O::V> = None;
    let mut acc: Option<O::V> = None;
    for i in 0..n {
        // (1 − x_i)·y_i
        let g = Gate { qm: -Fp3::ONE, qb: Fp3::ONE, ..Gate::default() };
        let mut t = o.gate(g, x[i], y[i], y[i]);
        if let Some(c) = carry {
            t = o.mul(t, c);
        }
        if let Some(s) = suffix[i + 1] {
            t = o.mul(t, s);
        }
        acc = Some(match acc {
            None => t,
            Some(a) => o.add(a, t),
        });
        // x_i·(1 − y_i)
        let g = Gate { qm: -Fp3::ONE, qa: Fp3::ONE, ..Gate::default() };
        let f = o.gate(g, x[i], y[i], y[i]);
        carry = Some(match carry {
            None => f,
            Some(c) => o.mul(c, f),
        });
    }
    match (acc, carry) {
        (Some(a), Some(c)) => o.add(a, c),
        _ => o.one(),
    }
}

/// `Π x_i`.
pub fn product<O: Ops>(o: &mut O, xs: &[O::V]) -> O::V {
    let mut acc: Option<O::V> = None;
    for &x in xs {
        acc = Some(match acc {
            None => x,
            Some(a) => o.mul(a, x),
        });
    }
    acc.unwrap_or_else(|| o.one())
}

/// `1, r, …, r^{m−1}`.
pub fn powers<O: Ops>(o: &mut O, r: O::V, m: usize) -> Vec<O::V> {
    let mut out = Vec::with_capacity(m);
    if m == 0 {
        return out;
    }
    out.push(o.one());
    if m > 1 {
        out.push(r);
    }
    for i in 2..m {
        let p = o.mul(out[i - 1], r);
        out.push(p);
    }
    out
}

/// `Σ_i c_i x_i` for variables `c`, `x`.
pub fn combine<O: Ops>(o: &mut O, c: &[O::V], x: &[O::V]) -> O::V {
    let mut acc: Option<O::V> = None;
    for (&a, &b) in c.iter().zip(x) {
        acc = Some(match acc {
            None => o.mul(a, b),
            Some(t) => o.mul_add(a, b, t),
        });
    }
    acc.unwrap_or_else(|| o.zero())
}

/// `Π_j (1 + b_j·(ω^{2^j} − 1)) = ω^{Σ b_j 2^j}` for bits `b` (low first).
pub fn pow_bits<O: Ops>(o: &mut O, omega: Goldilocks, bits: &[O::V]) -> O::V {
    let mut acc: Option<O::V> = None;
    let mut w = omega;
    for &b in bits {
        let c = Fp3::from_base(w - Goldilocks::ONE);
        acc = Some(match acc {
            None => o.affine(c, b, Fp3::ONE),
            Some(a) => {
                let g = Gate { qm: c, qa: Fp3::ONE, ..Gate::default() };
                o.gate(g, a, b, b)
            }
        });
        w = w * w;
    }
    acc.unwrap_or_else(|| o.one())
}

/// `Σ_i c_i x^i` (Horner).
pub fn horner<O: Ops>(o: &mut O, coeffs: &[O::V], x: O::V) -> O::V {
    let mut acc: Option<O::V> = None;
    for &c in coeffs.iter().rev() {
        acc = Some(match acc {
            None => c,
            Some(a) => o.mul_add(a, x, c),
        });
    }
    acc.unwrap_or_else(|| o.zero())
}

/// The multilinear polynomial with monomial coefficients `coeffs` (index
/// bit `k` ↔ variable `k`) at `point`: `f(x) = f_even(x_2..) + x_1·f_odd(x_2..)`.
pub fn monomial<O: Ops>(o: &mut O, coeffs: &[O::V], point: &[O::V]) -> O::V {
    assert_eq!(coeffs.len(), 1 << point.len());
    let mut cur = coeffs.to_vec();
    for &r in point {
        cur = cur.chunks(2).map(|p| o.mul_add(r, p[1], p[0])).collect();
    }
    cur[0]
}

/// `x^{2^k}`.
pub fn pow2k<O: Ops>(o: &mut O, x: O::V, k: usize) -> O::V {
    let mut y = x;
    for _ in 0..k {
        y = o.mul(y, y);
    }
    y
}

/// The symbol of `syms` (coset order) at position `Σ bits_j 2^j`.
pub fn mux<O: Ops>(o: &mut O, syms: &[O::V], bits: &[O::V]) -> O::V {
    assert_eq!(syms.len(), 1 << bits.len());
    let mut cur = syms.to_vec();
    for &b in bits {
        cur = cur.chunks(2).map(|p| o.lerp(b, p[0], p[1])).collect();
    }
    cur[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::ops::Native;
    use lens::rspcs::field::{eq_eval, ml_eval_ext, pow_point, quadratic_at};

    fn e(i: u64) -> Fp3 {
        Fp3::new(Goldilocks::new(i * 7 + 1), Goldilocks::new(i + 11), Goldilocks::new(3 * i + 2))
    }

    #[test]
    fn generic_arithmetic_matches_the_reference() {
        let mut o = Native::new();
        let a: Vec<Fp3> = (0..5).map(e).collect();
        let b: Vec<Fp3> = (5..10).map(e).collect();
        assert_eq!(eq(&mut o, &a, &b), eq_eval(&a, &b));
        assert_eq!(eq_pow(&mut o, e(3), &b), eq_eval(&pow_point(e(3), 5), &b));
        let p: Vec<Fp3> = vec![Fp3::ZERO, Fp3::ONE, Fp3::ONE, Fp3::ZERO, Fp3::ONE];
        assert_eq!(eq_row(&mut o, 0b10110, &b), eq_eval(&p, &b));
        let vals: Vec<Fp3> = (0..23).map(e).collect();
        let mut padded = vals.clone();
        padded.resize(32, Fp3::ZERO);
        assert_eq!(mle(&mut o, &vals, &b), ml_eval_ext(&padded, &b));
        let pts: Vec<Fp3> = (0..10).map(e).collect();
        let x = e(40);
        assert_eq!(
            interpolate(&mut o, &pts, x),
            crate::air::zerocheck_interpolate(&pts, x)
        );
        assert_eq!(quadratic(&mut o, e(1), e(2), e(3), x), quadratic_at(e(1), e(2), e(3), x));
        assert_eq!(next_eval(&mut o, &a, &b), crate::air::public::next_eval(&a, &b));
        let w = lens::rspcs::field::root_of_unity(8);
        let bits: Vec<Fp3> = [1u64, 0, 1, 1, 0, 0, 0, 0].iter().map(|&v| Fp3::from_base(Goldilocks::new(v))).collect();
        assert_eq!(pow_bits(&mut o, w, &bits), Fp3::from_base(w.exp(13)));
        let syms: Vec<Fp3> = (0..8).map(e).collect();
        assert_eq!(mux(&mut o, &syms, &bits[..3]), e(5));
        let cs: Vec<Fp3> = (0..8).map(e).collect();
        assert_eq!(horner(&mut o, &cs, x), lens::rspcs::field::univariate_ext(&cs, x));
        assert_eq!(monomial(&mut o, &cs, &a[..3]), lens::rspcs::field::coeff_ml_eval(&cs, &a[..3]));
        let x2 = x * x;
        let x4 = x2 * x2;
        assert_eq!(pow2k(&mut o, x, 3), x4 * x4);
        assert!(o.error.is_none());
    }
}
