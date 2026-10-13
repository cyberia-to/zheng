//! The zerocheck of a uniform AIR:
//!
//! ```text
//! Σ_{x ∈ {0,1}^n} eq(τ, x) · Σ_k μ^k · C_k(W(x), W(x+1), P(x)) = 0
//! ```
//!
//! over the row variables (lens order: variable `k` ↔ bit `k` of the row,
//! bound low bit first). Every column — local, next-row and public — is a
//! multilinear table folded in place; round `j` sends the round polynomial
//! (degree `D + 1`) at `0, 2, 3, …, D + 1` (`h(1) = claim − h(0)`). The
//! prover ends with every column's value at the point `ρ`; the verifier
//! checks the last claim against `eq(τ, ρ)·Σ_k μ^k C_k(values)`.

use crate::fs::FiatShamir;
use nebu::{Fp3, Goldilocks};

use super::{Air, Vals};

/// `Σ_k μ^k C_k` at one assignment of the columns.
pub(crate) fn combine<A: Air>(
    air: &A,
    w: usize,
    vals: &[Fp3],
    ch: &[Fp3],
    mu: &[Fp3],
    scratch: &mut [Fp3],
) -> Fp3 {
    let v = Vals {
        local: &vals[..w],
        next: &vals[w..2 * w],
        publics: &vals[2 * w..],
    };
    for s in scratch.iter_mut() {
        *s = Fp3::ZERO;
    }
    air.eval(&v, ch, scratch);
    scratch
        .iter()
        .zip(mu)
        .fold(Fp3::ZERO, |acc, (&c, &m)| acc + c * m)
}

/// Value at `x` of the polynomial through `(i, values[i])`, `i = 0..len`.
pub(crate) fn interpolate(values: &[Fp3], x: Fp3) -> Fp3 {
    let n = values.len();
    let mut acc = Fp3::ZERO;
    for (i, &vi) in values.iter().enumerate() {
        let mut num = Fp3::ONE;
        let mut den = Goldilocks::ONE;
        for j in 0..n {
            if j != i {
                num *= x - Fp3::from_base(Goldilocks::new(j as u64));
                den *= Goldilocks::new(i as u64) - Goldilocks::new(j as u64);
            }
        }
        let d = den.inv();
        acc += vi * Fp3::new(num.c0 * d, num.c1 * d, num.c2 * d);
    }
    acc
}

fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get()).min(16)
}

/// One round: `h(X)` at `X = 0..=deg` from the current tables.
fn round<A: Air>(
    air: &A,
    w: usize,
    cols: &[Vec<Fp3>],
    eq: &[Fp3],
    ch: &[Fp3],
    mu: &[Fp3],
    deg: usize,
) -> Vec<Fp3> {
    let pairs = eq.len() / 2;
    let k = air.shape().constraints;
    let workers = threads().min(pairs.max(1));
    let chunk = pairs.div_ceil(workers);
    let parts: Vec<Vec<Fp3>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|wi| {
                s.spawn(move || {
                    let mut h = vec![Fp3::ZERO; deg + 1];
                    let mut vals = vec![Fp3::ZERO; cols.len()];
                    let mut scratch = vec![Fp3::ZERO; k];
                    let lo_i = wi * chunk;
                    let hi_i = ((wi + 1) * chunk).min(pairs);
                    for i in lo_i..hi_i {
                        let (e0, e1) = (eq[2 * i], eq[2 * i + 1]);
                        for (x, hx) in h.iter_mut().enumerate() {
                            let xf = Fp3::from_base(Goldilocks::new(x as u64));
                            let ex = e0 + xf * (e1 - e0);
                            if ex == Fp3::ZERO {
                                continue;
                            }
                            for (v, c) in vals.iter_mut().zip(cols) {
                                let (a, b) = (c[2 * i], c[2 * i + 1]);
                                *v = a + xf * (b - a);
                            }
                            *hx += ex * combine(air, w, &vals, ch, mu, &mut scratch);
                        }
                    }
                    h
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("zerocheck worker")).collect()
    });
    let mut h = vec![Fp3::ZERO; deg + 1];
    for p in parts {
        for (a, b) in h.iter_mut().zip(p) {
            *a += b;
        }
    }
    h
}

fn fold(v: &mut Vec<Fp3>, alpha: Fp3) {
    let half = v.len() / 2;
    for i in 0..half {
        let a = v[2 * i];
        v[i] = a + alpha * (v[2 * i + 1] - a);
    }
    v.truncate(half);
}

/// Prover. `cols` = local (`w`), next (`w`), public tables, each `2^n`
/// long; `eq` = the table of `eq(τ, ·)`. Returns the round messages, the
/// point and every column's value there.
#[allow(clippy::type_complexity)]
pub(crate) fn prove<A: Air>(
    air: &A,
    w: usize,
    mut cols: Vec<Vec<Fp3>>,
    mut eq: Vec<Fp3>,
    ch: &[Fp3],
    mu: &[Fp3],
    t: &mut impl FiatShamir,
) -> (Vec<Vec<Fp3>>, Vec<Fp3>, Vec<Fp3>) {
    let deg = air.shape().degree + 1;
    let n = eq.len().trailing_zeros() as usize;
    let mut msgs = Vec::with_capacity(n);
    let mut point = Vec::with_capacity(n);
    for _ in 0..n {
        let h = round(air, w, &cols, &eq, ch, mu, deg);
        let msg: Vec<Fp3> = core::iter::once(h[0]).chain(h[2..].iter().copied()).collect();
        t.absorb_fp3_slice(&msg);
        msgs.push(msg);
        let alpha = t.squeeze_fp3();
        for c in &mut cols {
            fold(c, alpha);
        }
        fold(&mut eq, alpha);
        point.push(alpha);
    }
    let evals = cols.iter().map(|c| c[0]).collect();
    (msgs, point, evals)
}

/// Verifier: returns the point and the final claim (to be checked by the
/// caller against `eq(τ, ρ)·Σ μ^k C_k`), or `None` on a malformed message.
pub(crate) fn verify(
    t: &mut impl FiatShamir,
    msgs: &[Vec<Fp3>],
    n: usize,
    degree: usize,
) -> Option<(Vec<Fp3>, Fp3)> {
    let deg = degree + 1;
    if msgs.len() != n || msgs.iter().any(|m| m.len() != deg) {
        return None;
    }
    let mut claim = Fp3::ZERO;
    let mut point = Vec::with_capacity(n);
    for msg in msgs {
        let mut h = Vec::with_capacity(deg + 1);
        h.push(msg[0]);
        h.push(claim - msg[0]);
        h.extend_from_slice(&msg[1..]);
        t.absorb_fp3_slice(msg);
        let alpha = t.squeeze_fp3();
        claim = interpolate(&h, alpha);
        point.push(alpha);
    }
    Some((point, claim))
}
