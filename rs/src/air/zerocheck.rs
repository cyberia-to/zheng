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
    on_cube: bool,
    skip_one: bool,
) -> Vec<Fp3> {
    let pairs = eq.len() / 2;
    // the first round's points 0 and 1 are trace rows, where every
    // constraint of an honest trace vanishes: q(0) = q(1) = 0
    let first = if on_cube { 2 } else { 0 };
    if on_cube {
        if let Some(h) = round_mix(air, w, cols, eq, ch, mu, deg, first) {
            return h;
        }
    }
    let k = air.shape().constraints;
    let workers = threads().min(pairs.max(1));
    let chunk = pairs.div_ceil(workers);
    let parts: Vec<Vec<Fp3>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|wi| {
                s.spawn(move || {
                    let mut h = vec![Fp3::ZERO; deg + 1];
                    let mut vals = vec![Fp3::ZERO; cols.len()];
                    let mut step = vec![Fp3::ZERO; cols.len()];
                    let mut scratch = vec![Fp3::ZERO; k];
                    let lo_i = wi * chunk;
                    let hi_i = ((wi + 1) * chunk).min(pairs);
                    let start = Fp3::from_base(Goldilocks::new(first as u64));
                    for i in lo_i..hi_i {
                        let (e0, e1) = (eq[2 * i], eq[2 * i + 1]);
                        // every column along the line, one addition a point
                        for ((v, d), c) in vals.iter_mut().zip(step.iter_mut()).zip(cols) {
                            let (a, b) = (c[2 * i], c[2 * i + 1]);
                            *d = b - a;
                            *v = if first == 0 { a } else { a + start * *d };
                        }
                        // the eq factor of this round's variable comes out of
                        // the sum (`h = L·q`): one weight per pair
                        let g = e0 + e1;
                        if g == Fp3::ZERO {
                            continue;
                        }
                        for (x, hx) in h.iter_mut().enumerate().take(deg).skip(first) {
                            if x > first {
                                for (v, d) in vals.iter_mut().zip(&step) {
                                    *v += *d;
                                }
                            }
                            if x == 1 && skip_one {
                                continue;
                            }
                            *hx += g * combine(air, w, &vals, ch, mu, &mut scratch);
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

/// The first round in mixed arithmetic (the lines between two trace rows
/// are base-field): the same `h` as [`round`], `None` when the AIR has no
/// mixed evaluation.
#[allow(clippy::too_many_arguments)]
fn round_mix<A: Air>(air: &A, w: usize, cols: &[Vec<Fp3>], eq: &[Fp3], ch: &[Fp3], mu: &[Fp3], deg: usize, first: usize) -> Option<Vec<Fp3>> {
    use super::mix::Mix;
    let pairs = eq.len() / 2;
    let k = air.shape().constraints;
    {
        // probe: does the AIR evaluate in mixed arithmetic?
        let z = vec![Mix::B(Goldilocks::ZERO); cols.len()];
        let mut out = vec![Mix::B(Goldilocks::ZERO); k];
        let v = Vals { local: &z[..w], next: &z[w..2 * w], publics: &z[2 * w..] };
        if !air.eval_mix(&v, ch, &mut out) {
            return None;
        }
    }
    let workers = threads().min(pairs.max(1));
    let chunk = pairs.div_ceil(workers);
    let parts: Vec<Vec<Fp3>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|wi| {
                s.spawn(move || {
                    let mut h = vec![Fp3::ZERO; deg + 1];
                    let mut vals = vec![Mix::B(Goldilocks::ZERO); cols.len()];
                    let mut step = vec![Mix::B(Goldilocks::ZERO); cols.len()];
                    let mut scratch = vec![Mix::B(Goldilocks::ZERO); k];
                    let start = Mix::B(Goldilocks::new(first as u64));
                    for i in wi * chunk..((wi + 1) * chunk).min(pairs) {
                        let (e0, e1) = (eq[2 * i], eq[2 * i + 1]);
                        for ((v, d), c) in vals.iter_mut().zip(step.iter_mut()).zip(cols) {
                            let (a, b) = (Mix::of(c[2 * i]), Mix::of(c[2 * i + 1]));
                            *d = b - a;
                            *v = a + start * *d;
                        }
                        let g = e0 + e1;
                        if g == Fp3::ZERO {
                            continue;
                        }
                        for (x, hx) in h.iter_mut().enumerate().take(deg).skip(first) {
                            if x > first {
                                for (v, d) in vals.iter_mut().zip(&step) {
                                    *v += *d;
                                }
                            }
                            for sc in scratch.iter_mut() {
                                *sc = Mix::B(Goldilocks::ZERO);
                            }
                            let v = Vals { local: &vals[..w], next: &vals[w..2 * w], publics: &vals[2 * w..] };
                            air.eval_mix(&v, ch, &mut scratch);
                            let c = scratch.iter().zip(mu).fold(Fp3::ZERO, |acc, (&c, &m)| acc + c.scale(m));
                            *hx += g * c;
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
    Some(h)
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
    // h(X) = L(X)·q(X): L the eq factor of the round's variable (degree 1,
    // the same for every pair up to the pair's weight), q of degree
    // `deg − 1` — evaluated at `deg − 1` points (q(1) from the running
    // claim, the first round's q(0) = q(1) = 0), extrapolated to `deg`
    let mut claim = Fp3::ZERO;
    for r in 0..n {
        let (l0, l1) = eq
            .chunks_exact(2)
            .find(|p| p[0] + p[1] != Fp3::ZERO)
            .map_or((Fp3::ZERO, Fp3::ZERO), |p| {
                let gi = (p[0] + p[1]).inv();
                (p[0] * gi, p[1] * gi)
            });
        let skip_one = r > 0 && l1 != Fp3::ZERO;
        let mut q = round(air, w, &cols, &eq, ch, mu, deg, r == 0, skip_one);
        if skip_one {
            q[1] = (claim - l0 * q[0]) * l1.inv();
        }
        q[deg] = interpolate(&q[..deg], Fp3::from_base(Goldilocks::new(deg as u64)));
        let h: Vec<Fp3> = q
            .iter()
            .enumerate()
            .map(|(x, &qx)| {
                let xf = Fp3::from_base(Goldilocks::new(x as u64));
                (l0 + xf * (l1 - l0)) * qx
            })
            .collect();
        let msg: Vec<Fp3> = core::iter::once(h[0]).chain(h[2..].iter().copied()).collect();
        t.absorb_fp3_slice(&msg);
        msgs.push(msg);
        let alpha = t.squeeze_fp3();
        claim = interpolate(&h, alpha);
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
