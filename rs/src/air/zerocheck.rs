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

/// Rounds over at least this many rows run on the device.
const DEVICE_MIN: usize = 1 << 10;
/// A device session's rounds over at most this many pairs run on the CPU.
const CPU_TAIL: usize = 1 << 8;

/// The backend program of a recorded combination.
fn program(g: &super::num::Graph) -> lens::rspcs::program::Program {
    let c = g.compile();
    let (ops, consts, inputs, outputs) = c.parts();
    let consts = consts.iter().map(|&x| lens::rspcs::program::from_fp3(x)).collect();
    lens::rspcs::program::Program::from_slots(ops, consts, inputs, outputs[0])
}

/// Every column's canonical limbs, column-major (in threads).
fn pack_flat(cols: &[Vec<Fp3>]) -> Vec<[u64; 3]> {
    use lens::rspcs::program::from_fp3;
    let len = cols.first().map_or(0, Vec::len);
    let mut flat = vec![[0u64; 3]; cols.len() * len];
    let per = cols.len().div_ceil(threads()).max(1);
    std::thread::scope(|s| {
        for (chunk, cs) in flat.chunks_mut(len * per).zip(cols.chunks(per)) {
            s.spawn(move || {
                for (dst, c) in chunk.chunks_mut(len).zip(cs) {
                    for (d, v) in dst.iter_mut().zip(c) {
                        *d = from_fp3(*v);
                    }
                }
            });
        }
    });
    flat
}

/// The points a round evaluates and the `q` they fill.
fn round_points(deg: usize, on_cube: bool, skip_one: bool) -> Vec<u64> {
    let first = if on_cube { 2 } else { 0 };
    (first..deg).filter(|&x| !(x == 1 && skip_one)).map(|x| x as u64).collect()
}

/// [`round`] on the prover backend: the same `q` at the same points.
fn device_round(p: &lens::rspcs::program::Program, cols: &[Vec<Fp3>], eq: &[Fp3], deg: usize, on_cube: bool, skip_one: bool) -> Vec<Fp3> {
    use lens::rspcs::program::{from_fp3, to_fp3};
    let xs = round_points(deg, on_cube, skip_one);
    let flat = pack_flat(cols);
    let weights: Vec<[u64; 3]> = eq.chunks_exact(2).map(|e| from_fp3(e[0] + e[1])).collect();
    let sums = lens::rspcs::backend::current().line_sums(p, &flat, &weights, &xs);
    let mut q = vec![Fp3::ZERO; deg + 1];
    for (&x, v) in xs.iter().zip(sums) {
        q[x as usize] = to_fp3(v);
    }
    q
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
    // a device backend evaluates the rounds from the recorded constraint
    // polynomial (the same values as `round`)
    let backend = lens::rspcs::backend::current();
    let device = (backend.name() != "cpu")
        .then(|| air.combine_graph(cols.len(), ch, mu))
        .flatten()
        .map(|g| program(&g));
    // the columns resident on the device across rounds (folded there)
    let mut session = device.as_ref().and_then(|p| backend.line_session(p, &pack_flat(&cols), eq.len()));
    if session.is_some() {
        cols = Vec::new();
    }
    for r in 0..n {
        // the last rounds' few pairs: the columns come back to the CPU
        // (a device round there costs its interpreter's latency)
        if eq.len() / 2 <= CPU_TAIL
            && let Some(mut sess) = session.take()
        {
            let len = eq.len();
            let flat = sess.columns();
            cols = flat.chunks_exact(len).map(|c| c.iter().map(|&v| lens::rspcs::program::to_fp3(v)).collect()).collect();
        }
        let (l0, l1) = eq
            .chunks_exact(2)
            .find(|p| p[0] + p[1] != Fp3::ZERO)
            .map_or((Fp3::ZERO, Fp3::ZERO), |p| {
                let gi = (p[0] + p[1]).inv();
                (p[0] * gi, p[1] * gi)
            });
        let skip_one = r > 0 && l1 != Fp3::ZERO;
        let mut q = match (&mut session, &device) {
            (Some(sess), _) => {
                let xs = round_points(deg, r == 0, skip_one);
                let weights: Vec<[u64; 3]> = eq.chunks_exact(2).map(|e| lens::rspcs::program::from_fp3(e[0] + e[1])).collect();
                let mut q = vec![Fp3::ZERO; deg + 1];
                for (&x, v) in xs.iter().zip(sess.sums(&weights, &xs)) {
                    q[x as usize] = lens::rspcs::program::to_fp3(v);
                }
                q
            }
            (None, Some(p)) if eq.len() >= DEVICE_MIN && eq.len() / 2 > CPU_TAIL => device_round(p, &cols, &eq, deg, r == 0, skip_one),
            _ => round(air, w, &cols, &eq, ch, mu, deg, r == 0, skip_one),
        };
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
        match &mut session {
            Some(sess) => sess.fold(lens::rspcs::program::from_fp3(alpha)),
            None => {
                for c in &mut cols {
                    fold(c, alpha);
                }
            }
        }
        fold(&mut eq, alpha);
        point.push(alpha);
    }
    let evals = match &mut session {
        Some(sess) => sess.firsts().into_iter().map(lens::rspcs::program::to_fp3).collect(),
        None => cols.iter().map(|c| c[0]).collect(),
    };
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

#[cfg(test)]
mod device_tests {
    use super::*;
    use crate::machine::air::{Constants, Machine};
    use crate::recursion::relation::{COLS, PUBS, Relation, View};

    fn e(k: u64) -> Fp3 {
        Fp3::new(Goldilocks::new(k * 31 + 7), Goldilocks::new(k ^ 0x55), Goldilocks::new(k * k + 1))
    }

    /// The device round (the recorded combination as a backend program,
    /// here on the CPU interpreter) gives `round`'s values on the step
    /// relation at random rows, off and on the cube.
    /// The CPU under another name with a resident session (the
    /// reference): the whole zerocheck proof equals the AIR's.
    struct Device;
    impl lens::rspcs::backend::Backend for Device {
        fn name(&self) -> &'static str {
            "device-test"
        }
        fn line_session<'a>(&'a self, p: &'a lens::rspcs::program::Program, cols: &[[u64; 3]], len: usize) -> Option<Box<dyn lens::rspcs::backend::LineSession + 'a>> {
            Some(Box::new(lens::rspcs::backend::CpuSession::new(p, cols, len)))
        }
    }

    #[test]
    fn a_resident_session_proves_as_the_air() {
        use crate::recursion::sponge::ProverTranscript;
        let n = 10;
        let constants = Constants { fml0: 3, obj0: 4, p: 9, output: [Goldilocks::new(5); 4], cycles: 77, root: [Goldilocks::ZERO; 4] };
        let rel = Relation::new(Machine::new(constants, &[], 1 << n, 0, 1 << n), [e(1), e(2)]);
        let view = View(&rel);
        let inputs = 2 * COLS + PUBS;
        let cols: Vec<Vec<Fp3>> = (0..inputs as u64).map(|c| (0..1u64 << n).map(|r| e(c * 97 + r)).collect()).collect();
        let eq: Vec<Fp3> = (0..1u64 << n).map(|r| e(r + 5000)).collect();
        let ch = [e(11), e(12)];
        let mu: Vec<Fp3> = (0..rel.constraints() as u64).map(|k| e(k + 9000)).collect();
        let mut t1 = ProverTranscript::new(1);
        let want = prove(&view, COLS, cols.clone(), eq.clone(), &ch, &mu, &mut t1);
        let prev = lens::rspcs::backend::install(std::sync::Arc::new(Device));
        let mut t2 = ProverTranscript::new(1);
        let got = prove(&view, COLS, cols, eq, &ch, &mu, &mut t2);
        lens::rspcs::backend::install(prev);
        assert_eq!(got, want);
    }

    #[test]
    fn device_rounds_equal_the_air_rounds() {
        let n = 10;
        let constants = Constants { fml0: 3, obj0: 4, p: 9, output: [Goldilocks::new(5); 4], cycles: 77, root: [Goldilocks::ZERO; 4] };
        let rel = Relation::new(Machine::new(constants, &[], 1 << n, 0, 1 << n), [e(1), e(2)]);
        let view = View(&rel);
        let inputs = 2 * COLS + PUBS;
        let cols: Vec<Vec<Fp3>> = (0..inputs as u64).map(|c| (0..1u64 << n).map(|r| e(c * 97 + r)).collect()).collect();
        let eq: Vec<Fp3> = (0..1u64 << n).map(|r| e(r + 5000)).collect();
        let ch = [e(11), e(12)];
        let mu: Vec<Fp3> = (0..rel.constraints() as u64).map(|k| e(k + 9000)).collect();
        let g = view.combine_graph(inputs, &ch, &mu).expect("graph");
        let p = program(&g);
        let deg = view.shape().degree + 1;
        for (cube, skip) in [(false, false), (false, true), (true, false)] {
            let want = round(&view, COLS, &cols, &eq, &ch, &mu, deg, cube, skip);
            let got = device_round(&p, &cols, &eq, deg, cube, skip);
            for x in 0..deg {
                if (cube && x < 2) || (skip && x == 1) {
                    continue;
                }
                assert_eq!(got[x], want[x], "x {x} cube {cube} skip {skip}");
            }
        }
    }
}
