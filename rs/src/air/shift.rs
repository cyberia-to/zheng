//! A degree-2 product sumcheck `Σ_y a(y)·b(y) = σ` over `n` variables
//! (lens order, low bit first); used to reduce the local and next-row
//! column claims of the zerocheck to one point.

use crate::fs::FiatShamir;
use lens::rspcs::field::quadratic_at;
use nebu::Fp3;

fn fold(v: &mut Vec<Fp3>, alpha: Fp3) {
    let half = v.len() / 2;
    for i in 0..half {
        let x = v[2 * i];
        v[i] = x + alpha * (v[2 * i + 1] - x);
    }
    v.truncate(half);
}

/// Prover: round messages `(h(0), h(2))`, the point. `bs` are folded
/// alongside `b` so the caller can read their values at the point.
pub(crate) fn prove(
    t: &mut impl FiatShamir,
    mut a: Vec<Fp3>,
    mut b: Vec<Fp3>,
    extra: &mut [Vec<Fp3>],
) -> (Vec<Fp3>, Vec<Fp3>) {
    let n = a.len().trailing_zeros() as usize;
    let mut msgs = Vec::with_capacity(2 * n);
    let mut point = Vec::with_capacity(n);
    for _ in 0..n {
        let (mut h0, mut h2) = (Fp3::ZERO, Fp3::ZERO);
        for (ap, bp) in a.chunks_exact(2).zip(b.chunks_exact(2)) {
            h0 += ap[0] * bp[0];
            h2 += (ap[1] + ap[1] - ap[0]) * (bp[1] + bp[1] - bp[0]);
        }
        t.absorb_fp3(h0);
        t.absorb_fp3(h2);
        msgs.push(h0);
        msgs.push(h2);
        let alpha = t.squeeze_fp3();
        fold(&mut a, alpha);
        fold(&mut b, alpha);
        for e in extra.iter_mut() {
            fold(e, alpha);
        }
        point.push(alpha);
    }
    (msgs, point)
}

/// Verifier: the point and the final claim.
pub(crate) fn verify(
    t: &mut impl FiatShamir,
    sigma: Fp3,
    msgs: &[Fp3],
    n: usize,
) -> Option<(Vec<Fp3>, Fp3)> {
    if msgs.len() != 2 * n {
        return None;
    }
    let mut claim = sigma;
    let mut point = Vec::with_capacity(n);
    for p in msgs.chunks_exact(2) {
        t.absorb_fp3(p[0]);
        t.absorb_fp3(p[1]);
        let alpha = t.squeeze_fp3();
        claim = quadratic_at(p[0], claim - p[0], p[1], alpha);
        point.push(alpha);
    }
    Some((point, claim))
}
