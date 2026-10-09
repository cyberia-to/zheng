//! The claim-batching sumcheck of an accumulation step (and of the
//! decider): for words `f_1..f_m` (multilinear in `ℓ` variables, tables in
//! lens's order — bit `k` of an index is variable `k`) and weights
//! `w_i = Σ_j c_ij · eq(z_ij, ·)`, prove
//!
//! ```text
//! Σ_{b ∈ {0,1}^ℓ} Σ_i w_i(b) · f_i(b) = σ
//! ```
//!
//! Variable `k` is bound in round `k` (low bit first), so the final point
//! `ρ` is in lens order. Round `k` sends `h(0), h(2)` of the degree-2 round
//! polynomial `h`; `h(1) = claim − h(0)`. The verifier ends with the claim
//! `Σ_i w_i(ρ) · f_i(ρ)` and the prover sends every `f_i(ρ)`.

use crate::fs::FiatShamir;
use lens::rspcs::field::{eq_eval, eq_table, quadratic_at};
use nebu::Fp3;

/// Weighted sum of evaluation claims on one word: `Σ_j coef_j · eq(point_j, ·)`.
#[derive(Clone, Debug, Default)]
pub struct Weight {
    pub terms: Vec<(Vec<Fp3>, Fp3)>,
}

impl Weight {
    /// `w(x) = Σ_j coef_j · eq(point_j, x)`.
    pub fn eval(&self, x: &[Fp3]) -> Fp3 {
        self.terms
            .iter()
            .fold(Fp3::ZERO, |acc, (p, c)| acc + *c * eq_eval(p, x))
    }
    /// The table of `w` over `{0,1}^ℓ`.
    pub fn table(&self, vars: usize) -> Vec<Fp3> {
        let mut out = vec![Fp3::ZERO; 1 << vars];
        for (p, c) in &self.terms {
            debug_assert_eq!(p.len(), vars);
            for (o, e) in out.iter_mut().zip(eq_table(p)) {
                *o += *c * e;
            }
        }
        out
    }
}

/// Run the prover over tables `f_i` and their weights; returns the round
/// messages `(h(0), h(2))…`, the point `ρ` and every `f_i(ρ)`.
pub fn prove(
    t: &mut impl FiatShamir,
    mut f: Vec<Vec<Fp3>>,
    weights: &[Weight],
    vars: usize,
) -> (Vec<Fp3>, Vec<Fp3>, Vec<Fp3>) {
    let mut w: Vec<Vec<Fp3>> = weights.iter().map(|w| w.table(vars)).collect();
    let mut msgs = Vec::with_capacity(2 * vars);
    let mut point = Vec::with_capacity(vars);
    for _ in 0..vars {
        let (mut h0, mut h2) = (Fp3::ZERO, Fp3::ZERO);
        for (fi, wi) in f.iter().zip(&w) {
            let (a, b) = round_sums(fi, wi);
            h0 += a;
            h2 += b;
        }
        t.absorb_fp3(h0);
        t.absorb_fp3(h2);
        msgs.push(h0);
        msgs.push(h2);
        let alpha = t.squeeze_fp3();
        for fi in &mut f {
            fold(fi, alpha);
        }
        for wi in &mut w {
            fold(wi, alpha);
        }
        point.push(alpha);
    }
    let evals = f.iter().map(|fi| fi[0]).collect();
    (msgs, point, evals)
}

/// `(Σ_b' f(0,b')w(0,b'), Σ_b' f(2,b')w(2,b'))` with variable 0 the low bit.
fn round_sums(f: &[Fp3], w: &[Fp3]) -> (Fp3, Fp3) {
    let (mut h0, mut h2) = (Fp3::ZERO, Fp3::ZERO);
    for (fp, wp) in f.chunks_exact(2).zip(w.chunks_exact(2)) {
        h0 += fp[0] * wp[0];
        let f2 = fp[1] + fp[1] - fp[0];
        let w2 = wp[1] + wp[1] - wp[0];
        h2 += f2 * w2;
    }
    (h0, h2)
}

fn fold(v: &mut Vec<Fp3>, alpha: Fp3) {
    let half = v.len() / 2;
    for i in 0..half {
        let a = v[2 * i];
        v[i] = a + alpha * (v[2 * i + 1] - a);
    }
    v.truncate(half);
}

/// Verifier: replay the rounds on claim `sigma`; returns `ρ` and the final
/// claim, or `None` on a malformed message list.
pub fn verify(
    t: &mut impl FiatShamir,
    sigma: Fp3,
    msgs: &[Fp3],
    vars: usize,
) -> Option<(Vec<Fp3>, Fp3)> {
    if msgs.len() != 2 * vars {
        return None;
    }
    let mut claim = sigma;
    let mut point = Vec::with_capacity(vars);
    for pair in msgs.chunks_exact(2) {
        let (h0, h2) = (pair[0], pair[1]);
        let h1 = claim - h0;
        t.absorb_fp3(h0);
        t.absorb_fp3(h2);
        let alpha = t.squeeze_fp3();
        claim = quadratic_at(h0, h1, h2, alpha);
        point.push(alpha);
    }
    Some((point, claim))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lens::Transcript;
    use lens::rspcs::field::ml_eval_ext;
    use nebu::Goldilocks;

    fn e(i: u64) -> Fp3 {
        Fp3::new(Goldilocks::new(i), Goldilocks::new(3 * i + 1), Goldilocks::new(i * i + 7))
    }

    #[test]
    fn batched_sumcheck_reduces_to_the_point_evaluations() {
        let vars = 5;
        let f: Vec<Vec<Fp3>> = (0..3u64)
            .map(|i| (0..32u64).map(|b| e(100 * i + b)).collect())
            .collect();
        let weights: Vec<Weight> = (0..3u64)
            .map(|i| Weight {
                terms: (0..2u64)
                    .map(|j| ((0..vars as u64).map(|k| e(7 * i + j + k)).collect(), e(i + j + 2)))
                    .collect(),
            })
            .collect();
        let sigma = f
            .iter()
            .zip(&weights)
            .map(|(fi, wi)| {
                wi.terms
                    .iter()
                    .fold(Fp3::ZERO, |a, (p, c)| a + *c * ml_eval_ext(fi, p))
            })
            .fold(Fp3::ZERO, |a, b| a + b);
        let mut tp = Transcript::new(b"t");
        let (msgs, point, evals) = prove(&mut tp, f.clone(), &weights, vars);
        let mut tv = Transcript::new(b"t");
        let (vp, claim) = verify(&mut tv, sigma, &msgs, vars).unwrap();
        assert_eq!(vp, point);
        for (fi, &v) in f.iter().zip(&evals) {
            assert_eq!(ml_eval_ext(fi, &point), v);
        }
        let expect = weights
            .iter()
            .zip(&evals)
            .fold(Fp3::ZERO, |a, (w, &v)| a + w.eval(&point) * v);
        assert_eq!(claim, expect);
        let mut tb = Transcript::new(b"t");
        let (_, bad) = verify(&mut tb, sigma + Fp3::ONE, &msgs, vars).unwrap();
        assert_ne!(bad, expect);
    }
}
