//! Libra masking polynomials for a zero-knowledge sumcheck.
//!
//! `g(x) = Σ_{i<R} g_i(x_i)` with every `g_i` a uniform polynomial of
//! degree `d` over Fp3 (Xie, Zhang, Zhang, Papamanthou, Song, "Libra",
//! CRYPTO 2019, eprint 2019/317, §4.1). The prover sends `G = Σ_{x∈{0,1}^R}
//! g(x)`, the verifier draws `ρ`, and the sumcheck runs on `f + ρ·g`. In
//! round `j` (MSB-first, variable `j` bound by challenge `r_j`) the mask
//! contributes
//!
//! ```text
//! s_j^g(X) = 2^{R−1−j}·(Σ_{i<j} g_i(r_i) + g_j(X)) + 2^{R−2−j}·Σ_{i>j} (g_i(0) + g_i(1))
//! ```
//!
//! so the coefficients of degree ≥ 1 of every round polynomial carry the
//! fresh coefficients of `g_j`, scaled by `ρ·2^{R−1−j} ≠ 0`: the round
//! messages are uniform among the transcripts that pass the verifier's
//! consistency checks, whatever `f` is. The final value `g(r)` is never
//! sent on its own; it reaches the verifier only inside the one linear
//! claim the hiding commitment opens.
//!
//! In the commitment a coefficient `c = c0 + c1·t + c2·t²` (Fp3 =
//! F_p[t]/(t³ − t − 1)) is three base-field entries, round by round, degree
//! by degree, limb by limb.

use nebu::{Fp3, Goldilocks};

use super::coins::Coins;
use crate::types::SumcheckPoly;

/// One mask: `R` univariate polynomials of degree `d`.
#[derive(Clone)]
pub(crate) struct Mask {
    /// `coeffs[i][k]`: coefficient of `x_i^k` in `g_i`.
    coeffs: Vec<Vec<Fp3>>,
}

fn two_pow(e: usize) -> Fp3 {
    Fp3::from_base(Goldilocks::new(2).exp(e as u64))
}

fn eval(c: &[Fp3], x: Fp3) -> Fp3 {
    c.iter().rev().fold(Fp3::ZERO, |acc, &k| acc * x + k)
}

/// `t^l` for the limb `l` of an Fp3 coefficient.
pub(crate) fn limb_basis(l: usize) -> Fp3 {
    let t = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
    (0..l).fold(Fp3::ONE, |acc, _| acc * t)
}

impl Mask {
    /// Base-field entries a mask of `rounds` rounds and degree `degree` takes.
    pub fn entries(rounds: usize, degree: usize) -> usize {
        rounds * (degree + 1) * 3
    }

    pub fn sample(rounds: usize, degree: usize, coins: &mut Coins) -> Self {
        Self {
            coeffs: (0..rounds)
                .map(|_| (0..=degree).map(|_| coins.ext()).collect())
                .collect(),
        }
    }

    /// The committed base-field entries, in the order documented above.
    pub fn limbs(&self) -> Vec<Goldilocks> {
        self.coeffs
            .iter()
            .flatten()
            .flat_map(|c| [c.c0, c.c1, c.c2])
            .collect()
    }

    /// `Σ_{x∈{0,1}^R} g(x)`.
    pub fn sum(&self) -> Fp3 {
        let r = self.coeffs.len();
        if r == 0 {
            return Fp3::ZERO;
        }
        let ends = self
            .coeffs
            .iter()
            .fold(Fp3::ZERO, |acc, c| acc + eval(c, Fp3::ZERO) + eval(c, Fp3::ONE));
        two_pow(r - 1) * ends
    }

    /// The mask's round-`j` polynomial (degree `d`) after challenges
    /// `prefix = (r_0, …, r_{j−1})`.
    pub fn round_poly(&self, prefix: &[Fp3]) -> Vec<Fp3> {
        let r = self.coeffs.len();
        let j = prefix.len();
        let bound = prefix
            .iter()
            .zip(&self.coeffs)
            .fold(Fp3::ZERO, |acc, (&x, c)| acc + eval(c, x));
        let scale = two_pow(r - 1 - j);
        let mut out: Vec<Fp3> = self.coeffs[j].iter().map(|&c| scale * c).collect();
        out[0] += scale * bound;
        if j + 1 < r {
            let rest = self.coeffs[j + 1..]
                .iter()
                .fold(Fp3::ZERO, |acc, c| acc + eval(c, Fp3::ZERO) + eval(c, Fp3::ONE));
            out[0] += two_pow(r - 2 - j) * rest;
        }
        out
    }

    /// `g(point)`.
    pub fn eval_at(&self, point: &[Fp3]) -> Fp3 {
        point
            .iter()
            .zip(&self.coeffs)
            .fold(Fp3::ZERO, |acc, (&x, c)| acc + eval(c, x))
    }
}

/// The weights of `scale·g(point)` on the mask's committed entries:
/// entry `(i, k, l)` gets `scale · point_i^k · t^l`.
pub(crate) fn weights(point: &[Fp3], degree: usize, scale: Fp3) -> Vec<Fp3> {
    let basis = [limb_basis(0), limb_basis(1), limb_basis(2)];
    let mut out = Vec::with_capacity(Mask::entries(point.len(), degree));
    for &x in point {
        let mut power = scale;
        for _ in 0..=degree {
            for b in basis {
                out.push(power * b);
            }
            power *= x;
        }
    }
    out
}

/// `f`'s round polynomial plus `ρ` times the mask's.
pub(crate) fn masked(f: SumcheckPoly<Fp3>, rho: Fp3, g: &[Fp3]) -> SumcheckPoly<Fp3> {
    debug_assert_eq!(f.coeffs.len(), g.len());
    SumcheckPoly {
        degree: f.degree,
        coeffs: f.coeffs.iter().zip(g).map(|(&a, &b)| a + rho * b).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute force: the mask's round polynomials sum and fold like any
    /// sumcheck, and the committed weights evaluate g.
    #[test]
    fn rounds_sums_and_weights_agree_with_brute_force() {
        let mut coins = Coins::seeded([3; 32]);
        for (rounds, degree) in [(1, 2), (3, 2), (4, 8)] {
            let g = Mask::sample(rounds, degree, &mut coins);
            let brute = (0..1usize << rounds).fold(Fp3::ZERO, |acc, x| {
                let p: Vec<Fp3> = (0..rounds)
                    .map(|i| Fp3::from_base(Goldilocks::new(((x >> (rounds - 1 - i)) & 1) as u64)))
                    .collect();
                acc + g.eval_at(&p)
            });
            assert_eq!(g.sum(), brute);
            let mut claim = g.sum();
            let mut prefix = vec![];
            for j in 0..rounds {
                let s = g.round_poly(&prefix);
                assert_eq!(eval(&s, Fp3::ZERO) + eval(&s, Fp3::ONE), claim, "round {j}");
                let r = coins.ext();
                claim = eval(&s, r);
                prefix.push(r);
            }
            assert_eq!(claim, g.eval_at(&prefix));
            let scale = coins.ext();
            let w = weights(&prefix, degree, scale);
            let dot = w
                .iter()
                .zip(g.limbs())
                .fold(Fp3::ZERO, |acc, (&w, v)| acc + w * Fp3::from_base(v));
            assert_eq!(dot, scale * g.eval_at(&prefix));
        }
    }
}
