// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Sumcheck provers: bilinear (inner) and multi-multilinear (outer).
//!
//! `SumcheckProver` — bilinear bookkeeping for the inner sumcheck:
//!   Σ_{x ∈ {0,1}^k} w(x) · f(x) = claim.
//!
//! `OuterSumcheckProver` — multi-multilinear bookkeeping for the outer sumcheck:
//!   Σ_{x ∈ {0,1}^{log m}} eq(τ,x) · G(x) = claim,
//! where G(x) = Σ_j c_j · ∏_{i∈S_j} f_i(x) has degree max|S_j| in each variable.
//! Round polynomials have degree max|S_j|+1.  For m=1: 0 rounds, empty output.

use nebu::Goldilocks;

use crate::field::ChallengeField;
use crate::multilinear::evals_to_coeffs;
use crate::par;
use crate::types::SumcheckPoly;

/// Pairs per worker below which a round stays on one thread.
const MIN_PAIRS: usize = 1 << 11;

/// `table[m] ← table[m] + r·(table[m+half] − table[m])`, truncated to half
/// — the MSB fold, the same values as `(1−r)·lo + r·hi`.
fn fold_table<F: ChallengeField>(table: &mut Vec<F>, r: F) {
    let half = table.len() / 2;
    assert!(half >= 1 && table.len().is_power_of_two(), "table must be power-of-2 size ≥ 2");
    let (lo, hi) = table.split_at_mut(half);
    let hi = &*hi;
    par::chunks_mut(lo, MIN_PAIRS, |off, c| {
        for (k, v) in c.iter_mut().enumerate() {
            *v = *v + r * (hi[off + k] - *v);
        }
    });
    table.truncate(half);
}

/// Fold a base-field table by an extension challenge.
fn fold_base<F: ChallengeField>(table: &[Goldilocks], r: F) -> Vec<F> {
    let half = table.len() / 2;
    let (lo, hi) = table.split_at(half);
    let mut out = vec![F::ZERO; half];
    par::chunks_mut(&mut out, MIN_PAIRS, |off, c| {
        for (k, v) in c.iter_mut().enumerate() {
            let a = lo[off + k];
            *v = F::from_base(a) + r.mul_base(hi[off + k] - a);
        }
    });
    out
}

#[inline]
fn pow<V: ChallengeField>(x: V, k: u32) -> V {
    match k {
        1 => x,
        2 => x * x,
        _ => {
            let (mut base, mut e, mut acc) = (x, k, V::ONE);
            while e > 0 {
                if e & 1 == 1 {
                    acc = acc * base;
                }
                base = base * base;
                e >>= 1;
            }
            acc
        }
    }
}

/// Bilinear sumcheck prover for Σ_x w(x)·f(x) = claim.
///
/// w is the "weight" table (known to both prover and verifier).
/// f is the "witness" table (committed; evaluations provided by the prover).
pub struct SumcheckProver<F: ChallengeField = Goldilocks> {
    w_table: Vec<F>,
    f_table: Vec<F>,
    num_vars: usize,
    round: usize,
}

impl<F: ChallengeField> SumcheckProver<F> {
    /// Create a new prover. `w` and `f` must both have length 2^num_vars.
    pub fn new(w: Vec<F>, f: Vec<F>) -> Self {
        debug_assert_eq!(w.len(), f.len());
        debug_assert!(w.len().is_power_of_two());
        let num_vars = w.len().trailing_zeros() as usize;
        Self { w_table: w, f_table: f, num_vars, round: 0 }
    }

    /// The claim of the current round: Σ_x w(x)·f(x) over the tables.
    pub fn claimed_sum(&self) -> F {
        let (w, f) = (&self.w_table, &self.f_table);
        par::ranges(w.len(), MIN_PAIRS, |r| r.fold(F::ZERO, |acc, i| acc + w[i] * f[i]))
            .into_iter()
            .fold(F::ZERO, |a, b| a + b)
    }

    /// Number of sumcheck rounds remaining.
    pub fn rounds_remaining(&self) -> usize {
        self.num_vars - self.round
    }

    /// The round polynomial g (degree 2, g(0) + g(1) = the current claim),
    /// interpolated from t = 0, 1, 2.
    pub fn round_poly(&self) -> SumcheckPoly<F> {
        let half = self.w_table.len() / 2;
        let (w, f) = (&self.w_table, &self.f_table);
        let evals = par::ranges(half, MIN_PAIRS, |range| {
            let mut e = [F::ZERO; 3];
            for m in range {
                let (w0, f0) = (w[m], f[m]);
                let (dw, df) = (w[m + half] - w0, f[m + half] - f0);
                let (w1, f1) = (w0 + dw, f0 + df);
                e[0] = e[0] + w0 * f0;
                e[1] = e[1] + w1 * f1;
                e[2] = e[2] + (w1 + dw) * (f1 + df);
            }
            e
        })
        .into_iter()
        .fold([F::ZERO; 3], |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]]);
        SumcheckPoly { degree: 2, coeffs: evals_to_coeffs(&evals) }
    }

    /// Fold both tables with challenge r, advancing to the next round.
    pub fn fold(&mut self, r: F) {
        fold_table(&mut self.w_table, r);
        fold_table(&mut self.f_table, r);
        self.round += 1;
    }

    /// Final evaluation claim after all rounds: `(w(r), f(r))`.
    pub fn final_claim(&self) -> (F, F) {
        debug_assert_eq!(self.w_table.len(), 1);
        (self.w_table[0], self.f_table[0])
    }

    /// Run all rounds, applying `challenge_fn` to each round polynomial to get the challenge.
    pub fn prove_all<C>(&mut self, mut challenge_fn: C) -> Vec<SumcheckPoly<F>>
    where
        C: FnMut(&SumcheckPoly<F>) -> F,
    {
        let mut polys = Vec::with_capacity(self.num_vars);
        while self.round < self.num_vars {
            let poly = self.round_poly();
            let r = challenge_fn(&poly);
            polys.push(poly);
            self.fold(r);
        }
        polys
    }
}

/// Multi-multilinear outer sumcheck prover for SuperSpartan.
///
/// Proves Σ_{x ∈ {0,1}^{log m}} eq(τ, x) · G(x) = claim, where:
///   G(x) = Σ_j c_j · ∏_{i ∈ S_j} f_i(x)  (degree = max |S_j|).
///
/// Round polynomials have degree (max|S_j|+1), evaluated at d+2 points.
/// For m=1 (num_vars=0): prove_all returns []; matrix_evals returns f_tables[i][0].
///
/// The tables may start over the base field ([`Self::new_base`]): the
/// first round then multiplies in Goldilocks and lifts once per point; the
/// first fold moves them to `F`. The round polynomials are the same field
/// elements either way.
pub struct OuterSumcheckProver<F: ChallengeField = Goldilocks> {
    eq_table: Vec<F>,
    /// f_tables[i][r] = M_i[row r] · z — one entry per matrix, one slot per
    /// row (empty while the base tables are still in use).
    pub f_tables: Vec<Vec<F>>,
    base: Option<(Vec<Vec<Goldilocks>>, Vec<Goldilocks>)>,
    /// Each multiset as (table, multiplicity) pairs.
    terms: Vec<Vec<(usize, u32)>>,
    coeffs: Vec<F>,
    degree: usize,
    num_vars: usize,
    round: usize,
}

fn group(multisets: &[Vec<usize>]) -> Vec<Vec<(usize, u32)>> {
    multisets
        .iter()
        .map(|ms| {
            let mut t: Vec<(usize, u32)> = Vec::new();
            for &i in ms {
                match t.iter_mut().find(|(j, _)| *j == i) {
                    Some((_, k)) => *k += 1,
                    None => t.push((i, 1)),
                }
            }
            t
        })
        .collect()
}

/// `(h(0), …, h(points−1))` of `Σ_b eq_t(b) · G_t(b)` over the pairs of
/// `tables` (values in `V`), each point's `G` lifted into `F` by `scale`.
fn outer_evals<F: ChallengeField, V: ChallengeField>(
    eq: &[F],
    tables: &[&[V]],
    terms: &[Vec<(usize, u32)>],
    coeffs: &[V],
    points: usize,
    scale: impl Fn(F, V) -> F + Sync,
) -> Vec<F> {
    let half = eq.len() / 2;
    let n = tables.len();
    par::ranges(half, MIN_PAIRS, |range| {
        let mut acc = vec![F::ZERO; points];
        let mut cur = vec![V::ZERO; n];
        let mut step = vec![V::ZERO; n];
        for m in range {
            for i in 0..n {
                let lo = tables[i][m];
                cur[i] = lo;
                step[i] = tables[i][m + half] - lo;
            }
            let mut e = eq[m];
            let de = eq[m + half] - e;
            for (t, a) in acc.iter_mut().enumerate() {
                if t > 0 {
                    for i in 0..n {
                        cur[i] = cur[i] + step[i];
                    }
                    e = e + de;
                }
                let mut g = V::ZERO;
                for (ts, &c) in terms.iter().zip(coeffs) {
                    let mut prod = c;
                    for &(i, k) in ts {
                        prod = prod * pow(cur[i], k);
                    }
                    g = g + prod;
                }
                *a = *a + scale(e, g);
            }
        }
        acc
    })
    .into_iter()
    .fold(vec![F::ZERO; points], |mut a, b| {
        for (x, y) in a.iter_mut().zip(b) {
            *x = *x + y;
        }
        a
    })
}

impl<F: ChallengeField> OuterSumcheckProver<F> {
    /// Create a new prover.
    ///
    /// `eq_table` = eq_evals(τ) of length m = 2^log_m.
    /// `f_tables[i]` = per-row M_i·z evaluations, length m.
    /// `multisets`, `coeffs` come directly from the CCSInstance.
    pub fn new(
        eq_table: Vec<F>,
        f_tables: Vec<Vec<F>>,
        multisets: Vec<Vec<usize>>,
        coeffs: Vec<F>,
    ) -> Self {
        debug_assert!(eq_table.len().is_power_of_two() || eq_table.len() == 1);
        for ft in &f_tables {
            debug_assert_eq!(ft.len(), eq_table.len());
        }
        let num_vars = eq_table.len().trailing_zeros() as usize;
        let degree = multisets.iter().map(|ms| ms.len()).max().unwrap_or(1);
        Self {
            eq_table,
            f_tables,
            base: None,
            terms: group(&multisets),
            coeffs,
            degree,
            num_vars,
            round: 0,
        }
    }

    /// [`Self::new`] over base-field tables and coefficients.
    pub fn new_base(
        eq_table: Vec<F>,
        f_tables: Vec<Vec<Goldilocks>>,
        multisets: Vec<Vec<usize>>,
        coeffs: Vec<Goldilocks>,
    ) -> Self {
        let lifted: Vec<F> = coeffs.iter().map(|&c| F::from_base(c)).collect();
        let mut p = Self::new(eq_table, vec![], multisets, lifted);
        for ft in &f_tables {
            debug_assert_eq!(ft.len(), p.eq_table.len());
        }
        if p.num_vars == 0 {
            p.f_tables = f_tables
                .iter()
                .map(|t| t.iter().map(|&v| F::from_base(v)).collect())
                .collect();
        } else {
            p.base = Some((f_tables, coeffs));
        }
        p
    }

    /// The claim of the current round: Σ_b eq(b) · G(b) over the tables.
    pub fn claimed_sum(&self) -> F {
        // the sum is the round polynomial's h(0) + h(1); with no rounds left
        // it is the single entry
        if self.round == self.num_vars {
            let mut g = F::ZERO;
            for (ts, &c) in self.terms.iter().zip(&self.coeffs) {
                let mut prod = c;
                for &(i, k) in ts {
                    prod = prod * pow(self.f_tables[i][0], k);
                }
                g = g + prod;
            }
            return self.eq_table[0] * g;
        }
        let poly = self.round_poly();
        poly.eval_0() + poly.eval_1()
    }

    /// Round polynomial h(t) = Σ_b eq_t(b) · G_t(b), evaluated at t=0,1,...,degree+1.
    ///
    /// Degree of h = degree+1. Interpolated from degree+2 evaluation points.
    pub fn round_poly(&self) -> SumcheckPoly<F> {
        let points = self.degree + 2;
        let evals = match &self.base {
            Some((tables, coeffs)) => {
                let tables: Vec<&[Goldilocks]> = tables.iter().map(Vec::as_slice).collect();
                outer_evals(&self.eq_table, &tables, &self.terms, coeffs, points, |e, g| e.mul_base(g))
            }
            None => {
                let tables: Vec<&[F]> = self.f_tables.iter().map(Vec::as_slice).collect();
                outer_evals(&self.eq_table, &tables, &self.terms, &self.coeffs, points, |e, g| e * g)
            }
        };
        SumcheckPoly { degree: (self.degree + 1) as u8, coeffs: evals_to_coeffs(&evals) }
    }

    /// Fold eq_table and all f_tables with challenge r, advancing one round.
    pub fn fold(&mut self, r: F) {
        fold_table(&mut self.eq_table, r);
        match self.base.take() {
            Some((tables, _)) => {
                self.f_tables = tables.iter().map(|t| fold_base(t, r)).collect();
            }
            None => {
                for ft in &mut self.f_tables {
                    fold_table(ft, r);
                }
            }
        }
        self.round += 1;
    }

    /// Run all rounds, applying `challenge_fn` to get each challenge.
    pub fn prove_all<C>(&mut self, mut challenge_fn: C) -> Vec<SumcheckPoly<F>>
    where
        C: FnMut(&SumcheckPoly<F>) -> F,
    {
        let mut polys = Vec::with_capacity(self.num_vars);
        while self.round < self.num_vars {
            let poly = self.round_poly();
            let r = challenge_fn(&poly);
            polys.push(poly);
            self.fold(r);
        }
        polys
    }

    /// After all rounds: f_tables[i][0] = û_i(ρ_x) via MLE folding.
    pub fn matrix_evals(&self) -> Vec<F> {
        debug_assert!(self.f_tables.iter().all(|t| t.len() == 1));
        self.f_tables.iter().map(|t| t[0]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multilinear::eq_evals;

    #[test]
    fn bilinear_sumcheck_consistent() {
        // f = all-ones, w = eq_evals at random point
        let r_outer = vec![Goldilocks::new(3), Goldilocks::new(7)];
        let w = eq_evals(&r_outer);
        let f = vec![Goldilocks::new(1); 4];
        let mut prover = SumcheckProver::new(w, f);
        let _claimed = prover.claimed_sum(); // retained to show original API usage
        let mut round_polys = Vec::new();
        let challenges = [Goldilocks::new(5), Goldilocks::new(11)];
        for &c in &challenges {
            let poly = prover.round_poly();
            // Each round poly sums to the CURRENT claim, not the initial one.
            assert_eq!(poly.eval_0() + poly.eval_1(), prover.claimed_sum());
            round_polys.push(poly);
            prover.fold(c);
        }
        // after 2 rounds: single entry
        let (w_final, f_final) = prover.final_claim();
        assert_eq!(w_final * f_final, prover.claimed_sum());
    }
}
#[cfg(test)]
mod pairing_tests {
    use nebu::Goldilocks;
    use crate::multilinear::eq_evals;
    use crate::sumcheck::prover::OuterSumcheckProver;

    /// The outer fold pins the MSB row bit with the round-0 challenge, so the
    /// folded matrix eval equals the MLE weighted by eq of the REVERSED
    /// challenge order. spartan prover/verifier step 7/9 depend on this
    /// pairing when they rebuild w_combined; a change here must change them.
    #[test]
    fn outer_fold_pairs_challenges_msb_first() {
        let g = Goldilocks::new;
        let f = vec![g(1), g(2), g(3), g(4)];
        let tau = vec![g(10), g(20)];
        let eq_t = eq_evals(&tau);
        let mut p = OuterSumcheckProver::new(
            eq_t, vec![f.clone()], vec![vec![0]], vec![Goldilocks::ONE],
        );
        let ch = [g(5), g(7)];
        let mut i = 0;
        let _ = p.prove_all(|_| { let c = ch[i]; i += 1; c });
        let u = p.f_tables[0][0];

        let rev_paired: Goldilocks = eq_evals(&[ch[1], ch[0]]).iter().zip(f.iter())
            .fold(Goldilocks::ZERO, |a, (&w, &v)| a + w * v);
        let lsb_paired: Goldilocks = eq_evals(&ch).iter().zip(f.iter())
            .fold(Goldilocks::ZERO, |a, (&w, &v)| a + w * v);
        assert_eq!(u.as_u64(), rev_paired.as_u64(), "fold is MSB-first");
        assert_ne!(u.as_u64(), lsb_paired.as_u64(), "pairing direction matters");
    }
}

#[cfg(test)]
mod reference_tests {
    use nebu::{Fp3, Goldilocks};

    use super::OuterSumcheckProver;
    use crate::multilinear::{eq_evals, evals_to_coeffs, fold_inplace};

    /// The textbook round: every point, every product, no reuse.
    fn naive_round(eq: &[Fp3], f: &[Vec<Fp3>], ms: &[Vec<usize>], c: &[Fp3], d: usize) -> Vec<Fp3> {
        let half = eq.len() / 2;
        let evals: Vec<Fp3> = (0..d + 2)
            .map(|t| {
                let t = Fp3::from_base(Goldilocks::new(t as u64));
                (0..half).fold(Fp3::ZERO, |acc, m| {
                    let at = |v: &[Fp3]| (Fp3::ONE - t) * v[m] + t * v[m + half];
                    let g = ms.iter().zip(c).fold(Fp3::ZERO, |g, (s, &c)| {
                        g + c * s.iter().fold(Fp3::ONE, |p, &i| p * at(&f[i]))
                    });
                    acc + at(eq) * g
                })
            })
            .collect();
        evals_to_coeffs(&evals)
    }

    #[test]
    fn base_and_threaded_rounds_equal_the_textbook_rounds() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            Goldilocks::new(seed)
        };
        let ms = vec![vec![0, 1], vec![2], vec![3; 7], vec![4]];
        for log_m in [1usize, 5, 13] {
            let m = 1 << log_m;
            let base: Vec<Vec<Goldilocks>> = (0..5).map(|_| (0..m).map(|_| next()).collect()).collect();
            let coeffs = vec![Goldilocks::ONE, -Goldilocks::ONE, next(), -Goldilocks::ONE];
            let tau: Vec<Fp3> = (0..log_m).map(|_| Fp3::new(next(), next(), next())).collect();
            let mut f: Vec<Vec<Fp3>> = base.iter().map(|t| t.iter().map(|&v| Fp3::from_base(v)).collect()).collect();
            let c: Vec<Fp3> = coeffs.iter().map(|&v| Fp3::from_base(v)).collect();
            let mut eq = eq_evals(&tau);
            let mut p = OuterSumcheckProver::new_base(eq.clone(), base, ms.clone(), coeffs);
            let mut q = OuterSumcheckProver::new(eq.clone(), f.clone(), ms.clone(), c.clone());
            for _ in 0..log_m {
                let want = naive_round(&eq, &f, &ms, &c, 7);
                assert_eq!(p.round_poly().coeffs, want);
                assert_eq!(q.round_poly().coeffs, want);
                let r = Fp3::new(next(), next(), next());
                p.fold(r);
                q.fold(r);
                fold_inplace(&mut eq, r);
                for t in &mut f {
                    fold_inplace(t, r);
                }
            }
            assert_eq!(p.matrix_evals(), f.iter().map(|t| t[0]).collect::<Vec<_>>());
            assert_eq!(q.matrix_evals(), p.matrix_evals());
        }
    }
}
