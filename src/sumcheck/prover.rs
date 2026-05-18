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

use crate::multilinear::{evals_to_coeffs, fold_inplace, linear_ext};
use crate::types::SumcheckPoly;

/// Bilinear sumcheck prover for Σ_x w(x)·f(x) = claim.
///
/// w is the "weight" table (known to both prover and verifier).
/// f is the "witness" table (committed; evaluations provided by the prover).
pub struct SumcheckProver {
    w_table: Vec<Goldilocks>,
    f_table: Vec<Goldilocks>,
    current_claim: Goldilocks,
    num_vars: usize,
    round: usize,
}

impl SumcheckProver {
    /// Create a new prover.
    ///
    /// `w` and `f` must both have length 2^num_vars.
    /// `claimed_sum` = Σ_{x ∈ {0,1}^num_vars} w[x]·f[x].
    pub fn new(w: Vec<Goldilocks>, f: Vec<Goldilocks>) -> Self {
        debug_assert_eq!(w.len(), f.len());
        debug_assert!(w.len().is_power_of_two());
        let num_vars = w.len().trailing_zeros() as usize;
        let claimed_sum = w.iter().zip(f.iter()).fold(Goldilocks::ZERO, |acc, (&wi, &fi)| {
            acc + wi * fi
        });
        Self {
            current_claim: claimed_sum,
            w_table: w,
            f_table: f,
            num_vars,
            round: 0,
        }
    }

    /// Initial claimed sum.
    pub fn claimed_sum(&self) -> Goldilocks {
        self.current_claim
    }

    /// Number of sumcheck rounds remaining.
    pub fn rounds_remaining(&self) -> usize {
        self.num_vars - self.round
    }

    /// Compute the round polynomial for the current round.
    ///
    /// Returns a degree-2 polynomial g(t) such that g(0)+g(1) = current_claim.
    /// Evaluates at t=0,1,2.
    pub fn round_poly(&self) -> SumcheckPoly {
        let sz = self.w_table.len();
        let half = sz / 2;
        let mut evals = [Goldilocks::ZERO; 3];
        for m in 0..half {
            let w_lo = self.w_table[m];
            let w_hi = self.w_table[m + half];
            let f_lo = self.f_table[m];
            let f_hi = self.f_table[m + half];
            for (ti, t) in [Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::new(2)]
                .iter()
                .enumerate()
            {
                let wt = linear_ext(w_lo, w_hi, *t);
                let ft = linear_ext(f_lo, f_hi, *t);
                evals[ti] += wt * ft;
            }
        }
        let coeffs = evals_to_coeffs(&evals);
        SumcheckPoly { degree: 2, coeffs }
    }

    /// Fold both tables with challenge r, advancing to the next round.
    pub fn fold(&mut self, r: Goldilocks) {
        fold_inplace(&mut self.w_table, r);
        fold_inplace(&mut self.f_table, r);
        self.round += 1;
        // Current claim after folding: g(r) = (1-r)*lo_sum + r*hi_sum (computed by verifier).
        // Prover updates claim to g(r).
        self.current_claim = {
            // recompute as scalar product of the current (size-1 after all folds) tables
            // or — more precisely — just the round poly evaluated at r
            // We'll recompute from the folded tables
            self.w_table
                .iter()
                .zip(self.f_table.iter())
                .fold(Goldilocks::ZERO, |acc, (&wi, &fi)| acc + wi * fi)
        };
    }

    /// Final evaluation claim after all rounds.
    ///
    /// Returns (w_eval, f_eval) at the final point. The product must equal current_claim.
    pub fn final_claim(&self) -> (Goldilocks, Goldilocks) {
        debug_assert_eq!(self.w_table.len(), 1);
        (self.w_table[0], self.f_table[0])
    }

    /// Run all rounds, applying `challenge_fn` to each round polynomial to get the challenge.
    ///
    /// Returns the vector of round polynomials.
    pub fn prove_all<F>(&mut self, mut challenge_fn: F) -> Vec<SumcheckPoly>
    where
        F: FnMut(&SumcheckPoly) -> Goldilocks,
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
pub struct OuterSumcheckProver {
    eq_table: Vec<Goldilocks>,
    /// f_tables[i][r] = M_i[row r] · z — one entry per matrix, one slot per row.
    pub f_tables: Vec<Vec<Goldilocks>>,
    multisets: Vec<Vec<usize>>,
    coeffs: Vec<Goldilocks>,
    degree: usize,
    current_claim: Goldilocks,
    num_vars: usize,
    round: usize,
}

impl OuterSumcheckProver {
    /// Create a new prover.
    ///
    /// `eq_table` = eq_evals(τ) of length m = 2^log_m.
    /// `f_tables[i]` = per-row M_i·z evaluations, length m.
    /// `multisets`, `coeffs` come directly from the CCSInstance.
    pub fn new(
        eq_table: Vec<Goldilocks>,
        f_tables: Vec<Vec<Goldilocks>>,
        multisets: Vec<Vec<usize>>,
        coeffs: Vec<Goldilocks>,
    ) -> Self {
        debug_assert!(eq_table.len().is_power_of_two() || eq_table.len() == 1);
        for ft in &f_tables {
            debug_assert_eq!(ft.len(), eq_table.len());
        }
        let num_vars = eq_table.len().trailing_zeros() as usize;
        let degree = multisets.iter().map(|ms| ms.len()).max().unwrap_or(1);
        let claimed_sum = Self::compute_sum(&eq_table, &f_tables, &multisets, &coeffs);
        Self {
            eq_table,
            f_tables,
            multisets,
            coeffs,
            degree,
            current_claim: claimed_sum,
            num_vars,
            round: 0,
        }
    }

    fn compute_sum(
        eq_table: &[Goldilocks],
        f_tables: &[Vec<Goldilocks>],
        multisets: &[Vec<usize>],
        coeffs: &[Goldilocks],
    ) -> Goldilocks {
        let mut sum = Goldilocks::ZERO;
        for r in 0..eq_table.len() {
            let mut g_r = Goldilocks::ZERO;
            for (ms, &c) in multisets.iter().zip(coeffs.iter()) {
                let mut prod = Goldilocks::ONE;
                for &i in ms {
                    prod *= f_tables[i][r];
                }
                g_r += c * prod;
            }
            sum += eq_table[r] * g_r;
        }
        sum
    }

    pub fn claimed_sum(&self) -> Goldilocks {
        self.current_claim
    }

    /// Round polynomial h(t) = Σ_b eq_t(b) · G_t(b), evaluated at t=0,1,...,degree+1.
    ///
    /// Degree of h = degree+1. Interpolated from degree+2 evaluation points.
    pub fn round_poly(&self) -> SumcheckPoly {
        let sz = self.eq_table.len();
        let half = sz / 2;
        let num_pts = self.degree + 2;
        let mut evals = vec![Goldilocks::ZERO; num_pts];

        for m_idx in 0..half {
            let eq_lo = self.eq_table[m_idx];
            let eq_hi = self.eq_table[m_idx + half];
            let f_lo: Vec<Goldilocks> = self.f_tables.iter().map(|t| t[m_idx]).collect();
            let f_hi: Vec<Goldilocks> = self.f_tables.iter().map(|t| t[m_idx + half]).collect();

            for (t_int, eval) in evals.iter_mut().enumerate() {
                let t_val = Goldilocks::new(t_int as u64);
                let one_minus_t = Goldilocks::ONE - t_val;
                let eq_t = one_minus_t * eq_lo + t_val * eq_hi;
                let mut g_t = Goldilocks::ZERO;
                for (ms, &c) in self.multisets.iter().zip(self.coeffs.iter()) {
                    let mut prod = Goldilocks::ONE;
                    for &i in ms {
                        prod *= one_minus_t * f_lo[i] + t_val * f_hi[i];
                    }
                    g_t += c * prod;
                }
                *eval += eq_t * g_t;
            }
        }

        let coeffs = evals_to_coeffs(&evals);
        SumcheckPoly { degree: (self.degree + 1) as u8, coeffs }
    }

    /// Fold eq_table and all f_tables with challenge r, advancing one round.
    pub fn fold(&mut self, r: Goldilocks) {
        fold_inplace(&mut self.eq_table, r);
        for ft in &mut self.f_tables {
            fold_inplace(ft, r);
        }
        self.round += 1;
        self.current_claim =
            Self::compute_sum(&self.eq_table, &self.f_tables, &self.multisets, &self.coeffs);
    }

    /// Run all rounds, applying `challenge_fn` to get each challenge.
    pub fn prove_all<F>(&mut self, mut challenge_fn: F) -> Vec<SumcheckPoly>
    where
        F: FnMut(&SumcheckPoly) -> Goldilocks,
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
    pub fn matrix_evals(&self) -> Vec<Goldilocks> {
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
