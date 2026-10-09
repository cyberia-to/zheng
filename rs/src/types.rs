// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Core types for the zheng proof system.

use nebu::Goldilocks;

use crate::field::ChallengeField;

pub use lens::{Commitment, Opening};

// ── sumcheck ─────────────────────────────────────────────────────

/// one round polynomial g_i in a sumcheck transcript.
///
/// coefficients ascending: g_i(X) = c_0 + c_1·X + … + c_d·X^d.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SumcheckPoly<F: ChallengeField = Goldilocks> {
    pub degree: u8,
    pub coeffs: Vec<F>,
}

impl<F: ChallengeField> SumcheckPoly<F> {
    /// evaluate via Horner's method.
    pub fn eval(&self, x: F) -> F {
        let mut r = F::ZERO;
        for &c in self.coeffs.iter().rev() {
            r = r * x + c;
        }
        r
    }

    /// g_i(0) — first consistency check term.
    pub fn eval_0(&self) -> F {
        self.coeffs.first().copied().unwrap_or(F::ZERO)
    }

    /// g_i(1) — second consistency check term.
    pub fn eval_1(&self) -> F {
        self.coeffs.iter().copied().fold(F::ZERO, |acc, c| acc + c)
    }
}

// ── proof ────────────────────────────────────────────────────────

/// a Spartan proof: sumcheck transcript + lens opening. Its size and
/// soundness depend on the PCS; see `specs/soundness.md`.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Proof {
    /// hemera binding of the trace multilinear polynomial.
    pub commitment: Commitment,
    /// claimed û_i(ρ_x) = MLE of (M_i · z) evaluated at outer row challenge ρ_x.
    pub matrix_evals: Vec<Goldilocks>,
    /// outer sumcheck round polynomials (log m rounds). empty for single-row CCS (m=1).
    pub outer_sumcheck_polys: Vec<SumcheckPoly>,
    /// inner sumcheck round polynomials (log n rounds over the witness dimension).
    pub sumcheck_polys: Vec<SumcheckPoly>,
    /// evaluation of the committed polynomial at the sumcheck output point.
    pub eval_value: Goldilocks,
    /// Brakedown opening proof at the sumcheck output point. On the wire
    /// it carries only what the verifier reads (`crate::wire::opening`).
    #[cfg_attr(feature = "serde", serde(with = "crate::wire::opening"))]
    pub pcs_opening: Opening,
}

// ── CCS ──────────────────────────────────────────────────────────

/// a sparse matrix over Goldilocks in compressed sparse row format.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SparseMatrix {
    pub rows: usize,
    pub cols: usize,
    /// entries[i] = nonzero (col, coeff) pairs in row i.
    pub entries: Vec<Vec<(usize, Goldilocks)>>,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self { rows, cols, entries: vec![vec![]; rows] }
    }

    pub fn set(&mut self, row: usize, col: usize, val: Goldilocks) {
        self.entries[row].push((col, val));
    }

    /// compute M · z as a dense vector.
    pub fn mul_vec(&self, z: &[Goldilocks]) -> Vec<Goldilocks> {
        let mut out = vec![Goldilocks::ZERO; self.rows];
        for (i, row) in self.entries.iter().enumerate() {
            for &(j, c) in row {
                out[i] += c * z.get(j).copied().unwrap_or(Goldilocks::ZERO);
            }
        }
        out
    }
}

/// a CCS instance.
///
/// satisfiability: Σ_j c_j · ∏_{i ∈ S_j} (M_i · z) = 0.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CCSInstance {
    /// M_1, …, M_t — constraint matrices.
    pub matrices: Vec<SparseMatrix>,
    /// S_1, …, S_q — index sets into matrices (Hadamard product groups).
    pub multisets: Vec<Vec<usize>>,
    /// c_1, …, c_q — linear combination coefficients.
    pub coeffs: Vec<Goldilocks>,
    /// m — number of rows in each matrix.
    pub num_rows: usize,
    /// n — length of the witness vector z.
    pub num_cols: usize,
}

impl CCSInstance {
    /// check whether a witness satisfies this instance.
    pub fn is_satisfied_by(&self, witness: &CCSWitness) -> bool {
        let z = &witness.z;
        let mut sum = vec![Goldilocks::ZERO; self.num_rows];
        for (multiset, &coeff) in self.multisets.iter().zip(self.coeffs.iter()) {
            let mut product = vec![Goldilocks::ONE; self.num_rows];
            for &idx in multiset {
                let mv = self.matrices[idx].mul_vec(z);
                for (p, m) in product.iter_mut().zip(mv.iter()) {
                    *p *= *m;
                }
            }
            for (s, p) in sum.iter_mut().zip(product.iter()) {
                *s += coeff * *p;
            }
        }
        sum.iter().all(|&v| v == Goldilocks::ZERO)
    }
}

/// a CCS witness: z = public_input || private_witness || constant_1.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CCSWitness {
    pub z: Vec<Goldilocks>,
}

// ── errors ───────────────────────────────────────────────────────

#[derive(Debug)]
pub enum VerifyError {
    SumcheckFailed { round: usize },
    EvaluationMismatch,
    LensFailed,
    /// A degree-1 group carries a non-zero error term. Linear CCS instances
    /// fold satisfied steps to exactly zero error, so a non-zero entry means
    /// an unsatisfied step (e.g. a forged axis binding) was folded in.
    LinearErrorNonzero,
    /// A group's error vector does not have its instance's row count.
    GroupLayout,
}

#[cfg(feature = "legacy")]
#[path = "types_legacy.rs"]
mod legacy;
#[cfg(feature = "legacy")]
pub use legacy::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_vec_oob_column_returns_zero() {
        let mut m = SparseMatrix::new(1, 10);
        m.set(0, 5, Goldilocks::ONE); // column 5 is in-range for a 10-col matrix
        m.set(0, 9, Goldilocks::new(2)); // column 9 — in range
        // z only has 4 elements; columns 5 and 9 are out of range → should not panic
        let z = vec![Goldilocks::ONE; 4];
        let result = m.mul_vec(&z);
        // both column accesses OOB → zero contribution
        assert_eq!(result[0], Goldilocks::ZERO);
    }
}
