// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Core types for the zheng proof system.

use nebu::Goldilocks;

pub use lens::{Commitment, Opening};

// ── sumcheck ─────────────────────────────────────────────────────

/// one round polynomial g_i in a sumcheck transcript.
///
/// coefficients ascending: g_i(X) = c_0 + c_1·X + … + c_d·X^d.
#[derive(Clone, Debug)]
pub struct SumcheckPoly {
    pub degree: u8,
    pub coeffs: Vec<Goldilocks>,
}

impl SumcheckPoly {
    /// evaluate via Horner's method.
    pub fn eval(&self, x: Goldilocks) -> Goldilocks {
        let mut r = Goldilocks::ZERO;
        for &c in self.coeffs.iter().rev() {
            r = r * x + c;
        }
        r
    }

    /// g_i(0) — first consistency check term.
    pub fn eval_0(&self) -> Goldilocks {
        self.coeffs.first().copied().unwrap_or(Goldilocks::ZERO)
    }

    /// g_i(1) — second consistency check term.
    pub fn eval_1(&self) -> Goldilocks {
        self.coeffs.iter().copied().fold(Goldilocks::ZERO, |acc, c| acc + c)
    }
}

// ── proof ────────────────────────────────────────────────────────

/// a complete zheng proof: sumcheck transcript + lens opening.
///
/// ~2 KiB at 128-bit security for N = 2^20.
#[derive(Clone, Debug)]
pub struct Proof {
    /// hemera binding of the trace multilinear polynomial.
    pub commitment: Commitment,
    /// claimed û_i = M_i · z for each matrix M_i in the CCS instance.
    pub matrix_evals: Vec<Goldilocks>,
    /// one univariate polynomial per sumcheck round.
    pub sumcheck_polys: Vec<SumcheckPoly>,
    /// evaluation of the committed polynomial at the sumcheck output point.
    pub eval_value: Goldilocks,
    /// Brakedown opening proof at the sumcheck output point.
    pub pcs_opening: Opening,
}

/// public statement: what the proof attests to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// hemera hash of the nox program (formula NounId sequence).
    pub program_hash: [u8; 32],
    /// hemera hash of public inputs.
    pub input_hash: [u8; 32],
    /// hemera hash of public outputs.
    pub output_hash: [u8; 32],
    /// maximum focus consumed by the execution.
    pub focus_bound: u64,
}

// ── parameters ───────────────────────────────────────────────────

/// prover and verifier configuration.
#[derive(Clone, Debug)]
pub struct ProofParams {
    pub security: SecurityLevel,
    pub lens: LensBackend,
    /// log_2 of maximum trace rows (default: 20 → 2^20 rows).
    pub max_trace_log: u32,
}

impl Default for ProofParams {
    fn default() -> Self {
        Self {
            security: SecurityLevel::Sec128,
            lens: LensBackend::Brakedown,
            max_trace_log: 20,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    Sec100,
    Sec128,
}

impl SecurityLevel {
    /// number of proximity query repetitions (λ).
    pub fn lambda(self) -> usize {
        match self {
            SecurityLevel::Sec100 => 100,
            SecurityLevel::Sec128 => 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LensBackend {
    /// expander-graph codes over Goldilocks. default.
    Brakedown,
    /// binary Reed-Solomon over F₂. for binary nox languages.
    Binius,
}

// ── CCS ──────────────────────────────────────────────────────────

/// a sparse matrix over Goldilocks in compressed sparse row format.
#[derive(Clone, Debug, Default)]
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
                out[i] = out[i] + c * z[j];
            }
        }
        out
    }
}

/// a CCS instance.
///
/// satisfiability: Σ_j c_j · ∏_{i ∈ S_j} (M_i · z) = 0.
#[derive(Clone, Debug)]
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
                    *p = *p * *m;
                }
            }
            for (s, p) in sum.iter_mut().zip(product.iter()) {
                *s = *s + coeff * *p;
            }
        }
        sum.iter().all(|&v| v == Goldilocks::ZERO)
    }
}

/// a CCS witness: z = public_input || private_witness || constant_1.
#[derive(Clone, Debug)]
pub struct CCSWitness {
    pub z: Vec<Goldilocks>,
}

// ── accumulator ──────────────────────────────────────────────────

/// HyperNova running accumulator.
///
/// constant size (~200 bytes serialized) regardless of fold count.
#[derive(Clone, Debug)]
pub struct Accumulator {
    pub committed_instance: CCSInstance,
    /// prover's folded witness (ignored by verifier).
    pub folded_witness: CCSWitness,
    pub witness_commitment: Commitment,
    pub error_term: Goldilocks,
    pub step_count: u64,
}

// ── errors ───────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CommitError {
    ExecutionFailed(nox::ErrorKind),
    FocusExhausted,
    TraceOverflow,
}

#[derive(Debug)]
pub enum OpenError {
    InvalidPoint,
    LensFailed,
}

#[derive(Debug)]
pub enum VerifyError {
    SumcheckFailed { round: usize },
    EvaluationMismatch,
    LensFailed,
}

#[derive(Debug)]
pub enum FoldError {
    InstanceMismatch,
    WitnessMismatch,
}

#[derive(Debug)]
pub enum DecideError {
    EmptyAccumulator,
    SumcheckFailed { round: usize },
    LensFailed,
}
