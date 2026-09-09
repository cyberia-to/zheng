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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

/// One accumulator group: the decided proof and the accumulator it decides.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofGroup {
    pub proof: Proof,
    pub accumulator: Accumulator,
}

/// Proof for a complete nox trace: two accumulator groups at most.
///
/// `universal` folds every Layer-1 row (trace pairs, transcript and root
/// Poseidon2 rounds) under the universal step instance
/// (`ccs::universal_ccs`). `binding` folds the degree-1 opening bindings
/// (axis, hash, look eq steps) under `ccs::eq_instance`; absent when the
/// trace has none. The verifier derives both instances from these
/// positions — the wire never carries a CCS instance. Size is ~4 KiB and
/// independent of the trace length.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceProof {
    pub universal: ProofGroup,
    pub binding: Option<ProofGroup>,
}

impl TraceProof {
    /// The groups in canonical order: universal, then binding if present.
    pub fn groups(&self) -> impl Iterator<Item = &ProofGroup> {
        core::iter::once(&self.universal).chain(self.binding.iter())
    }

    /// Number of accumulator groups (1 or 2).
    pub fn group_count(&self) -> usize {
        1 + usize::from(self.binding.is_some())
    }
}

/// public statement: what the proof attests to.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Statement {
    /// hemera hash of the nox program (formula NounId sequence).
    pub program_hash: [u8; 32],
    /// hemera hash of public inputs.
    pub input_hash: [u8; 32],
    /// hemera hash of public outputs.
    pub output_hash: [u8; 32],
    /// maximum focus consumed by the execution.
    pub focus_bound: u64,
    /// BBG state root read by look (pattern 17) rows: four little-endian
    /// Goldilocks limbs, limb i at bytes [8i, 8i+8) — the packing of
    /// `bbg::BbgState::root()` and [`crate::root_to_bytes`]. `[0u8; 32]`
    /// is the "no state read" sentinel for programs without look rows.
    pub bbg_root: [u8; 32],
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

// ── accumulator ──────────────────────────────────────────────────

/// HyperNova running accumulator.
///
/// error_evals[r] = Σ_j c_j · ∏_{i ∈ S_j} (M_i[row r] · z_folded) for each row r.
/// For satisfying witnesses all entries are 0. Grows by num_rows scalars per fold group
/// but is otherwise O(1) in the number of folds.
///
/// Fields are `pub(crate)`, not `pub`: an `Accumulator` is only ever produced
/// by [`crate::fold`]/[`crate::folding::fold::fold_step`], which now checks
/// every incoming witness against the instance before folding it in
/// (`FoldError::UnsatisfyingWitness`). A bare struct literal from outside
/// this crate would skip that gate entirely — the exact attack this type
/// closes (see `fold.rs`'s `attack_*` tests). Downstream crates (joy, bbg)
/// only ever move `Accumulator` values around opaquely (store, clone, pass
/// to `decide`/`verify`); none construct or read individual fields.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Accumulator {
    /// The instance every fold into this accumulator must match. Prover
    /// state only: never serialized — the verifier derives the instance from
    /// the group's position in the [`TraceProof`] (a proof that named its
    /// own instance could name a trivial one). Deserializes empty.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) committed_instance: CCSInstance,
    /// prover's folded witness (ignored by verifier). Never serialized: a
    /// proof artifact carrying it would ship the prover's private state —
    /// for programs with divine() secrets, the secrets' folded image — and
    /// triple the wire size for nothing the verifier reads. Deserializes
    /// empty; only the prover-side fold ever needs it populated.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) folded_witness: CCSWitness,
    pub(crate) witness_commitment: Commitment,
    /// per-row constraint evaluation; length = committed_instance.num_rows.
    pub(crate) error_evals: Vec<Goldilocks>,
    pub(crate) step_count: u64,
}

impl Accumulator {
    /// The Brakedown commitment to the folded witness — public accumulator
    /// data a caller may need to display or log (e.g. bbg checkpoints).
    pub fn witness_commitment(&self) -> &Commitment {
        &self.witness_commitment
    }

    /// Number of steps folded into this accumulator so far.
    pub fn step_count(&self) -> u64 {
        self.step_count
    }
}

// ── errors ───────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CommitError {
    ExecutionFailed(nox::ErrorKind),
    FocusExhausted,
    TraceOverflow,
    /// Statement input_hash, output_hash, or focus_bound does not match the trace.
    StatementMismatch,
    /// A look opening does not bind to the trace: namespace out of range, or a
    /// value / point / commitment / root constraint is unsatisfied.
    LookBinding,
    /// A hash block does not bind to the trace: the block is not 25 rows,
    /// or a replayed sponge state / round index / digest / budget constraint
    /// diverges from the recorded rows.
    HashBinding,
    /// An axis opening does not bind to the trace: a commitment (r11-r14),
    /// point (r5) or value (r7) constraint is unsatisfied, or the point length
    /// does not match the axis address, or a verifier step is unsatisfied.
    AxisBinding,
    /// Trace pair `t` (rows t, t+1) does not satisfy the universal step
    /// instance: an unknown pattern tag, an out-of-range hash round index,
    /// or registers that violate the pattern's constraint. The relaxed fold
    /// would carry the violation invisibly; commit refuses instead.
    StepUnsatisfied(usize),
    DecideFailed(DecideError),
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
    /// A degree-1 group carries a non-zero error term. Linear CCS instances
    /// fold satisfied steps to exactly zero error, so a non-zero entry means
    /// an unsatisfied step (e.g. a forged axis binding) was folded in.
    LinearErrorNonzero,
    /// A group's error vector does not have its instance's row count.
    GroupLayout,
}

#[derive(Debug)]
pub enum FoldError {
    InstanceMismatch,
    WitnessMismatch,
    /// The incoming witness (before folding) does not satisfy `instance`:
    /// `error_evals(instance, witness) != 0` at at least one row. `commit()`
    /// already filters every real trace pair through this check
    /// (`CommitError::StepUnsatisfied`) before calling `fold_step` — this is
    /// the same gate enforced by the shared primitive itself, so a caller
    /// that reaches `fold_step`/`fold` directly (bypassing `commit()`, e.g.
    /// the public `zheng::fold` entry point) cannot fold in a fabricated,
    /// non-satisfying row either. It does not by itself prove the witness
    /// reflects any REAL nox execution — only that it is internally
    /// consistent with the instance (see `specs/decider.md` §soundness).
    UnsatisfyingWitness,
}

#[derive(Debug)]
pub enum DecideError {
    EmptyAccumulator,
    SumcheckFailed { round: usize },
    LensFailed,
}

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
