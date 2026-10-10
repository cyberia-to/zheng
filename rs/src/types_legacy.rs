//! Types of the retired folded trace API (`legacy` feature) — unsound;
//! see `crate::legacy`.

use nebu::Goldilocks;

use super::{CCSInstance, CCSWitness, Commitment, Proof};

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
    /// A blank accumulator for `instance`: zero witness, zero error, no
    /// steps. The only way to start a fold outside [`crate::commit`] — every
    /// step folded into it still passes [`crate::fold`]'s satisfiability
    /// gate, and [`crate::verify`] checks the decided group against the
    /// instance it derives from the group's position, never against
    /// `instance` — so a caller gains nothing by naming a trivial one.
    pub fn blank(instance: &CCSInstance) -> Self {
        let z = vec![Goldilocks::ZERO; 64];
        Self {
            committed_instance: instance.clone(),
            folded_witness: CCSWitness { z: z.clone() },
            witness_commitment: lens::brakedown::Brakedown::commit_raw(&z),
            error_evals: vec![Goldilocks::ZERO; instance.num_rows],
            step_count: 0,
        }
    }

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
    /// The authenticated TensorMerkle opening requires recursive constraints
    /// that are not implemented yet. Never omit the opening checks.
    UnsupportedRecursiveOpening,
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
