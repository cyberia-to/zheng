// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! zheng — proof system for nox executions over Goldilocks and hemera.
//!
//! Production surface (default build):
//!
//! - [`execution`] — the statements and their profiles:
//!   - [`execution::certificate`] — public profile v3 (statement + free
//!     witness positions, checked exactly; envelope profile 0);
//!   - [`execution::state`], [`execution::state_evidence`] — state profile v3,
//!     every read authenticated against the statement's own root (profile 3);
//!   - [`execution::succinct`] — succinct profile: witness committed, Spartan
//!     over Fp3 and one lens PCS opening (WHIR, TensorRs; profile 1);
//!   - [`execution::veil`] — zk profile: Libra-masked sumchecks and one hiding
//!     Reed–Solomon tensor commitment (profile 2, scheme 2);
//!   - [`execution::vk`] — verifying keys, derived by the verifier from the
//!     program and absorbed by the succinct and zk transcripts;
//!   - [`execution::zk`] — the native private MPC-in-the-head protocol
//!     (`ZHMITH01`, profile 2, scheme 1);
//! - [`envelope`] — the one wire format `ZHENGPF1` with a profile byte;
//! - [`sumcheck`], [`spartan`], [`transcript`], [`field`] — the IOP machinery,
//!   generic over the challenge field (Goldilocks or its cubic extension).
//!
//! The 0.3.x folded trace API (`commit`, `open`, `verify_eval`, `verify`,
//! `fold`, `decide`, the universal CCS in `ccs`, `folding`, `phi`) is unsound
//! and compiles only with the `legacy` feature; see [`legacy`] and
//! `specs/soundness.md`.

pub mod accumulate;
pub mod air;
pub mod envelope;
pub mod execution;
pub mod field;
pub mod multilinear;
pub mod spartan;
pub mod sumcheck;
pub mod transcript;
pub mod types;
pub mod wire;

#[cfg(feature = "legacy")]
pub mod ccs;
#[cfg(feature = "legacy")]
pub mod folding;
#[cfg(feature = "legacy")]
pub mod legacy;
#[cfg(feature = "legacy")]
pub mod phi;

pub use field::ChallengeField;
pub use transcript::Transcript;
pub use types::{CCSInstance, CCSWitness, Proof, SparseMatrix, SumcheckPoly, VerifyError};

#[cfg(feature = "legacy")]
pub use crate::ccs::{
    AxisOpening, HashAux, LookOpening, RootLeaves, build_axis_transcript_steps,
    build_look_transcript_steps, look_openings_from_provider, root_from_leaves, root_to_bytes,
    standalone_root,
};
#[cfg(feature = "legacy")]
pub(crate) use legacy::linkage_digest;
#[cfg(feature = "legacy")]
pub use legacy::{commit, decide, fold, open, row_hash, verify, verify_eval};
#[cfg(feature = "legacy")]
pub use phi::{
    PhiError, PhiProof, PhiStatement, SparseGraph, SpmvError, SpmvProof, SpmvStatement,
    TriKernelParams, prove_phi_star, prove_spmv, spmv_native, verify_phi_star, verify_spmv,
};
#[cfg(feature = "legacy")]
pub use types::{
    Accumulator, CommitError, DecideError, FoldError, LensBackend, OpenError, ProofParams,
    SecurityLevel, Statement, TraceProof,
};
