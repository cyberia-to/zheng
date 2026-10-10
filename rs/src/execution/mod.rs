//! Checked nox execution and experimental dynamic certificate components.
//! Public and private protocols have separate disclosure contracts; see
//! specs/execution.md and specs/native-private-ccs.md.
pub mod certificate;
/// Experimental public semantic-certificate components; no execution dispatch.
pub mod disclosed;
pub mod private;
pub mod private_state;
pub mod proof;
pub mod public;
pub mod relation;
pub mod state;
/// What authenticates state reads, verified against the statement's root.
pub mod state_evidence;
mod statement;
/// The succinct profile: committed witness, Spartan over Fp3, one opening.
pub mod succinct;
#[cfg(feature = "serde")]
mod statement_wire;
/// Experimental opt-in tagged kernel; no production protocol dispatch.
pub mod tagged;
/// Verifying keys: compiled relations cached by program key.
pub mod vk;
/// The zk profile: succinct proofs that hide the witness (secret inputs).
pub mod veil;
/// Native private CCS proofs over the soft3 field and hash.
pub mod zk;

pub use certificate::Certificate;
pub use proof::DirectProof;
pub use relation::ExecutionNoun;
pub use statement::{
    ExecutionStatement, MAX_DEPTH, MAX_INPUTS, MAX_OUTPUTS, MAX_PROGRAM_NODES, NounToken, certify_execution, prove_execution, verify_certificate,
    verify_certificate_with, verify_execution,
};
pub use vk::VerifyingKey;

#[cfg(test)]
mod call_tests;

#[cfg(test)]
mod direct_tests;

#[cfg(test)]
mod state_tests;

#[cfg(test)]
mod state_v3_tests;

#[cfg(test)]
mod private_state_tests;

#[cfg(test)]
mod budget_tests;
