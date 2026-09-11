//! Checked public execution over a verifier-derived, unfolded CCS.
//! This development protocol is not zero knowledge; see specs/execution.md.
pub mod proof;
pub mod public;
pub mod relation;
mod statement;
#[cfg(feature = "serde")]
mod statement_wire;

pub use proof::DirectProof;
pub use relation::ExecutionNoun;
pub use statement::{ExecutionStatement, NounToken, prove_execution, verify_execution};
