//! Checked public execution over a verifier-derived, unfolded CCS.
//! This development protocol is not zero knowledge; see specs/execution.md.
pub mod private;
pub mod private_state;
pub mod proof;
pub mod public;
pub mod relation;
pub mod state;
/// Experimental opt-in tagged kernel; no production protocol dispatch.
pub mod tagged;
mod statement;
#[cfg(feature = "serde")]
mod statement_wire;

pub use proof::DirectProof;
pub use relation::ExecutionNoun;
pub use statement::{ExecutionStatement, NounToken, prove_execution, verify_execution};

#[cfg(test)]
mod call_tests;

#[cfg(test)]
mod state_tests;

#[cfg(test)]
mod private_state_tests;

#[cfg(test)]
mod budget_tests;
