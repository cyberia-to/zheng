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
mod statement;
#[cfg(feature = "serde")]
mod statement_wire;
/// Experimental opt-in tagged kernel; no production protocol dispatch.
pub mod tagged;
/// Native private CCS proofs over the soft3 field and hash.
pub mod zk;

pub use certificate::Certificate;
pub use proof::DirectProof;
pub use relation::ExecutionNoun;
pub use statement::{
    ExecutionStatement, NounToken, certify_execution, prove_execution, verify_certificate,
    verify_execution,
};

#[cfg(test)]
mod call_tests;

#[cfg(test)]
mod direct_tests;

#[cfg(test)]
mod state_tests;

#[cfg(test)]
mod private_state_tests;

#[cfg(test)]
mod budget_tests;
