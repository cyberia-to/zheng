// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! SuperSpartan: the IOP generic over the challenge field (`iop`) and its
//! lens-PCS wrappers (`prover`, `verifier`).

pub mod iop;
pub mod prover;
pub mod verifier;

pub use prover::SpartanProver;
pub use verifier::SpartanVerifier;
