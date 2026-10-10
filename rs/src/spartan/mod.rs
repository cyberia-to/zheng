// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! SuperSpartan: the IOP generic over the challenge field (`iop`), its
//! verifier half over compressed round polynomials (`reduce`, used by the
//! succinct profile) and its lens-PCS wrappers (`prover`, `verifier`).

pub mod iop;
pub mod reduce;
pub mod prover;
pub mod verifier;

pub use prover::SpartanProver;
pub use verifier::SpartanVerifier;
