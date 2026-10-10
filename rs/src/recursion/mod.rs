//! Recursion: incrementally verifiable computation over the nox machine
//! (`specs/recursion.md`).
//!
//! The step relation of step `i` proves its nox segment *and* that the
//! verifier of step `i − 1` (its AIR reduction and its accumulation step)
//! accepted: the verifier runs inside the step's trace as the recursion
//! circuit. A proof of any number of steps is the last step's proof, its
//! accumulation step and one decider — constant in the number of steps.
//!
//! Everything the circuit re-checks is hashed field-natively: the
//! transcript is a duplex sponge over hemera's permutation ([`sponge`]),
//! the committed words are hemera Merkle trees over field elements
//! ([`word`]).

pub mod ops;
pub mod perm;
pub mod sponge;
pub mod word;
pub mod circuit;
pub mod gm;
pub mod acc;
pub mod params;
pub mod program;
pub mod relation;
pub mod state;
pub mod step;
pub mod prove;
pub mod ivc;
pub mod wire;
#[cfg(test)]
mod review;
