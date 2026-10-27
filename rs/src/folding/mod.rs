// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Legacy CCS fold (unsound; feature `legacy`, removed in phase 5):
//! incremental relaxed folding + decider. The verifier never checks the
//! fold (a hemera commitment is not homomorphic) — see specs/decider.md
//! §soundness. Accumulation (phase 3) replaces it.

pub mod decide;
pub mod fold;

pub use decide::decide;
pub use fold::fold_step;
