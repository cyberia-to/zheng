// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! HyperNova CCS folding: incremental accumulation + decider.

pub mod decide;
pub mod fold;

pub use decide::decide;
pub use fold::fold_step;
