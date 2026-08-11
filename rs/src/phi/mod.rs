// ---
// tags: zheng, rust, phi, spmv, tri-kernel
// crystal-type: source
// crystal-domain: comp
// ---
//! φ* SpMV circuit — prove tri-kernel convergence inside zheng.
//!
//! Implements the core of [[provable consensus]]: sparse matrix-vector
//! multiply as multi-row CCS, then diffusion / springs / heat / combine as
//! compositions of SpMV, folded over iterations into a HyperNova accumulator.
//!
//! Domain-sized graphs (ε-support, not planetary N) are the intended prove
//! target — same localization foculus uses for finality. Planetary 1.4B
//! constraint proofs are this module at scale, not a different design.
//!
//! Sections (provable-consensus.md):
//! - SpMV: public A, witness x,y  →  A·x − y = 0  (linear multi-row CCS)
//! - D / S / H: SpMV with public transition / symmetric weights
//! - combine + L1 normalize
//! - K iterations folded; decide → one proof

mod spmv;
mod trikernel;

pub use spmv::{
    SparseGraph, SpmvError, SpmvProof, SpmvStatement, prove_spmv, spmv_native, verify_spmv,
};
pub use trikernel::{
    PhiError, PhiProof, PhiStatement, TriKernelParams, prove_phi_star, verify_phi_star,
};
