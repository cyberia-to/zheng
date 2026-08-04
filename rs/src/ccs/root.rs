// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! The BBG root as a chain of hemera compressions — pattern-15 closure.
//!
//! One primitive everywhere: [`compress4`] is the first four elements of the
//! hemera permutation over `[a ‖ b ‖ 0⁸]` — the same permutation as the nox
//! hash jet and the Fiat-Shamir transcript. The BBG root is a left fold of
//! `compress4` over the 14 leaves (11 dimension commitments ‖ A ‖ N ‖ stats)
//! from a domain-tagged IV.
//!
//! This module is the single source of truth for the root layout: bbg calls
//! [`root_from_leaves`] natively in `compute_root`, and [`build_root_steps`]
//! replays the identical chain as hemera CCS pairs so the look argument can
//! bind an opened dimension commitment to the root recorded in the trace.

use nebu::Goldilocks;

use hemera::field::Goldilocks as HGold;
use hemera::permutation::{permute, permute_traced};

use super::transcript::{squeeze_ccs_pairs, SqueezeVisitor};
use crate::types::{CCSInstance, CCSWitness};

/// The 14 leaves of the BBG root preimage, each a 4-limb digest.
///
/// Order is frozen: the 11 public dimensions (particles, axons_out, axons_in,
/// neurons, locations, coins, cards, files, time, signals, balances — matching
/// bbg's `Dim` numbering and the look `namespace` register), then A (private
/// commitments), N (nullifiers), stats (committed graph statistics).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootLeaves {
    pub dims: [[Goldilocks; 4]; 11],
    pub a: [Goldilocks; 4],
    pub n: [Goldilocks; 4],
    pub stats: [Goldilocks; 4],
}

impl RootLeaves {
    /// The leaves in committed order.
    pub fn ordered(&self) -> [[Goldilocks; 4]; 14] {
        let mut out = [[Goldilocks::ZERO; 4]; 14];
        out[..11].copy_from_slice(&self.dims);
        out[11] = self.a;
        out[12] = self.n;
        out[13] = self.stats;
        out
    }

    /// A single-dimension state: `dims[ns]` set, every other leaf zero.
    ///
    /// The shape a standalone provider (one polynomial, no full bbg state)
    /// commits to — its root is `root_from_leaves(&solo(...))`.
    pub fn solo(ns: usize, dim: [Goldilocks; 4]) -> Self {
        let mut leaves = Self {
            dims: [[Goldilocks::ZERO; 4]; 11],
            a: [Goldilocks::ZERO; 4],
            n: [Goldilocks::ZERO; 4],
            stats: [Goldilocks::ZERO; 4],
        };
        leaves.dims[ns] = dim;
        leaves
    }
}

/// Domain tag for the root chain IV: `"bbg-root"` as a little-endian u64.
pub const ROOT_TAG: u64 = u64::from_le_bytes(*b"bbg-root");

/// The chain IV: `[ROOT_TAG, 0, 0, 0]`.
pub fn root_iv() -> [Goldilocks; 4] {
    [Goldilocks::new(ROOT_TAG), Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO]
}

fn to_hstate(a: &[Goldilocks; 4], b: &[Goldilocks; 4]) -> [HGold; 16] {
    let mut state = [HGold::ZERO; 16];
    for i in 0..4 {
        state[i] = HGold::new(a[i].canonicalize().as_u64());
        state[4 + i] = HGold::new(b[i].canonicalize().as_u64());
    }
    state
}

fn first4(state: &[HGold; 16]) -> [Goldilocks; 4] {
    core::array::from_fn(|i| Goldilocks::new(state[i].as_canonical_u64()))
}

/// One hemera compression: the first 4 elements of `P([a ‖ b ‖ 0⁸])`.
pub fn compress4(a: &[Goldilocks; 4], b: &[Goldilocks; 4]) -> [Goldilocks; 4] {
    let mut state = to_hstate(a, b);
    permute(&mut state);
    first4(&state)
}

/// The BBG root: left fold of [`compress4`] over the ordered leaves from the IV.
pub fn root_from_leaves(leaves: &RootLeaves) -> [Goldilocks; 4] {
    leaves.ordered().iter().fold(root_iv(), |acc, leaf| compress4(&acc, leaf))
}

/// Replay the root chain and emit hemera CCS pairs for every compression.
///
/// 14 compressions × 24 round pairs = 336 (CCSInstance, CCSWitness) pairs,
/// structurally identical to the transcript/hash pairs so they fold into the
/// same accumulator shapes. Returns the pairs and the recomputed root limbs;
/// the caller binds those limbs to the trace registers with eq steps.
pub fn build_root_steps(leaves: &RootLeaves) -> (Vec<(CCSInstance, CCSWitness)>, [Goldilocks; 4]) {
    let mut steps = Vec::new();
    let mut acc = root_iv();
    for leaf in leaves.ordered() {
        let mut state = to_hstate(&acc, &leaf);
        let mut visitor = SqueezeVisitor::new();
        permute_traced(&mut state, &mut visitor);
        steps.extend(squeeze_ccs_pairs(&visitor));
        acc = first4(&state);
    }
    (steps, acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::selector::is_satisfied;

    fn g(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    fn sample_leaves() -> RootLeaves {
        RootLeaves {
            dims: core::array::from_fn(|d| core::array::from_fn(|k| g((d * 4 + k + 1) as u64))),
            a: [g(101), g(102), g(103), g(104)],
            n: [g(201), g(202), g(203), g(204)],
            stats: [g(301), g(302), g(303), g(304)],
        }
    }

    #[test]
    fn root_is_deterministic() {
        assert_eq!(root_from_leaves(&sample_leaves()), root_from_leaves(&sample_leaves()));
    }

    #[test]
    fn root_binds_every_leaf() {
        let base = root_from_leaves(&sample_leaves());
        // Flipping any single leaf limb changes the root.
        let mut l = sample_leaves();
        l.dims[0][0] = g(999);
        assert_ne!(root_from_leaves(&l), base);
        let mut l = sample_leaves();
        l.dims[10][3] = g(999);
        assert_ne!(root_from_leaves(&l), base);
        let mut l = sample_leaves();
        l.a[0] = g(999);
        assert_ne!(root_from_leaves(&l), base);
        let mut l = sample_leaves();
        l.stats[3] = g(999);
        assert_ne!(root_from_leaves(&l), base);
    }

    #[test]
    fn compress_is_order_sensitive() {
        let a = [g(1), g(2), g(3), g(4)];
        let b = [g(5), g(6), g(7), g(8)];
        assert_ne!(compress4(&a, &b), compress4(&b, &a));
    }

    #[test]
    fn root_steps_match_native_and_satisfy() {
        let leaves = sample_leaves();
        let (steps, computed) = build_root_steps(&leaves);
        assert_eq!(computed, root_from_leaves(&leaves), "replay matches native fold");
        assert_eq!(steps.len(), 14 * 24, "24 round pairs per compression");
        for (i, (instance, witness)) in steps.iter().enumerate() {
            assert!(is_satisfied(instance, witness), "root step {i} unsatisfied");
        }
    }
}
