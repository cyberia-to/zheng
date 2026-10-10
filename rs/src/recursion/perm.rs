//! Hemera's permutation over nebu's Goldilocks, and the field-native
//! constructions the recursion profile hashes with: a duplex sponge of
//! rate [`RATE`] (capacity 7 lanes, a domain tag in capacity lane 0) and
//! a Merkle node `perm(l ‖ r ‖ NODE_TAG ‖ 0⁷)[0..4]`. Nothing is hashed as
//! bytes: every absorbed value is a field element, so the recursion circuit
//! proves exactly these permutations.

use hemera::field::Goldilocks as HG;
use nebu::Goldilocks;

pub const WIDTH: usize = 16;
/// Rate lanes of the duplex sponge (three Fp3 elements).
pub const RATE: usize = 9;
/// Merkle node tag (lane 8 of a node's input).
pub const NODE_TAG: u64 = 0x6e6f6465;

/// Chain tags (capacity lane 0 of a chain's first block).
pub mod tag {
    /// A step transcript.
    pub const STEP: u64 = 1;
    /// A committed word's leaf.
    pub const LEAF: u64 = 2;
    /// The IVC state digest.
    pub const STATE: u64 = 3;
    /// The out-of-domain sample of a pre-committed trace word.
    pub const PRE: u64 = 4;
    /// The chain of pre-committed roots.
    pub const CHAIN: u64 = 5;
    /// The statement context.
    pub const CTX: u64 = 6;
    /// A cap of a committed word.
    pub const CAP: u64 = 7;
    /// The decider of the last accumulator.
    pub const DECIDE: u64 = 8;
    /// A wrap proof's transcript.
    pub const WRAP: u64 = 9;
    /// The digest of a final verifier's public values.
    pub const PUBLIC: u64 = 10;
}

fn to_h(x: Goldilocks) -> HG {
    HG::new(x.as_u64())
}
fn from_h(x: HG) -> Goldilocks {
    Goldilocks::new(x.as_canonical_u64())
}

/// Hemera's permutation in place.
pub fn permute(s: &mut [Goldilocks; WIDTH]) {
    let mut h: [HG; WIDTH] = core::array::from_fn(|i| to_h(s[i]));
    hemera::permutation::permute(&mut h);
    *s = core::array::from_fn(|i| from_h(h[i]));
}

/// Many permutations at once (hemera's interleaved kernel).
pub fn permute_many(states: &mut [[Goldilocks; WIDTH]]) {
    let mut h: Vec<[HG; WIDTH]> = states
        .iter()
        .map(|s| core::array::from_fn(|i| to_h(s[i])))
        .collect();
    hemera::permutation::permute_batch(&mut h);
    for (s, hs) in states.iter_mut().zip(h) {
        *s = core::array::from_fn(|i| from_h(hs[i]));
    }
}

/// A Merkle node's input.
pub fn node_input(l: [Goldilocks; 4], r: [Goldilocks; 4]) -> [Goldilocks; WIDTH] {
    let mut s = [Goldilocks::ZERO; WIDTH];
    s[..4].copy_from_slice(&l);
    s[4..8].copy_from_slice(&r);
    s[8] = Goldilocks::new(NODE_TAG);
    s
}

/// A 4-ary Merkle node's input: the four children, all sixteen lanes
/// (a truncated-permutation compression; the binary node's tag tells the
/// two apart).
pub fn node4_input(c: [[Goldilocks; 4]; 4]) -> [Goldilocks; WIDTH] {
    let mut s = [Goldilocks::ZERO; WIDTH];
    for (i, d) in c.iter().enumerate() {
        s[4 * i..4 * i + 4].copy_from_slice(d);
    }
    s
}

/// The children of a 4-ary node whose digest `cur` sits at `pos`, the
/// siblings filling the other positions in order.
pub fn children4(cur: [Goldilocks; 4], pos: usize, sibs: [[Goldilocks; 4]; 3]) -> [[Goldilocks; 4]; 4] {
    let mut out = [[Goldilocks::ZERO; 4]; 4];
    let mut it = sibs.iter();
    for (i, o) in out.iter_mut().enumerate() {
        *o = if i == pos { cur } else { *it.next().expect("three siblings") };
    }
    out
}

/// A Merkle node's output state.
pub fn node_state(l: [Goldilocks; 4], r: [Goldilocks; 4]) -> [Goldilocks; WIDTH] {
    let mut s = node_input(l, r);
    permute(&mut s);
    s
}

pub fn head(s: &[Goldilocks; WIDTH]) -> [Goldilocks; 4] {
    [s[0], s[1], s[2], s[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_agrees_with_single() {
        let mut many: Vec<[Goldilocks; WIDTH]> = (0..37u64)
            .map(|k| core::array::from_fn(|i| Goldilocks::new(k * 131 + i as u64)))
            .collect();
        let want: Vec<_> = many
            .iter()
            .map(|s| {
                let mut t = *s;
                permute(&mut t);
                t
            })
            .collect();
        permute_many(&mut many);
        assert_eq!(many, want);
        // and the machine's row function is the same permutation
        let t = crate::machine::hemera::Tables::default();
        let x: [Goldilocks; WIDTH] = core::array::from_fn(|i| Goldilocks::new(i as u64 * 977 + 3));
        let mut y = x;
        permute(&mut y);
        assert_eq!(t.permute(&x), y);
    }
}
