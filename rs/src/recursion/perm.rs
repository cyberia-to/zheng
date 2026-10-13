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
    /// A long message absorbed as a digest (`recursion::msg`).
    pub const MSG: u64 = 11;
}

fn to_h(x: Goldilocks) -> HG {
    HG::new(x.as_u64())
}
fn from_h(x: HG) -> Goldilocks {
    Goldilocks::new(x.as_canonical_u64())
}

/// Permutations computed natively so far (one at a time, batched) — a
/// counter for verifier profiles.
pub static COUNT: [core::sync::atomic::AtomicU64; 2] = [core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)];

/// `(single, batched)` permutations computed so far.
pub fn count() -> (u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (COUNT[0].load(Relaxed), COUNT[1].load(Relaxed))
}

/// Hemera's permutation in place.
pub fn permute(s: &mut [Goldilocks; WIDTH]) {
    COUNT[0].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut h: [HG; WIDTH] = core::array::from_fn(|i| to_h(s[i]));
    hemera::permutation::permute(&mut h);
    *s = core::array::from_fn(|i| from_h(h[i]));
}

/// Batches at least this long go to the process's prover backend (lens
/// `rspcs::backend`); shorter ones — verifier paths, single sponges — run
/// hemera's interleaved kernel here.
pub const BACKEND_MIN: usize = 1 << 12;

/// Many permutations at once (hemera's interleaved kernel, or the prover
/// backend for long batches — the same permutation either way).
pub fn permute_many(states: &mut [[Goldilocks; WIDTH]]) {
    COUNT[1].fetch_add(states.len() as u64, core::sync::atomic::Ordering::Relaxed);
    if states.len() >= BACKEND_MIN {
        let mut raw: Vec<[u64; WIDTH]> = states.iter().map(|s| s.map(|x| x.as_u64())).collect();
        lens::rspcs::backend::current().permute(&mut raw);
        for (s, r) in states.iter_mut().zip(&raw) {
            *s = r.map(Goldilocks::new);
        }
        return;
    }
    let mut h: Vec<[HG; WIDTH]> = states
        .iter()
        .map(|s| core::array::from_fn(|i| to_h(s[i])))
        .collect();
    hemera::permutation::permute_batch(&mut h);
    for (s, hs) in states.iter_mut().zip(h) {
        *s = core::array::from_fn(|i| from_h(hs[i]));
    }
}

/// Permutations a proof's parser computed (expanding multi-openings),
/// kept so the verifier's batched Merkle check reads them instead of
/// recomputing: a cache of a pure function — a hit is the permutation's
/// output whatever proof put it there. Bounded: cleared past
/// [`MEMO_CAP`] entries.
static MEMO: std::sync::Mutex<Option<std::collections::HashMap<[u64; WIDTH], [Goldilocks; WIDTH], MemoHash>>> = std::sync::Mutex::new(None);

/// Entries the cache holds at most (a final proof's parse adds ≈ 3,000).
pub const MEMO_CAP: usize = 1 << 16;

#[derive(Clone, Copy, Default)]
pub struct MemoHash;

impl core::hash::BuildHasher for MemoHash {
    type Hasher = MemoHasher;
    fn build_hasher(&self) -> MemoHasher {
        MemoHasher(0)
    }
}

/// A multiply-xor hasher over the state's limbs (keys are permutation
/// inputs; collisions only cost a comparison).
#[derive(Clone, Copy)]
pub struct MemoHasher(u64);

impl core::hash::Hasher for MemoHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(8) {
            let mut b = [0u8; 8];
            b[..c.len()].copy_from_slice(c);
            self.write_u64(u64::from_le_bytes(b));
        }
    }
    fn write_u64(&mut self, x: u64) {
        self.0 = (self.0.rotate_left(5) ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

fn key(s: &[Goldilocks; WIDTH]) -> [u64; WIDTH] {
    core::array::from_fn(|i| s[i].as_u64())
}

/// [`permute_many`], remembering every input's output.
pub fn permute_many_remember(states: &mut [[Goldilocks; WIDTH]]) {
    let inputs: Vec<[u64; WIDTH]> = states.iter().map(key).collect();
    permute_many(states);
    let mut g = MEMO.lock().expect("memo");
    let m = g.get_or_insert_with(Default::default);
    if m.len() + states.len() > MEMO_CAP {
        m.clear();
    }
    for (k, s) in inputs.into_iter().zip(states.iter()) {
        m.insert(k, *s);
    }
}

/// [`permute_many`], reading remembered outputs where there are any.
pub fn permute_many_recall(states: &mut [[Goldilocks; WIDTH]]) {
    let mut miss = Vec::new();
    {
        let g = MEMO.lock().expect("memo");
        match g.as_ref() {
            Some(m) if !m.is_empty() => {
                for (i, s) in states.iter_mut().enumerate() {
                    match m.get(&key(s)) {
                        Some(o) => *s = *o,
                        None => miss.push(i),
                    }
                }
            }
            _ => miss.extend(0..states.len()),
        }
    }
    if miss.len() == states.len() {
        permute_many(states);
        return;
    }
    let mut batch: Vec<[Goldilocks; WIDTH]> = miss.iter().map(|&i| states[i]).collect();
    permute_many(&mut batch);
    for (&i, s) in miss.iter().zip(batch) {
        states[i] = s;
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
