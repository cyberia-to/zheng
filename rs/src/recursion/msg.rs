//! Long proof messages absorbed as a digest: the message is split into
//! [`LANES`] contiguous parts, each hashed by its own duplex sponge (tag
//! `MSG`), and a last sponge (tag `MSG`) hashes the parts' digests. The
//! transcript absorbs that digest instead of the message, so the
//! verifier's serial chain of permutations shortens from `⌈len/3⌉` to the
//! last sponge's few blocks; the parts run side by side (one batched
//! permutation per step natively). Binding is the hash row's collision
//! resistance, as for a Merkle root.

use nebu::{Fp3, Goldilocks};

use super::ops::Ops;
use super::perm::{self, RATE, WIDTH, tag};
use super::sponge::Sponge;

/// Parts of a message.
pub const LANES: usize = 8;

fn parts(len: usize) -> usize {
    len.div_ceil(LANES).max(1)
}

/// The message's values (written: the prover supplies them) and its
/// digest, over any interpreter.
pub fn absorb_generic<O: Ops>(o: &mut O, items: &[Fp3]) -> (Vec<O::V>, [O::V; 4]) {
    let mut vals = Vec::with_capacity(items.len());
    let mut heads = Vec::new();
    for part in items.chunks(parts(items.len())) {
        let mut sp = Sponge::new(o, tag::MSG);
        for &x in part {
            vals.push(sp.absorb_free_ext(o, x));
        }
        if sp.has_pending() {
            sp.flush(o);
        }
        for i in 0..4 {
            heads.push(o.out_base(&sp.chain, i));
        }
    }
    let mut sp = Sponge::new(o, tag::MSG);
    for &h in &heads {
        sp.absorb(o, h);
    }
    if sp.has_pending() {
        sp.flush(o);
    }
    let d = core::array::from_fn(|i| o.out_base(&sp.chain, i));
    (vals, d)
}

/// The digest natively: the parts' sponges as one batch per block.
pub fn digest_native(items: &[Fp3]) -> [Goldilocks; 4] {
    let chunks: Vec<&[Fp3]> = items.chunks(parts(items.len())).collect();
    let mut fresh = [Goldilocks::ZERO; WIDTH];
    fresh[RATE] = Goldilocks::new(tag::MSG);
    let mut states = vec![fresh; chunks.len()];
    let blocks = chunks.iter().map(|c| c.len().div_ceil(3)).max().unwrap_or(0);
    for b in 0..blocks {
        let idx: Vec<usize> = (0..chunks.len()).filter(|&q| b * 3 < chunks[q].len()).collect();
        let mut batch: Vec<[Goldilocks; WIDTH]> = idx
            .iter()
            .map(|&q| {
                let mut s = states[q];
                for (k, x) in s.iter_mut().take(RATE).enumerate() {
                    *x = match chunks[q].get(3 * b + k / 3) {
                        Some(v) => [v.c0, v.c1, v.c2][k % 3],
                        None => Goldilocks::ZERO,
                    };
                }
                s
            })
            .collect();
        perm::permute_many(&mut batch);
        for (&q, s) in idx.iter().zip(batch) {
            states[q] = s;
        }
    }
    let heads: Vec<Goldilocks> = states.iter().flat_map(|s| [s[0], s[1], s[2], s[3]]).collect();
    let mut s = fresh;
    for block in heads.chunks(RATE) {
        for (k, x) in s.iter_mut().take(RATE).enumerate() {
            *x = block.get(k).copied().unwrap_or(Goldilocks::ZERO);
        }
        perm::permute(&mut s);
    }
    perm::head(&s)
}

/// Absorb a message's digest into `t`; returns the message's values.
pub fn absorb<O: Ops>(o: &mut O, t: &mut Sponge<O>, items: &[Fp3]) -> Vec<O::V> {
    let (vals, d) = o.message(items);
    t.absorb_all(o, &d);
    vals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::ops::Native;

    #[test]
    fn the_native_digest_is_the_generic_sponge_s() {
        for len in [1usize, 2, 3, 7, 8, 9, 25, 64, 256, 257] {
            let items: Vec<Fp3> = (0..len as u64).map(|i| Fp3::new(Goldilocks::new(i), Goldilocks::new(i * 7 + 1), Goldilocks::new(3))).collect();
            let mut o = Native::new();
            let (vals, d) = absorb_generic(&mut o, &items);
            assert_eq!(vals, items);
            assert_eq!(d.map(|x| x.c0), digest_native(&items), "{len}");
            let mut o = Native::new();
            let (_, d2) = o.message(&items);
            assert_eq!(d2, d);
            // another message, another digest
            let mut other = items.clone();
            other[len - 1] += Fp3::ONE;
            assert_ne!(digest_native(&other), digest_native(&items));
        }
    }
}
