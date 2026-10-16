//! The prover's randomness: a counter-mode PRF over the hemera permutation,
//! keyed from a 32-byte seed (OS entropy, or a fixed seed in tests).
//!
//! Key. `K = derive_key("zheng-veil-coins-v2", seed)`, read as four
//! Goldilocks elements (hemera's constant-time key derivation; the seed and
//! the key are zeroized on drop).
//!
//! Block `b` of the stream `label` is the first eight lanes of
//!
//! ```text
//! π_ct(K0 K1 K2 K3 ‖ label ‖ b ‖ 0 × 9 ‖ TAG)
//! ```
//!
//! with `π_ct` hemera's constant-time Poseidon2 permutation (`permute_ct`);
//! the other eight lanes (512 bits) are never output. Element `i` of a
//! stream is lane `i mod 8` of block `⌊i/8⌋`; an `Fp3` element takes three
//! consecutive base elements. Every element is a whole output lane — a
//! field element already — so no rejection sampling and no branch on
//! secret data. Each block is a pure function of `(K, label, b)`, so a
//! vector fills in parallel over blocks and equals the sequential fill for
//! any thread count.
//!
//! Labels: every consumer reads its own stream, so no two consumers ever
//! share an input to `π_ct` (see [`label`]).
//!
//! Security (`audit/veil-coins-2026-10.md`): with `π` an ideal permutation
//! on `F_p^16`, a distinguisher making `q` block queries and `N` offline
//! permutation queries tells the streams from independent uniform field
//! elements with advantage at most `N/p^4 + N·q/p^8 + (q + N)²/p^16`
//! (`≈ N·2^-256`), on top of `derive_key`'s own pseudorandomness.

use hemera::field::Goldilocks as Lane;
use hemera::permutation::permute_ct;
use nebu::{Fp3, Goldilocks};
use zeroize::Zeroizing;

use crate::par;

/// `derive_key` context of the PRF key.
const CONTEXT: &str = "zheng-veil-coins-v2";
/// Lane 15 of every block input: ASCII "veilcoin" mod p.
const TAG: u64 = u64::from_le_bytes(*b"veilcoin") % nebu::field::P;
/// Output lanes per block (hemera's rate); the capacity half stays hidden.
pub(crate) const BLOCK: usize = 8;
/// Elements below which a fill stays on one thread.
const PAR_MIN: usize = 1 << 12;

/// A stream's label: lane 4 of every block input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Label(pub u64);

/// The label table. One stream per consumer; the streams never overlap.
pub(crate) mod label {
    use super::Label;
    /// `pad::Extension::witness`: the masking rows' free values, in fill order.
    pub const PAD_FILL: Label = Label(1);
    /// Libra mask of the outer sumcheck (`g1`), coefficients round-major.
    pub const LIBRA_G1: Label = Label(2);
    /// Libra mask of the inner sumcheck (`g2`).
    pub const LIBRA_G2: Label = Label(3);
    /// Hiding commitment: `ν_i`, element `row·k + c` is coefficient
    /// `k + c` of data row `row`.
    pub const ROW_PAD: Label = Label(4);
    /// Hiding commitment masking row `m_a` (`K` coefficients).
    pub const MASK_A: Label = Label(5);
    /// Hiding commitment masking row `m_b` (`k − 1` coefficients).
    pub const MASK_B: Label = Label(6);
    /// Hiding commitment masking row `m_P` (`K` coefficients).
    pub const MASK_P: Label = Label(7);
    /// Column salts: element `4j + s` is limb `s` of column `j`'s salt.
    pub const SALT: Label = Label(8);
    /// veil-W (`small`): the masking block `r` of the committed vector.
    pub const W_BLOCK: Label = Label(9);
    /// veil-W: the round-0 mask table `G` (Fp3).
    pub const W_G: Label = Label(10);
    /// veil-W: the round-0 leaf salts, leaf-major.
    pub const W_SALT: Label = Label(11);
    /// Tests only: labels from here up.
    #[cfg(test)]
    pub const TEST: Label = Label(1 << 32);
}

pub(crate) struct Coins {
    key: Zeroizing<[u64; 4]>,
}

impl Coins {
    /// Fresh OS entropy.
    pub fn os() -> Result<Self, String> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| "veil: entropy unavailable".to_string())?;
        Ok(Self::seeded(*seed))
    }

    /// A deterministic key (tests and differential runs).
    pub fn seeded(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let bytes = Zeroizing::new(hemera::derive_key(CONTEXT, seed.as_ref()));
        let mut key = Zeroizing::new([0u64; 4]);
        for (k, chunk) in key.iter_mut().zip(bytes.chunks_exact(8)) {
            // hemera digests carry canonical lanes; no reduction, no branch
            *k = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
        }
        Self { key }
    }

    /// The permutation input of block `b` of stream `label`.
    fn input(&self, label: Label, b: u64) -> [Lane; 16] {
        let mut state = [Lane::ZERO; 16];
        for (s, &k) in state.iter_mut().zip(self.key.iter()) {
            *s = Lane::new(k);
        }
        state[4] = Lane::new(label.0);
        state[5] = Lane::new(b);
        state[15] = Lane::new(TAG);
        state
    }

    /// Block `b` of stream `label`: the rate half of `π_ct(input)`, read
    /// canonically by hemera's masked reduction (no branch on the value).
    fn block(&self, label: Label, b: u64) -> [Goldilocks; BLOCK] {
        let mut state = self.input(label, b);
        permute_ct(&mut state);
        let out = core::array::from_fn(|i| Goldilocks::new(state[i].as_canonical_u64()));
        // the key and the hidden half leave the stack (best effort; the
        // output itself is the caller's secret)
        state = [Lane::ZERO; 16];
        core::hint::black_box(&mut state);
        out
    }

    /// Elements `offset .. offset + out.len()` of stream `label`, on this
    /// thread.
    pub fn fill_at(&self, label: Label, offset: usize, out: &mut [Goldilocks]) {
        let mut i = 0;
        while i < out.len() {
            let pos = offset + i;
            let (b, lane) = (pos / BLOCK, pos % BLOCK);
            let block = self.block(label, b as u64);
            let n = (BLOCK - lane).min(out.len() - i);
            out[i..i + n].copy_from_slice(&block[lane..lane + n]);
            i += n;
        }
    }

    /// The first `out.len()` elements of stream `label`, in threads.
    pub fn fill(&self, label: Label, out: &mut [Goldilocks]) {
        par::chunks_mut(out, PAR_MIN, |off, chunk| self.fill_at(label, off, chunk));
    }

    /// The first `n` elements of stream `label`.
    pub fn bases(&self, label: Label, n: usize) -> Vec<Goldilocks> {
        let mut v = vec![Goldilocks::ZERO; n];
        self.fill(label, &mut v);
        v
    }

    /// The first `n` `Fp3` elements of stream `label` (three bases each).
    pub fn exts(&self, label: Label, n: usize) -> Vec<Fp3> {
        self.bases(label, 3 * n)
            .chunks_exact(3)
            .map(|c| Fp3::new(c[0], c[1], c[2]))
            .collect()
    }

    /// A sequential reader of stream `label` from element 0.
    #[cfg(test)]
    pub fn stream(&self, label: Label) -> Stream<'_> {
        Stream {
            coins: self,
            label,
            next: 0,
        }
    }
}

/// Sequential access to one stream (tests).
#[cfg(test)]
pub(crate) struct Stream<'a> {
    coins: &'a Coins,
    label: Label,
    next: usize,
}

#[cfg(test)]
impl Stream<'_> {
    pub fn base(&mut self) -> Goldilocks {
        let mut v = [Goldilocks::ZERO];
        self.coins.fill_at(self.label, self.next, &mut v);
        self.next += 1;
        v[0]
    }

    pub fn bases(&mut self, n: usize) -> Vec<Goldilocks> {
        let mut v = vec![Goldilocks::ZERO; n];
        self.coins.fill_at(self.label, self.next, &mut v);
        self.next += n;
        v
    }

    pub fn ext(&mut self) -> Fp3 {
        Fp3::new(self.base(), self.base(), self.base())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_seed_is_deterministic_and_seeds_differ() {
        let a = Coins::seeded([7; 32]).bases(label::SALT, 100);
        assert_eq!(a, Coins::seeded([7; 32]).bases(label::SALT, 100));
        assert_ne!(a, Coins::seeded([8; 32]).bases(label::SALT, 100));
        let mut s = [7u8; 32];
        s[31] ^= 1;
        assert_ne!(a, Coins::seeded(s).bases(label::SALT, 100));
    }

    #[test]
    fn os_coins_differ() {
        let a = Coins::os().unwrap().bases(label::ROW_PAD, 16);
        let b = Coins::os().unwrap().bases(label::ROW_PAD, 16);
        assert_ne!(a, b);
    }

    #[test]
    fn element_is_lane_of_block() {
        let c = Coins::seeded([1; 32]);
        let v = c.bases(label::MASK_A, 3 * BLOCK);
        for b in 0..3 {
            assert_eq!(&v[b * BLOCK..(b + 1) * BLOCK], &c.block(label::MASK_A, b as u64));
        }
        // the input layout, spelled out once with the plain permutation
        let mut st = [Lane::ZERO; 16];
        for (s, &k) in st.iter_mut().zip(c.key.iter()) {
            *s = Lane::new(k);
        }
        st[4] = Lane::new(label::MASK_A.0);
        st[5] = Lane::new(2);
        st[15] = Lane::new(TAG);
        assert_eq!(st, c.input(label::MASK_A, 2));
        hemera::permutation::permute(&mut st);
        let want: Vec<Goldilocks> = st[..BLOCK].iter().map(|l| Goldilocks::new(l.as_canonical_u64())).collect();
        assert_eq!(&v[2 * BLOCK..], &want[..]);
    }

    /// Parallel fill == sequential fill == any chunking == the reader.
    #[test]
    fn parallel_fill_equals_sequential() {
        let c = Coins::seeded([2; 32]);
        for n in [0usize, 1, 7, 8, 9, 4095, 4096, 4097, 50_001] {
            let par = c.bases(label::SALT, n);
            let mut seq = vec![Goldilocks::ZERO; n];
            c.fill_at(label::SALT, 0, &mut seq);
            assert_eq!(par, seq, "n {n}");
            for chunk in [1usize, 3, 8, 13, 1000] {
                let mut v = vec![Goldilocks::ZERO; n];
                for (i, part) in v.chunks_mut(chunk).enumerate() {
                    c.fill_at(label::SALT, i * chunk, part);
                }
                assert_eq!(v, seq, "n {n} chunk {chunk}");
            }
            // explicit thread counts over the same scoped split par uses
            for threads in [2usize, 3, 5, 16] {
                let mut v = vec![Goldilocks::ZERO; n];
                let chunk = n.div_ceil(threads).max(1);
                std::thread::scope(|s| {
                    for (i, part) in v.chunks_mut(chunk).enumerate() {
                        let c = &c;
                        s.spawn(move || c.fill_at(label::SALT, i * chunk, part));
                    }
                });
                assert_eq!(v, seq, "n {n} threads {threads}");
            }
            let mut r = c.stream(label::SALT);
            let read: Vec<_> = (0..n.min(100)).map(|_| r.base()).collect();
            assert_eq!(read, seq[..n.min(100)]);
        }
        let e = c.exts(label::LIBRA_G1, 10);
        let b = c.bases(label::LIBRA_G1, 30);
        assert!(e.iter().zip(b.chunks(3)).all(|(e, b)| *e == Fp3::new(b[0], b[1], b[2])));
    }

    #[test]
    fn labels_and_blocks_are_separated() {
        let c = Coins::seeded([3; 32]);
        let all = [
            label::PAD_FILL,
            label::LIBRA_G1,
            label::LIBRA_G2,
            label::ROW_PAD,
            label::MASK_A,
            label::MASK_B,
            label::MASK_P,
            label::SALT,
            label::W_BLOCK,
            label::W_G,
            label::W_SALT,
        ];
        let mut seen = std::collections::HashSet::new();
        for l in all {
            for b in 0..64u64 {
                for v in c.block(l, b) {
                    assert!(seen.insert(v.as_u64()), "repeat at label {l:?} block {b}");
                }
            }
        }
        assert_ne!(c.block(label::SALT, 0), c.block(label::SALT, 1));
        assert_ne!(c.block(label::SALT, 0), c.block(label::MASK_P, 0));
    }

    /// Bucket chi-square on the low 8 bits and on `⌊256·v/p⌋` over 2^17
    /// elements, and no repeated element. Thresholds: 255 degrees of
    /// freedom, the 1e-6 upper tail is about 370.
    #[test]
    fn elements_look_uniform() {
        let n = 1usize << 17;
        let v = Coins::seeded([4; 32]).bases(label::TEST, n);
        let mut low = [0u64; 256];
        let mut range = [0u64; 256];
        let mut seen = std::collections::HashSet::with_capacity(n);
        for x in &v {
            let x = x.as_u64();
            assert!(x < nebu::field::P);
            assert!(seen.insert(x), "repeated element");
            low[(x & 0xff) as usize] += 1;
            range[((u128::from(x) * 256) / u128::from(nebu::field::P)) as usize] += 1;
        }
        // statistic × expected, in integers: Σ (o − e)² with e = n/256
        let e = (n / 256) as i64;
        for (name, h) in [("low bits", low), ("value/p", range)] {
            let num: i64 = h.iter().map(|&o| (o as i64 - e).pow(2)).sum();
            let chi2_times_e = num;
            assert!(chi2_times_e < 370 * e, "{name}: chi-square {} too large", num / e);
            assert!(chi2_times_e > 160 * e, "{name}: chi-square {} too small", num / e);
        }
        // the top bit is set about half the time (p ≈ 2^64 − 2^32)
        let top = v.iter().filter(|x| x.as_u64() >> 63 == 1).count();
        assert!((top as i64 - (n / 2) as i64).abs() < 2_000, "top bit {top}");
    }
}
