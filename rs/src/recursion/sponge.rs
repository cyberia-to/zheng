//! The field-native Fiat–Shamir transcript of the recursion profile: an
//! overwrite-mode duplex over hemera's permutation, rate [`RATE`] lanes,
//! capacity 7 lanes (the first holds the transcript's tag before the first
//! block), written once over [`Ops`] so the prover, the final verifier and
//! the recursion circuit run the same transcript.
//!
//! Absorbed items fill the rate lanes in order (an Fp3 takes three lanes
//! and never straddles a block); a block is permuted when the rate is full
//! or before a squeeze, unused lanes zero. A squeeze reads the next output
//! lanes of the last block (an Fp3 = three lanes; a squeeze-only block
//! keeps the previous rate). Challenges are output limbs of the
//! permutation: uniform on `F_p` in the ideal-permutation model, no
//! reduction from bytes. Indices take the low bits of a limb `v ≠ p − 1`
//! (`p − 1 = 2^32·(2^32 − 1)`, so `v mod 2^k` is exactly uniform for
//! `k ≤ 32`). Grinding absorbs a nonce and requires the low bits of the
//! next squeezed limb to be zero.

use nebu::{Fp3, Goldilocks};

use super::ops::{Arith, In, Ops};
use super::perm::RATE;

pub struct Sponge<O: Ops> {
    pub chain: O::Chain,
    pending: Vec<In<O::V>>,
    used: usize,
    /// Next unread output lane of the last block (`RATE` = none).
    out: usize,
}

impl<O: Ops> Sponge<O> {
    pub fn new(o: &mut O, tag: u64) -> Self {
        Self {
            chain: o.chain(tag),
            pending: Vec::new(),
            used: 0,
            out: RATE,
        }
    }

    fn push(&mut self, o: &mut O, it: In<O::V>) {
        let w = it.width();
        if self.used + w > RATE {
            self.flush(o);
        }
        self.pending.push(it);
        self.used += w;
        if self.used == RATE {
            self.flush(o);
        }
    }

    /// Whether absorbed items wait for a permutation.
    pub fn has_pending(&self) -> bool {
        self.used > 0
    }

    /// Permute the pending block (zero padding).
    pub fn flush(&mut self, o: &mut O) {
        let mut items = core::mem::take(&mut self.pending);
        let pad = if self.used == 0 { In::Keep } else { In::Zero };
        for _ in self.used..RATE {
            items.push(pad);
        }
        self.used = 0;
        self.out = 0;
        o.permute(&mut self.chain, &items)
    }

    pub fn absorb(&mut self, o: &mut O, v: O::V) {
        self.push(o, In::Var(v, false));
    }
    pub fn absorb_ext(&mut self, o: &mut O, v: O::V) {
        self.push(o, In::Var(v, true));
    }
    pub fn absorb_all(&mut self, o: &mut O, vs: &[O::V]) {
        for &v in vs {
            self.absorb(o, v);
        }
    }
    pub fn absorb_all_ext(&mut self, o: &mut O, vs: &[O::V]) {
        for &v in vs {
            self.absorb_ext(o, v);
        }
    }

    fn squeeze_lanes(&mut self, o: &mut O, w: usize) -> usize {
        if self.used > 0 || self.out + w > RATE {
            self.flush(o);
        }
        let lane = self.out;
        self.out += w;
        lane
    }
    pub fn squeeze(&mut self, o: &mut O) -> O::V {
        let lane = self.squeeze_lanes(o, 1);
        o.out_base(&self.chain, lane)
    }
    pub fn squeeze_ext(&mut self, o: &mut O) -> O::V {
        let lane = self.squeeze_lanes(o, 3);
        o.out_ext(&self.chain, lane)
    }
    pub fn squeeze_exts(&mut self, o: &mut O, k: usize) -> Vec<O::V> {
        (0..k).map(|_| self.squeeze_ext(o)).collect()
    }
    /// `count` symbol indices in `[0, 2^log_n)`: the low bits of a limb
    /// `≠ p − 1`; returns their bits (low first).
    pub fn indices(&mut self, o: &mut O, count: usize, log_n: usize) -> Vec<Vec<O::V>> {
        assert!(log_n <= 32);
        (0..count)
            .map(|_| {
                let v = self.squeeze(o);
                o.assert_ne_const(v, Fp3::from_base(Goldilocks::new(nebu::field::P - 1)), "index limb p − 1");
                o.bits(v, log_n)
            })
            .collect()
    }
    /// Check a grinding nonce: absorb it, the next limb's low `bits` bits
    /// are zero (nothing happens for 0 bits).
    pub fn grind_check(&mut self, o: &mut O, bits: u32, nonce: u64) {
        if bits == 0 {
            return;
        }
        self.absorb_free(o, Goldilocks::new(nonce));
        let v = self.squeeze(o);
        for b in o.bits(v, bits as usize) {
            o.assert_const(b, Fp3::ZERO, "grinding");
        }
    }
}

/// Values to absorb that the prover supplies (proof messages).
impl<O: Ops> Sponge<O> {
    pub fn absorb_free(&mut self, o: &mut O, x: Goldilocks) -> O::V {
        let v = o.alloc(Fp3::from_base(x));
        self.push(o, In::Free(v, false));
        v
    }
    pub fn absorb_free_ext(&mut self, o: &mut O, x: Fp3) -> O::V {
        let v = o.alloc(x);
        self.push(o, In::Free(v, true));
        v
    }
}

/// The prover's grinding: the least nonce whose check passes on the
/// native transcript (the check's block input built once; the search runs
/// on the process's prover backend, which returns the least nonce).
pub fn grind(t: &Sponge<super::ops::Native>, bits: u32) -> u64 {
    if bits == 0 {
        return 0;
    }
    let mut base = t.clone_native();
    let mut o = super::ops::Native::new();
    if base.used + 1 > RATE {
        base.flush(&mut o);
    }
    let lane = base.used;
    let mut items = base.pending.clone();
    items.push(In::Free(Fp3::ZERO, false));
    for _ in base.used + 1..RATE {
        items.push(In::Zero);
    }
    let template = base.chain.input(&items).map(|x| x.as_u64());
    lens::rspcs::backend::current().grind(&template, lens::rspcs::backend::Inject::lane(lane), bits)
}

impl Sponge<super::ops::Native> {
    pub fn clone_native(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            pending: self.pending.clone(),
            used: self.used,
            out: self.out,
        }
    }
}

/// The prover's side of the transcript (native values).
pub struct ProverTranscript {
    pub o: super::ops::Native,
    pub sp: Sponge<super::ops::Native>,
}

impl ProverTranscript {
    pub fn new(tag: u64) -> Self {
        let mut o = super::ops::Native::new();
        let sp = Sponge::new(&mut o, tag);
        Self { o, sp }
    }
    pub fn absorb(&mut self, x: Goldilocks) {
        self.sp.absorb(&mut self.o, Fp3::from_base(x));
    }
    pub fn absorb_all(&mut self, xs: &[Goldilocks]) {
        for &x in xs {
            self.absorb(x);
        }
    }
    pub fn absorb_ext(&mut self, x: Fp3) {
        self.sp.absorb_ext(&mut self.o, x);
    }
    pub fn squeeze(&mut self) -> Goldilocks {
        self.sp.squeeze(&mut self.o).c0
    }
    pub fn squeeze_ext(&mut self) -> Fp3 {
        self.sp.squeeze_ext(&mut self.o)
    }
    pub fn squeeze_exts(&mut self, k: usize) -> Vec<Fp3> {
        (0..k).map(|_| self.squeeze_ext()).collect()
    }
    /// Grind `bits`, absorb the nonce; returns it.
    pub fn grind(&mut self, bits: u32) -> u64 {
        let n = grind(&self.sp, bits);
        self.sp.grind_check(&mut self.o, bits, n);
        n
    }
    /// `count` symbol indices in `[0, 2^log_n)` (`Err` on a limb `p − 1`).
    pub fn indices(&mut self, count: usize, log_n: usize) -> Result<Vec<usize>, String> {
        (0..count)
            .map(|_| {
                let v = self.squeeze().as_u64();
                if v == nebu::field::P - 1 {
                    return Err("recursion: index limb p − 1 (regrind)".to_string());
                }
                Ok((v & ((1u64 << log_n) - 1)) as usize)
            })
            .collect()
    }
}

impl crate::fs::FiatShamir for ProverTranscript {
    fn absorb_fp3(&mut self, x: Fp3) {
        self.absorb_ext(x);
    }
    fn squeeze_fp3(&mut self) -> Fp3 {
        self.squeeze_ext()
    }
}
