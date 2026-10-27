//! A recording prover backend for the review tests: the CPU under a device
//! name, every call counted, every device path taken with lens's reference
//! kernels; `evil` corrupts every result it returns.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use lens::rspcs::backend::{self, Backend, Cpu, CosetLeaves, CpuSession, Inject, LineSession, State};
use lens::rspcs::program::{Limbs, Program};

const P: u64 = 0xFFFF_FFFF_0000_0001;

const METHODS: [&str; 9] = ["permute", "grind", "sponge", "line_sums", "line_session", "merkle_levels", "coset_leaves", "coset_ntt", "name"];

pub struct Rec {
    name: &'static str,
    evil: bool,
    pub calls: [AtomicU64; 9],
}

impl Rec {
    pub fn new(name: &'static str, evil: bool) -> Self {
        Self { name, evil, calls: Default::default() }
    }
    fn hit(&self, i: usize) {
        self.calls[i].fetch_add(1, Relaxed);
    }
    pub fn counts(&self) -> Vec<(&'static str, u64)> {
        METHODS[..8].iter().zip(&self.calls).map(|(m, c)| (*m, c.load(Relaxed))).filter(|c| c.1 > 0).collect()
    }
}

impl Backend for Rec {
    fn name(&self) -> &'static str {
        self.name
    }
    fn permute(&self, states: &mut [State]) {
        self.hit(0);
        Cpu.permute(states);
        if self.evil {
            states.iter_mut().for_each(|s| s[0] ^= 1);
        }
    }
    fn grind(&self, template: &State, inject: Inject, bits: u32) -> u64 {
        self.hit(1);
        Cpu.grind(template, inject, bits) + u64::from(self.evil)
    }
    fn sponge(&self, init: &State, rate: usize, blocks: usize, lanes: &[u64]) -> Vec<[u64; 4]> {
        self.hit(2);
        let mut v = Cpu.sponge(init, rate, blocks, lanes);
        if self.evil {
            v.iter_mut().for_each(|d| d[0] ^= 1);
        }
        v
    }
    fn line_sums(&self, prog: &Program, cols: &[Limbs], weights: &[Limbs], xs: &[u64]) -> Vec<Limbs> {
        self.hit(3);
        let mut v = Cpu.line_sums(prog, cols, weights, xs);
        if self.evil {
            v.iter_mut().for_each(|l| l[0] = (l[0] + 1) % P);
        }
        v
    }
    fn line_session<'a>(&'a self, prog: &'a Program, cols: &[Limbs], len: usize) -> Option<Box<dyn LineSession + 'a>> {
        self.hit(4);
        Some(Box::new(CpuSession::new(prog, cols, len)))
    }
    fn merkle_levels(&self, leaves: &[[u64; 4]], arities: &[usize], tag: u64) -> Option<Vec<Vec<[u64; 4]>>> {
        self.hit(5);
        let mut v = backend::merkle_levels_reference(leaves, arities, tag);
        if self.evil {
            v.iter_mut().for_each(|l| l.iter_mut().for_each(|d| d[0] ^= 1));
        }
        Some(v)
    }
    fn coset_leaves(&self, job: &CosetLeaves<'_>, cosets: core::ops::Range<usize>) -> Option<Vec<[u64; 4]>> {
        self.hit(6);
        let mut v = backend::coset_leaves_reference(job, cosets);
        if self.evil {
            v.iter_mut().for_each(|d| d[0] ^= 1);
        }
        Some(v)
    }
    fn coset_ntt(&self, coeffs: &[u64], shifts: &[u64]) -> Vec<Vec<u64>> {
        self.hit(7);
        let mut v = Cpu.coset_ntt(coeffs, shifts);
        if self.evil {
            v.iter_mut().for_each(|c| c[0] = (c[0] + 1) % P);
        }
        v
    }
}

/// The CPU backend.
pub struct Cpu2;
impl Backend for Cpu2 {
    fn name(&self) -> &'static str {
        "cpu"
    }
}
