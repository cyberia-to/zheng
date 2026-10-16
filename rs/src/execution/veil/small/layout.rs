//! Where every value of veil-W's committed vector lives, and the size of
//! the masking block the round-0 lemma needs.
//!
//! The committed vector `c` has `2^n` slots (`n ≥ ℓ`, the Spartan free
//! half's variables). Slots `[0, 2^ℓ)` are Spartan's free half: the free
//! wires sit at `[0, used)` and are the only slots any matrix reads. The
//! mask region `M` sits at the top of `[0, 2^n)`: the Libra masks `g1`,
//! `g2` at `[lib, lib + |g1| + |g2|)` and the block `r` at
//! `[2^n − R, 2^n)`, `R = 2^ρ` — the slots whose top `n − ρ` index bits are
//! all one. `n` is the least size with `used ≤ lib`.
//!
//! The block size is the masking lemma's (`docs/explanation/zk-small.md`
//! § the design): with `q₀` round-0 queries, `s₀` round-0 OOD samples and
//! round-0 folding `k₀`, each of the `2^{k₀}` sub-polynomials of `r`
//! needs `D ≥ q₀ + 3·(1 + s₀)` coefficients, so
//! `R = next_pow2(2^{k₀}·(q₀ + 3·(1 + s₀)))`.

use lens::rspcs::WhirConfig;
use lens::WhirParams;

use super::super::libra::Mask;
use super::super::protocol::Setup;

/// Largest committed vector, in variables (the relation cap is 2^20).
const MAX_VARS: usize = 22;

/// The slot layout of one relation under one WHIR parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Slots {
    /// Variables of the committed vector.
    pub n: usize,
    /// First slot after the free wires Spartan reads.
    pub used: usize,
    /// First Libra slot; `g1` then `g2`.
    pub lib: usize,
    /// Libra entries `|g1| + |g2|`.
    pub lib_len: usize,
    /// `log2 R`.
    pub rho: usize,
    /// Round-0 folding `k₀`, queries `q₀` and OOD samples `s₀`.
    pub k0: usize,
    pub q0: usize,
    pub s0: usize,
}

impl Slots {
    pub fn block(&self) -> usize {
        1 << self.rho
    }
    pub fn block_start(&self) -> usize {
        (1 << self.n) - self.block()
    }
    /// Per sub-polynomial coefficients `D = R / 2^{k₀}`.
    #[cfg(test)]
    pub fn per_coset(&self) -> usize {
        self.block() >> self.k0
    }
}

/// `log2 R` the lemma needs at `(params, n)`, with `(k₀, q₀, s₀)`.
fn block_vars(params: &WhirParams, n: usize) -> Result<(usize, usize, usize, usize), String> {
    let cfg = WhirConfig::derive(params, n).map_err(|e| format!("veil-W: schedule: {e:?}"))?;
    let r0 = cfg.rounds[0];
    let need = (r0.queries + 3 * (1 + r0.ood)) << r0.fold;
    Ok((need.next_power_of_two().trailing_zeros() as usize, r0.fold, r0.queries, r0.ood))
}

/// Free slots the relabelled relation reads (one past the last).
pub(crate) fn used_slots(s: &Setup) -> usize {
    let half = s.half();
    s.layout.map.iter().flatten().filter(|&&x| x < half).map(|&x| x + 1).max().unwrap_or(0)
}

impl Slots {
    /// The least `n ≥ ℓ` whose top region holds the Libra masks and the
    /// block under `params`.
    pub fn derive(s: &Setup, params: &WhirParams) -> Result<Self, String> {
        let used = used_slots(s);
        let lib_len = Mask::entries(s.log_m, s.degree) + Mask::entries(s.layout.vars, 2);
        for n in s.layout.vars.max(1)..=MAX_VARS {
            let (rho, k0, q0, s0) = block_vars(params, n)?;
            if rho >= n || rho < k0 {
                continue;
            }
            let top = (1usize << n) - (1usize << rho);
            let Some(lib) = top.checked_sub(lib_len) else { continue };
            if used <= lib {
                return Ok(Self { n, used, lib, lib_len, rho, k0, q0, s0 });
            }
        }
        Err("veil-W: relation too large for the committed-size cap".into())
    }
}
