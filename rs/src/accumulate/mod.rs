//! Hash-based accumulation of evaluation claims on Reed–Solomon codewords,
//! and its decider.
//!
//! An *instance* is a WHIR-committed word `u: L → K` (root, base or Fp3
//! symbols) with evaluation claims `f(z_j) = y_j` on its message `f` (the
//! multilinear whose monomial coefficients define `û`, `û(x) = f(pow(x))`).
//! It is accepted (relaxed relation) when `u` is `δ`-close to a codeword of
//! `C = RS[K, L, 2^ℓ]` whose message satisfies every claim.
//!
//! An accumulation step reduces `m` instances (an accumulator and fresh
//! ones alike) to one *accumulator*: a new Fp3 word `g` with
//! `1 + s + t` claims, whatever `m` and whatever the depth — the distance
//! `δ` is preserved, so steps compose without bound. The step is the
//! claim-carrying form of WARP (Bünz–Chiesa–Fenzi–Wang, eprint 2025/753:
//! pseudo-batching §6, codeword batching Construction 7.2) instantiated for
//! Reed–Solomon codes with univariate out-of-domain samples as in ARC
//! (Bünz–Mishra–Nguyen–Wang, eprint 2024/1731, §2.1) and WHIR:
//!
//! 1. `γ`; sumcheck reduces every claim of every word to one point `ρ`;
//!    the prover sends `μ_i = f_i(ρ)`;
//! 2. grinding, `r`; the virtual word `u' = Σ r^{i} u_i` carries the claim
//!    `f'(ρ) = Σ r^{i} μ_i`;
//! 3. the prover commits `g` (honestly `u'`), answers `s` OOD samples;
//! 4. grinding, `t` positions `x_k ∈ L`; every input word is opened there
//!    and `y_k = Σ r^i u_i(x_k)` becomes the claim `ĝ(x_k) = y_k`.
//!
//! The decider proves one accumulator with a claim-batching sumcheck and a
//! single WHIR opening of `g` at the resulting point. See
//! `specs/accumulation.md`; parameters and the round-by-round bound in
//! [`config`].

pub mod config;
mod decide;
mod step;
pub mod sumcheck;
mod wire;

#[cfg(test)]
mod tests;

pub use config::{AccConfig, MIN_BITS};
pub use decide::{DeciderProof, decide, verify_decider};
pub use step::{AccProof, Accumulator, accumulate, verify_step};

use lens::rspcs::WhirData;
use lens::rspcs::field::pow_point;
use lens::{Commitment, Transcript};
use nebu::Fp3;

/// `f(point) = value` on a word's message; `point` in lens order (variable
/// `k` ↔ bit `k` of a table index).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub point: Vec<Fp3>,
    pub value: Fp3,
}

impl Claim {
    /// The claim `û(x) = value` for a univariate point `x`.
    pub fn univariate(x: Fp3, vars: usize, value: Fp3) -> Self {
        Self {
            point: pow_point(x, vars),
            value,
        }
    }
}

/// A committed word and its claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub root: Commitment,
    /// Fp3 symbols (an accumulator) or Goldilocks ones (a fresh witness).
    pub ext: bool,
    pub claims: Vec<Claim>,
}

/// An instance with the prover's committed data.
pub struct Witnessed {
    pub instance: Instance,
    pub data: WhirData,
}

impl Instance {
    pub(crate) fn absorb(&self, t: &mut Transcript) {
        t.absorb(self.root.as_bytes());
        t.absorb(&[u8::from(self.ext)]);
        t.absorb_u64(self.claims.len() as u64);
        for c in &self.claims {
            t.absorb_u64(c.point.len() as u64);
            t.absorb_fp3_slice(&c.point);
            t.absorb_fp3(c.value);
        }
    }
}

/// The transcript every step and decider of one accumulation runs on:
/// domain, the caller's context bytes and the configuration.
pub fn transcript(domain: &[u8], context: &[u8], cfg: &AccConfig) -> Transcript {
    let mut t = Transcript::new(domain);
    t.absorb_u64(context.len() as u64);
    t.absorb(context);
    t.absorb(&cfg.whir.header());
    t.absorb_u64(cfg.num_vars as u64);
    t.absorb_u64(cfg.ood as u64);
    t.absorb_u64(cfg.queries as u64);
    t.absorb_u64(u64::from(cfg.query_pow));
    t
}
