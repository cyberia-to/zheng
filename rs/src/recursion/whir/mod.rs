//! Field-native WHIR: lens's WHIR (`lens/specs/whir.md`, eprint 2024/1586)
//! on the recursion profile's transcript and words — a duplex sponge over
//! hemera's permutation ([`super::sponge`]) and hemera Merkle trees over
//! field elements ([`super::word`]) — with its verifier written once over
//! [`Ops`](super::ops::Ops), so the same opening is checked natively and
//! inside the recursion circuit.
//!
//! The opening is *batched*: `m` committed words `f_1..f_m` of `ℓ`
//! variables, each carrying evaluation claims at its own points, are
//! opened together.
//!
//! ```text
//! batch   γ; Σ_i Σ_e γ^e·eq(z_e, X)·f_i(X) by an ℓ-round sumcheck to one
//!         point ρ'; μ_i = f_i(ρ'); grinding; r; f_0 = Σ_i r^i·f_i,
//!         f_0(ρ') = Σ_i r^i·μ_i
//! whir    lens's Construction 5.1 on the virtual f_0 at (ρ', Σ r^i μ_i):
//!         OOD on f_0, the folding sumcheck, per round a fresh word of the
//!         folded polynomial, its OOD, grinding, shift queries; the final
//!         polynomial in the clear, final queries, the closing check
//! ```
//!
//! A query on `f_0` opens its leaf in every input word (one path each) and
//! folds `Σ_i r^i·leaf_i`. The round schedule (folds, rates, OOD counts,
//! queries, grinding) is lens's `WhirConfig` for `(whir, ℓ)`; the batch
//! adds the claim-batching, sumcheck and combination rounds of an
//! accumulation step (`accumulate::config`). Soundness:
//! `specs/soundness.md` § field-native WHIR.

mod prove;
mod verify;
pub mod wire;

#[cfg(test)]
mod tests;

pub use prove::prove;
pub use verify::{check_shape, verify};

use lens::rspcs::soundness::{ext_field_bits, log2_add, mca_log2, proximity};
use lens::rspcs::whir::{LeafLayout, RoundSpec, WhirConfig};
use lens::WhirParams;
use nebu::Fp3;

use super::word::{Digest, LeafOpening};

/// Bits every round must prove (grinding included).
pub const MIN_BITS: f64 = 128.0;
/// Grinding budget of the combination challenge.
pub const COMB_POW_MAX: u32 = 32;

/// A batched opening's parameters.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub whir: WhirParams,
    /// lens's round schedule at `(whir, ℓ)`.
    pub wc: WhirConfig,
    /// Input words.
    pub inputs: usize,
    /// The most claims (all inputs together) a proof carries.
    pub claims: usize,
    /// Grinding before the combination challenge `r`.
    pub comb_pow: u32,
}

impl Config {
    pub fn derive(whir: &WhirParams, num_vars: usize, inputs: usize, claims: usize) -> Result<Self, String> {
        let wc = WhirConfig::derive(whir, num_vars).map_err(|e| format!("whir: {e}"))?;
        if inputs == 0 || claims < inputs {
            return Err("whir: every input word carries a claim".into());
        }
        let mut c = Self { whir: *whir, wc, inputs, claims, comb_pow: 0 };
        c.comb_pow = (MIN_BITS + c.comb_log_err()).ceil().max(0.0) as u32;
        if c.comb_pow > COMB_POW_MAX {
            return Err(format!("whir: combination grinding {} > {COMB_POW_MAX}", c.comb_pow));
        }
        let bits = c.security_bits();
        if bits < MIN_BITS {
            return Err(format!("whir: {bits:.2} bits < {MIN_BITS}"));
        }
        Ok(c)
    }

    pub fn num_vars(&self) -> usize {
        self.wc.num_vars
    }
    /// The layout of round `i`'s committed function (round 0: the input
    /// words').
    pub fn layout(&self, i: usize) -> LeafLayout {
        let s = self.wc.rounds[i];
        LeafLayout { log_domain: s.log_domain, log_width: s.fold as u32 }
    }
    pub fn round(&self, i: usize) -> RoundSpec {
        self.wc.rounds[i]
    }
    /// Queries on round `i`'s function.
    pub fn queries(&self, i: usize) -> usize {
        self.wc.rounds[i].queries
    }

    fn log_list0(&self) -> f64 {
        let s = self.wc.rounds[0];
        proximity(s.regime, s.log_inv_rate, s.log_domain).log_list
    }

    fn comb_log_err(&self) -> f64 {
        if self.inputs <= 1 {
            return f64::NEG_INFINITY;
        }
        let s = self.wc.rounds[0];
        let d = ((self.inputs - 1) as f64).log2();
        let mca = mca_log2(s.regime, s.log_inv_rate, s.log_domain) + d;
        log2_add(mca, self.log_list0() + d - ext_field_bits())
    }

    /// Every round-by-round term as `(name, bits)`: the batch's (claim
    /// batching `|Λ|(J−1)/|K|`, sumcheck `2|Λ|/|K|` a round, combination
    /// `ε_mca(m−1) + |Λ|(m−1)/|K|` minus grinding — as an accumulation
    /// step's) and lens's WHIR terms.
    pub fn terms(&self) -> Vec<(String, f64)> {
        let k = ext_field_bits();
        let list = self.log_list0();
        let mut out = Vec::new();
        if self.claims > 1 {
            out.push(("batch γ".into(), k - list - ((self.claims - 1) as f64).log2()));
        }
        out.push(("batch sumcheck".into(), k - list - 1.0));
        if self.inputs > 1 {
            out.push(("batch combine".into(), -self.comb_log_err() + f64::from(self.comb_pow)));
        }
        out.extend(self.wc.terms());
        out
    }

    pub fn security_bits(&self) -> f64 {
        self.terms().into_iter().map(|(_, b)| b).fold(f64::INFINITY, f64::min)
    }
}

/// A claim on one input word (`Multi`: at a point; `Uni`: at `pow(x)`).
pub use super::acc::{ClaimRef, InstV};

/// The batch: the claim sumcheck, every word at its point, the
/// combination's grinding nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchProof {
    pub sumcheck: Vec<Fp3>,
    pub evals: Vec<Fp3>,
    pub comb_nonce: u64,
}

/// One WHIR round after the first: the folded function's root and OOD
/// answers, the shift queries on the previous function, the folding
/// sumcheck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    pub root: Digest,
    pub ood: Vec<Fp3>,
    pub query_nonce: u64,
    /// `open[q][w]`: query `q` in word `w` of the previous function (every
    /// input word when it is `f_0`).
    pub open: Vec<Vec<LeafOpening>>,
    pub sumcheck: Vec<Fp3>,
    pub fold_nonces: Vec<u64>,
}

/// A batched field-native WHIR opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub batch: BatchProof,
    pub ood0: Vec<Fp3>,
    pub sumcheck0: Vec<Fp3>,
    pub fold_nonces0: Vec<u64>,
    pub rounds: Vec<Round>,
    pub final_poly: Vec<Fp3>,
    pub final_nonce: u64,
    pub final_open: Vec<Vec<LeafOpening>>,
}


/// An opening of the right shape, every value zero (circuit layouts are
/// fixed by shapes alone).
pub fn dummy(cfg: &Config, inputs: usize) -> Proof {
    let wc = &cfg.wc;
    let z = Fp3::ZERO;
    let leaf = |s: &RoundSpec| LeafOpening {
        symbols: vec![z; 1 << s.fold],
        path: vec![[nebu::Goldilocks::ZERO; 4]; s.log_leaves() as usize],
        leaf: Some(0),
    };
    let q = |s: &RoundSpec| if s.opens_all() { 1usize << s.log_leaves() } else { s.queries };
    let opens = |s: &RoundSpec, words: usize| vec![vec![leaf(s); words]; q(s)];
    let fold_n = |s: &RoundSpec| if s.fold_pow > 0 { s.fold } else { 0 };
    let s0 = wc.rounds[0];
    let rounds = (1..wc.rounds.len())
        .map(|i| {
            let (prev, s) = (wc.rounds[i - 1], wc.rounds[i]);
            Round {
                root: [nebu::Goldilocks::ZERO; 4],
                ood: vec![z; s.ood],
                query_nonce: 0,
                open: opens(&prev, if i == 1 { inputs } else { 1 }),
                sumcheck: vec![z; 2 * s.fold],
                fold_nonces: vec![0; fold_n(&s)],
            }
        })
        .collect();
    let last = *wc.rounds.last().expect("a round");
    Proof {
        batch: BatchProof { sumcheck: vec![z; 2 * wc.num_vars], evals: vec![z; inputs], comb_nonce: 0 },
        ood0: vec![z; s0.ood],
        sumcheck0: vec![z; 2 * s0.fold],
        fold_nonces0: vec![0; fold_n(&s0)],
        rounds,
        final_poly: vec![z; 1 << wc.final_vars],
        final_nonce: 0,
        final_open: opens(&last, if wc.rounds.len() == 1 { inputs } else { 1 }),
    }
}
