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

pub use prove::{prove, prove_direct};
pub use verify::{check_shape, verify, verify_direct};

use lens::rspcs::whir::{LeafLayout, RoundSpec, WhirConfig};
use lens::WhirParams;
use nebu::Fp3;

use super::word::{Arity, Digest, LeafOpening, Word};

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
    /// Input words (polynomials).
    pub inputs: usize,
    /// Input words per round-0 tree (a [`super::word::Group`] commits
    /// several under one tree; one path opens them all).
    pub groups: Vec<usize>,
    /// The most claims (all inputs together) a proof carries.
    pub claims: usize,
    /// Grinding before the combination challenge `r`.
    pub comb_pow: u32,
    /// The fan-in of every tree it opens (round 0's words must be
    /// committed with it).
    pub arity: Arity,
}

impl Config {
    /// `groups`: input words per round-0 tree.
    pub fn derive(whir: &WhirParams, num_vars: usize, groups: &[usize], claims: usize) -> Result<Self, String> {
        let wc = WhirConfig::derive(whir, num_vars).map_err(|e| format!("whir: {e}"))?;
        let inputs: usize = groups.iter().sum();
        if inputs == 0 || groups.contains(&0) || claims < inputs {
            return Err("whir: every input word carries a claim".into());
        }
        let mut c = Self { whir: *whir, wc, inputs, groups: groups.to_vec(), claims, comb_pow: 0, arity: Arity::Two };
        c.comb_pow = lens::rspcs::whir::batch::comb_pow(&c.wc, inputs, MIN_BITS);
        if c.comb_pow > COMB_POW_MAX {
            return Err(format!("whir: combination grinding {} > {COMB_POW_MAX}", c.comb_pow));
        }
        let bits = c.security_bits();
        if bits < MIN_BITS {
            return Err(format!("whir: {bits:.2} bits < {MIN_BITS}"));
        }
        Ok(c)
    }

    /// The same opening over trees of `arity`.
    pub fn with_arity(mut self, arity: Arity) -> Self {
        self.arity = arity;
        self
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

    /// One input word: its claims are WHIR's initial weights (no batch
    /// sumcheck).
    pub fn direct(&self) -> bool {
        self.inputs == 1
    }

    /// Every round-by-round term as `(name, bits)`: the batch's (lens
    /// `whir::batch`) and lens's WHIR terms.
    pub fn terms(&self) -> Vec<(String, f64)> {
        let mut out = lens::rspcs::whir::batch::terms(&self.wc, self.inputs, self.claims, self.comb_pow);
        out.extend(self.wc.terms());
        out
    }

    pub fn security_bits(&self) -> f64 {
        self.terms().into_iter().map(|(_, b)| b).fold(f64::INFINITY, f64::min)
    }
}

/// A committed tree of one or more input words (the prover's side).
pub trait Tree: Sync {
    fn arity(&self) -> Arity;
    fn members(&self) -> Vec<&Word>;
    fn root(&self) -> Digest;
    fn open(&self, leaf: usize) -> LeafOpening;
}

impl Tree for Word {
    fn arity(&self) -> Arity {
        self.arity
    }
    fn members(&self) -> Vec<&Word> {
        vec![self]
    }
    fn root(&self) -> Digest {
        Word::root(self)
    }
    fn open(&self, leaf: usize) -> LeafOpening {
        Word::open(self, leaf)
    }
}

impl Tree for super::word::Group {
    fn arity(&self) -> Arity {
        self.arity
    }
    fn members(&self) -> Vec<&Word> {
        self.words.iter().collect()
    }
    fn root(&self) -> Digest {
        super::word::Group::root(self)
    }
    fn open(&self, leaf: usize) -> LeafOpening {
        super::word::Group::open(self, leaf)
    }
}

/// The weight of a direct claim `Σ_x w(x)·f(x) = v` on the one input
/// word (direct mode; `ℓ = n + 6`: rows the low `n` variables, 64
/// columns the high six).
#[derive(Clone, Debug)]
pub enum Weight<V> {
    /// `eq(point, ·)`.
    Eq(Vec<V>),
    /// `eq(pow(x), ·)`.
    Pow(V),
    /// `row(ρ, r)·col[c]` at index `c·2^n + r`, `row` = `eq` or the
    /// successor `nxt` (the claim on a column combination at `ρ` or at its
    /// successor row).
    RowCol { next: bool, rho: Vec<V>, col: Vec<V> },
    /// The `i`-th [`NativeWeight`] (a native verifier only).
    Native(usize),
}

/// A weight a native verifier evaluates itself.
pub trait NativeWeight {
    /// The weight over the word (the prover's table).
    fn table(&self) -> Vec<Fp3>;
    /// Its values at `(α, b)` for every `b` of the last `fv` variables,
    /// `α` the first `ℓ − fv` (the closing check).
    fn partial(&self, alpha: &[Fp3], fv: usize) -> Vec<Fp3>;
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
    /// `open[q][w]`: query `q` in tree `w` of the previous function (every
    /// round-0 tree when it is `f_0`, members' symbols concatenated).
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
pub fn dummy(cfg: &Config) -> Proof {
    let wc = &cfg.wc;
    let z = Fp3::ZERO;
    let leaf = |s: &RoundSpec, m: usize| LeafOpening {
        symbols: vec![z; m << s.fold],
        path: vec![[nebu::Goldilocks::ZERO; 4]; cfg.arity.path_len(s.log_leaves() as usize)],
        leaf: Some(0),
    };
    let q = |s: &RoundSpec| if s.opens_all() { 1usize << s.log_leaves() } else { s.queries };
    let opens = |s: &RoundSpec, first: bool| {
        let one = [1usize];
        let g: &[usize] = if first { &cfg.groups } else { &one };
        vec![g.iter().map(|&m| leaf(s, m)).collect::<Vec<_>>(); q(s)]
    };
    let fold_n = |s: &RoundSpec| if s.fold_pow > 0 { s.fold } else { 0 };
    let s0 = wc.rounds[0];
    let rounds = (1..wc.rounds.len())
        .map(|i| {
            let (prev, s) = (wc.rounds[i - 1], wc.rounds[i]);
            Round {
                root: [nebu::Goldilocks::ZERO; 4],
                ood: vec![z; s.ood],
                query_nonce: 0,
                open: opens(&prev, i == 1),
                sumcheck: vec![z; 2 * s.fold],
                fold_nonces: vec![0; fold_n(&s)],
            }
        })
        .collect();
    let last = *wc.rounds.last().expect("a round");
    Proof {
        batch: BatchProof { sumcheck: vec![z; 2 * wc.num_vars], evals: vec![z; cfg.inputs], comb_nonce: 0 },
        ood0: vec![z; s0.ood],
        sumcheck0: vec![z; 2 * s0.fold],
        fold_nonces0: vec![0; fold_n(&s0)],
        rounds,
        final_poly: vec![z; 1 << wc.final_vars],
        final_nonce: 0,
        final_open: opens(&last, wc.rounds.len() == 1),
    }
}
