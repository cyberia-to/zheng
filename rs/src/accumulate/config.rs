//! Parameters of one accumulation step and their proven round-by-round
//! soundness (`specs/accumulation.md` § soundness).
//!
//! Every committed word of an accumulation lives in the code
//! `C = RS[K, L, 2^ℓ]` of the WHIR round-0 layout for `(whir, ℓ)`: domain
//! `L` of order `2^{ℓ+r}` in Goldilocks, rate `ρ = 2^{−r}`, `K = Fp3`.
//! The proximity parameter is the decider's: `δ` and the list bound are
//! those of the regime lens derives for WHIR's first round at `(whir, ℓ)`,
//! so a word the decider accepts is within the same `δ` the accumulation
//! verifier reasons about.
//!
//! Terms for a step with `m` input words carrying `J` claims in total
//! (`|Λ|` = list bound of `C^m` at `δ`, WHIR Theorem 4.3 with Lemma 4.4):
//!
//! | round | error | source |
//! |---|---|---|
//! | `γ` (claim batching) | `|Λ|·(J − 1)/|K|` | Schwartz–Zippel in `γ`, union over `Λ(C^m, δ)` |
//! | sumcheck round `k` (`ℓ` rounds) | `|Λ|·2/|K|` | sumcheck (degree 2), union over `Λ(C^m, δ)` |
//! | `r` (word combination) | `ε_mca(m−1) + |Λ|·(m − 1)/|K|`, minus `comb_pow` | BCGM Thm 9.2/Lemma 9.3 (powers generator, degree `m − 1`) with WHIR Lemma 4.13; Schwartz–Zippel in `r` |
//! | OOD (`s` samples) | `(|Λ_1|²/2)·(2^ℓ/|K|)^s` | WHIR Lemma 4.25 (WARP Lemma 7.3 `ε_out`) |
//! | spot checks (`t` positions) | `(1 − δ)^t`, minus `query_pow` | WARP Lemma 7.3 `ε_shift` |
//!
//! `ε_mca(d)` is `d` times lens's affine-line term (`soundness::mca_log2`):
//! Johnson `(μ+½)^7/(3ρ^{3/2})·d·n²/|K|`, unique decoding `d·n/|K|`.

use lens::rspcs::soundness::{Regime, ext_field_bits, log2_add, mca_log2, proximity};
use lens::rspcs::whir::{LeafLayout, WhirConfig};
use lens::WhirParams;

/// Bits every accumulation step must prove (round-by-round, grinding
/// included).
pub const MIN_BITS: f64 = 128.0;

/// Derived parameters of the accumulation steps over one code.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AccConfig {
    /// The WHIR parameters of every committed word and of the decider.
    pub whir: WhirParams,
    /// `ℓ`: variables of every committed multilinear.
    pub num_vars: usize,
    pub layout: LeafLayout,
    /// The proximity regime (WHIR round 0's at `(whir, ℓ)`).
    pub regime: Regime,
    /// Out-of-domain samples on each new accumulator word.
    pub ood: usize,
    /// Spot-check positions per step.
    pub queries: usize,
    /// Grinding before the spot-check positions.
    pub query_pow: u32,
    /// Grinding before the combination challenge `r`.
    pub comb_pow: u32,
    /// The largest number of input words per step this config admits.
    pub max_inputs: usize,
}

/// Grinding budget of the combination challenge: the MCA error of an
/// `m`-word combination is `(m − 1)` times WHIR's own fold term, so wide
/// steps grind more than WHIR's per-challenge budget.
pub const COMB_POW_MAX: u32 = 32;

impl AccConfig {
    /// Parameters reaching [`MIN_BITS`] for up to `max_inputs` words per
    /// step and `max_claims` claims per step, grinding at most
    /// `whir.pow_bits` per challenge.
    pub fn derive(
        whir: &WhirParams,
        num_vars: usize,
        max_inputs: usize,
        max_claims: usize,
    ) -> Result<Self, String> {
        let wc = WhirConfig::derive(whir, num_vars).map_err(|e| format!("acc: whir: {e}"))?;
        let spec = wc.rounds[0];
        let layout = LeafLayout::derive(whir, num_vars).map_err(|e| format!("acc: {e}"))?;
        let r = spec.log_inv_rate;
        let log_n = spec.log_domain;
        let prox = proximity(spec.regime, r, log_n);
        let budget = u32::from(whir.pow_bits);
        let k = ext_field_bits();
        // OOD: least s with (|Λ|²/2)·(2^ℓ/|K|)^s ≤ 2^-128
        let ood = if prox.log_list == 0.0 {
            0
        } else {
            (1..64)
                .find(|&s| -(2.0 * prox.log_list - 1.0 + s as f64 * (num_vars as f64 - k)) >= MIN_BITS)
                .ok_or("acc: no OOD count reaches the target")?
        };
        let need = (MIN_BITS - f64::from(budget)).max(0.0);
        let queries = ((need / -prox.log_one_minus_delta).ceil() as usize).max(1);
        let query_pow = (MIN_BITS - queries as f64 * -prox.log_one_minus_delta)
            .ceil()
            .max(0.0) as u32;
        let mut cfg = Self {
            whir: *whir,
            num_vars,
            layout,
            regime: spec.regime,
            ood,
            queries,
            query_pow,
            comb_pow: 0,
            max_inputs,
        };
        cfg.comb_pow = cfg.comb_pow_for(max_inputs);
        if cfg.comb_pow > COMB_POW_MAX || cfg.query_pow > budget {
            return Err(format!(
                "acc: grinding {}/{} exceeds the budget {COMB_POW_MAX}/{budget}",
                cfg.comb_pow, cfg.query_pow
            ));
        }
        let bits = cfg.security_bits(max_inputs, max_claims);
        if bits < MIN_BITS {
            return Err(format!("acc: {bits:.2} bits < {MIN_BITS}"));
        }
        Ok(cfg)
    }

    fn log_n(&self) -> u32 {
        self.layout.log_domain
    }

    fn rate_bits(&self) -> u32 {
        self.layout.log_domain - self.num_vars as u32
    }

    /// `log2 |Λ(C^m, δ)|` (independent of `m`: WHIR Lemma 4.4).
    pub fn log_list(&self) -> f64 {
        proximity(self.regime, self.rate_bits(), self.log_n()).log_list
    }

    /// `log2(1 − δ)`.
    pub fn log_one_minus_delta(&self) -> f64 {
        proximity(self.regime, self.rate_bits(), self.log_n()).log_one_minus_delta
    }

    /// Grinding before `r` for a step with `m` input words: the least
    /// count reaching [`MIN_BITS`] (0 for one word).
    pub fn comb_pow_for(&self, m: usize) -> u32 {
        (MIN_BITS + self.comb_log_err(m)).ceil().max(0.0) as u32
    }

    /// `log2` of the combination round's error before grinding.
    fn comb_log_err(&self, m: usize) -> f64 {
        if m <= 1 {
            return f64::NEG_INFINITY;
        }
        let d = ((m - 1) as f64).log2();
        let mca = mca_log2(self.regime, self.rate_bits(), self.log_n()) + d;
        log2_add(mca, self.log_list() + d - ext_field_bits())
    }

    /// Every round-by-round term of a step with `m` input words and `j`
    /// claims in total, as `(name, bits)`.
    pub fn terms(&self, m: usize, j: usize) -> Vec<(String, f64)> {
        let k = ext_field_bits();
        let list = self.log_list();
        let mut out = Vec::new();
        if j > 1 {
            out.push(("batch".into(), k - list - ((j - 1) as f64).log2()));
        }
        out.push(("sumcheck".into(), k - list - 1.0));
        if m > 1 {
            out.push((
                "combine".into(),
                -self.comb_log_err(m) + f64::from(self.comb_pow_for(m)),
            ));
        }
        if list > 0.0 {
            let ood = 2.0 * list - 1.0 + self.ood as f64 * (self.num_vars as f64 - k);
            out.push(("ood".into(), -ood));
        }
        out.push((
            "spot".into(),
            -(self.queries as f64 * self.log_one_minus_delta()) + f64::from(self.query_pow),
        ));
        out
    }

    /// Minimum over the terms of a step with `m` words and `j` claims.
    pub fn security_bits(&self, m: usize, j: usize) -> f64 {
        self.terms(m, j)
            .into_iter()
            .map(|(_, b)| b)
            .fold(f64::INFINITY, f64::min)
    }

    /// Claims an accumulator instance carries: the combined evaluation,
    /// the OOD answers and the spot checks.
    pub fn acc_claims(&self) -> usize {
        1 + self.ood + self.queries
    }
}
