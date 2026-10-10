//! Parameters of a recursion profile instance: the WHIR parameters of
//! every committed word, the step size, the accumulation configuration
//! derived from them, and the shapes they fix.

use lens::WhirParams;

use super::circuit::layout as cl;
use super::relation::{self, G_POINT, SEEDS};
use super::state::{Dims, ZeroWord};
use super::word::Digest;
use crate::accumulate::{self, AccConfig};
use crate::machine::air::{Constants, Machine};
use crate::machine::layout::{W1, W2};

/// Input words of an accumulation step: the accumulator and words a, b, c.
pub const INPUTS: usize = 4;
/// Segment-index bits in the nox public claim.
pub const STEP_BITS: usize = 32;
/// Column-index variables of the nox public claim (31 columns → 32).
pub const PN_COLS: usize = 5;
/// Variables of a word's column index (64 columns).
pub const CBITS: usize = 6;
/// Circuit columns in the boundary row.
pub const BV: usize = cl::V1 + cl::V2;

#[derive(Clone, Debug, PartialEq)]
pub struct Params {
    pub whir: WhirParams,
    /// `log2` of a step's rows.
    pub n: usize,
    /// `ℓ = n + 6`.
    pub vars: usize,
    pub cfg: AccConfig,
    /// OOD samples binding each fresh word.
    pub fresh: usize,
    pub dims: Dims,
    pub base: usize,
    pub g_deg: usize,
    pub pn_deg: usize,
    pub pv_deg: usize,
    pub zero_root: Digest,
    /// The circuit row carrying the step's public input.
    pub out_row: usize,
}

impl Params {
    /// Derive everything but `out_row` (set from the circuit layout).
    pub fn new(whir: &WhirParams, n: usize) -> Result<Self, String> {
        let vars = n + CBITS;
        crate::execution::succinct::admit::<lens::Whir>(whir, vars)?;
        let fresh = accumulate::fresh_ood(whir, vars)?;
        let probe = AccConfig::derive(whir, vars, INPUTS, 3 * (fresh + 2))?;
        let claims = probe.acc_claims() + 3 * (fresh + 2);
        let cfg = AccConfig::derive(whir, vars, INPUTS, claims)?;
        let constants = Constants { fml0: 0, obj0: 0, p: 0, output: [nebu::Goldilocks::ZERO; 4], cycles: 0, root: [nebu::Goldilocks::ZERO; 4] };
        let machine = Machine::new(constants, &[], 1 << n, 0, 1 << n);
        let rel = relation::Relation::new(machine, [nebu::Fp3::ZERO; 2]);
        let dims = Dims {
            boundary: W1 + W2,
            vars,
            ood: cfg.ood,
            spot: cfg.queries,
            g: G_POINT,
            pn: n + STEP_BITS + PN_COLS,
            pv: n + cl::pre::LOG,
        };
        let zero = ZeroWord::new(&cfg.layout);
        Ok(Self {
            whir: *whir,
            n,
            vars,
            cfg,
            fresh,
            dims,
            base: rel.base,
            g_deg: rel.g_degree(),
            pn_deg: dims.pn,
            pv_deg: dims.pv,
            zero_root: zero.root,
            out_row: 0,
        })
    }

    /// The zerocheck's round degree (`D + 1`).
    pub fn zc_deg(&self) -> usize {
        9
    }
    pub fn seeds(&self) -> usize {
        SEEDS
    }
}

/// Every round-by-round term of the recursion profile at `p` as `(name,
/// bits)`, grinding priced (`specs/soundness.md` § recursion), and the
/// grinding bits each term carries (its interactive value is the
/// difference).
pub fn ledger(p: &Params) -> Vec<(String, f64, u32)> {
    let j = p.cfg.acc_claims() + 3 * (p.fresh + 2);
    let mut rows: Vec<(String, f64, u32)> = p
        .cfg
        .terms(INPUTS, j)
        .into_iter()
        .map(|(n, b)| {
            let g = if n == "combine" {
                p.cfg.comb_pow_for(INPUTS)
            } else if n.starts_with("spot") || n.starts_with("position") {
                p.cfg.query_pow
            } else {
                0
            };
            (n, b, g)
        })
        .collect();
    if let Ok(dcfg) = super::whir::Config::derive(&p.whir, p.vars, &[1, 2], p.cfg.acc_claims() + 2) {
        let wc = &dcfg.wc;
        for (n, b) in dcfg.terms() {
            let g = if let Some(i) = n.strip_prefix("shift_") {
                wc.rounds[i.parse::<usize>().unwrap_or(1) - 1].query_pow
            } else if let Some(i) = n.strip_prefix("fold_") {
                wc.rounds[i.parse::<usize>().unwrap_or(0)].fold_pow
            } else if n == "fin" {
                wc.rounds.last().map_or(0, |r| r.query_pow)
            } else if n == "batch combine" {
                dcfg.comb_pow
            } else {
                0
            };
            rows.push((format!("decider {n}"), b, g));
        }
    }
    let k = lens::rspcs::soundness::ext_field_bits();
    let log2 = |x: usize| (x as f64).log2();
    let mut push = |n: &str, b: f64| rows.push((n.into(), b, 0));
    push("zerocheck μ (structured powers)", k - log2(SEEDS * (p.base - 1)));
    push("zerocheck τ", k - log2(p.n));
    push("zerocheck round (degree 9)", k - log2(10));
    // shift reduction: rounds of degree 2, ζ over three words (degree
    // 2), β (degree 1), column batching of 64 columns (6 variables)
    push("shift round (degree 2)", k - log2(2));
    push("shift batching ζ, β", k - log2(2));
    push("shift / boundary column batching", k - log2(CBITS));
    push("constraint line fold", k - log2(p.g_deg));
    push("nox public line fold", k - log2(p.pn_deg));
    push("circuit key line fold", k - log2(p.pv_deg));
    push("column batching γ_n, γ_v", k - log2(cl::pre::LOG));
    // circuit memory: T slot accesses per step
    let t = cl::SLOTS << p.n;
    push("circuit memory α", k - log2(t));
    push("circuit memory β (pairs)", k - 2.0 * log2(t) + 1.0);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;


    /// Every round of the recursion profile at its shipped parameters
    /// proves ≥ 128 bits (`specs/soundness.md` § recursion).
    #[test]
    fn every_ledger_row_of_the_recursion_profile_reaches_128_bits() {
        for rate in [4u8, 6] {
            rows_at(rate);
        }
    }

    fn rows_at(rate: u8) {
        let mut whir = crate::execution::succinct::params_for(20);
        whir.log_inv_rate = rate;
        whir.pow_bits = 24;
        let p = Params::new(&whir, 15).unwrap();
        eprintln!("rate 1/{}", 1u32 << rate);
        let j = p.cfg.acc_claims() + 3 * (p.fresh + 2);
        let rows = ledger(&p);
        for (name, bits, _) in &rows {
            eprintln!("{name:40} {bits:8.2}");
            assert!(*bits >= 128.0, "{name}: {bits}");
        }
        eprintln!("t {} s {} query_pow {} comb_pow {} fresh {} J {j} base {} g_deg {}", p.cfg.queries, p.cfg.ood, p.cfg.query_pow, p.cfg.comb_pow_for(INPUTS), p.fresh, p.base, p.g_deg);
    }
}

#[cfg(test)]
mod levers {
    use super::*;

    /// Queries the size levers buy (printed; `cargo test -- --ignored`).
    #[test]
    #[ignore = "prints the parameter table of audit/recursion-2026-10.md"]
    fn parameter_levers() {
        for (rate, pow, k) in [(4u8, 24u8, 4u8), (4, 30, 4), (4, 24, 5), (5, 24, 4), (6, 24, 4), (6, 30, 4)] {
            let mut whir = crate::execution::succinct::params_for(20);
            whir.log_inv_rate = rate;
            whir.pow_bits = pow;
            whir.folding_factor = k;
            match Params::new(&whir, 15) {
                Ok(p) => {
                    let wc = lens::rspcs::WhirConfig::derive(&whir, p.vars).unwrap();
                    let q: Vec<usize> = wc.rounds.iter().map(|r| r.queries).collect();
                    eprintln!(
                        "rate 1/{} pow {pow} k {k}: acc t {} depth {} · decider rounds {} queries {:?} final vars {} · bits {:.2}",
                        1 << rate, p.cfg.queries, p.cfg.layout.log_leaves(), wc.rounds.len(), q, wc.final_vars, wc.security_bits()
                    );
                }
                Err(e) => eprintln!("rate 1/{} pow {pow} k {k}: {e}", 1 << rate),
            }
        }
    }
}
