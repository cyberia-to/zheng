//! The grinding of a field-native WHIR schedule, rebalanced per round.
//!
//! lens's `WhirConfig::derive` fixes every round's queries `t_i` (the
//! opening's size, and the next wrap circuit's rows) by picking, per round,
//! the proximity regime with the fewest queries under one grinding budget
//! `pow_bits`, and grinds `pow_bits` before every round's queries. Here the
//! queries stay exactly lens's; per round the regime and the grinding are
//! re-chosen to make the least grinding work:
//!
//! ```text
//! round i   W_i = k_i·2^fold_pow + 2^query_pow (+ 2^comb_pow, round 0 of
//!           a batch), over Johnson regimes m = 3..=64 (lens's own family)
//! fold_pow  ⌈128 + log2 ε_fold(m)⌉              (WHIR Thm 5.2, as lens)
//! query_pow ⌈128 + log2((1−δ_m)^t_i + ε_comb)⌉  (the next round's shift
//!           or fin, as lens)
//! ood       the least s with ε_ood ≤ 2^-128      (Lemma 4.25, as lens)
//! ```
//!
//! Every term is lens's (`WhirConfig::terms`, `whir::batch::terms`
//! recompute them from the rebalanced rounds); each is ≥ 128 bits by
//! construction and checked again by `Config::derive`. A round whose
//! queries open every leaf keeps lens's choice.

use lens::rspcs::soundness::{Regime, ext_field_bits, log2_add, mca_log2, proximity};
use lens::rspcs::whir::WhirConfig;

/// Grinding above this per challenge is never chosen.
const POW_CAP: u32 = 32;

fn fold_log_err(regime: Regime, r: u32, log_n: u32, fold: usize) -> f64 {
    let list = 3f64.log2() + proximity(regime, r, log_n).log_list - ext_field_bits();
    (1..=fold).map(|s| log2_add(list, mca_log2(regime, r, log_n - s as u32))).fold(f64::NEG_INFINITY, f64::max)
}

fn ood_count(regime: Regime, r: u32, log_n: u32, m: usize, target: f64) -> usize {
    let log_list = proximity(regime, r, log_n).log_list;
    if log_list == 0.0 {
        return 0;
    }
    (1..64).find(|&s| -(2.0 * log_list - 1.0 + s as f64 * (m as f64 - ext_field_bits())) >= target).unwrap_or(64)
}

fn comb_log_err(regime: Regime, r: u32, log_n: u32, inputs: usize) -> f64 {
    if inputs <= 1 {
        return f64::NEG_INFINITY;
    }
    let d = ((inputs - 1) as f64).log2();
    log2_add(mca_log2(regime, r, log_n) + d, proximity(regime, r, log_n).log_list + d - ext_field_bits())
}

fn pow_for(target: f64, log_err: f64) -> u32 {
    (target + log_err).ceil().max(0.0) as u32
}

/// The query grinding of round `i` given every round's regime and OOD.
fn query_pow(wc: &WhirConfig, i: usize, target: f64) -> u32 {
    let cur = wc.rounds[i];
    if cur.opens_all() {
        return 0;
    }
    let prox = proximity(cur.regime, cur.log_inv_rate, cur.log_domain);
    let comb = wc.rounds.get(i + 1).map_or(f64::NEG_INFINITY, |next| {
        proximity(next.regime, next.log_inv_rate, next.log_domain).log_list + ((cur.queries + next.ood) as f64).log2() - ext_field_bits()
    });
    pow_for(target, log2_add(cur.queries as f64 * prox.log_one_minus_delta, comb))
}

/// Rebalance `wc` (lens's schedule) in place for `inputs` batched words;
/// queries unchanged.
pub fn rebalance(wc: &mut WhirConfig, inputs: usize, target: f64) {
    let lens_rounds = wc.rounds.clone();
    for i in 0..wc.rounds.len() {
        let cur = wc.rounds[i];
        if cur.opens_all() || !matches!(cur.regime, Regime::Johnson(_)) {
            continue;
        }
        let (r, log_n) = (cur.log_inv_rate, cur.log_domain);
        let mut best: Option<(f64, Regime)> = None;
        for m in 3..=64u32 {
            let reg = Regime::Johnson(m);
            let fold_pow = pow_for(target, fold_log_err(reg, r, log_n, cur.fold));
            // the next round's list enters only through a term ~2^-190: lens's
            let qpow = pow_for(target, cur.queries as f64 * proximity(reg, r, log_n).log_one_minus_delta);
            let comb = if i == 0 { pow_for(target, comb_log_err(reg, r, log_n, inputs)) } else { 0 };
            if fold_pow > POW_CAP || qpow > POW_CAP || comb > POW_CAP {
                continue;
            }
            let work = cur.fold as f64 * f64::from(fold_pow).exp2() + f64::from(qpow).exp2() + if inputs > 1 && i == 0 { f64::from(comb).exp2() } else { 0.0 };
            if best.is_none_or(|(w, _)| work < w) {
                best = Some((work, reg));
            }
        }
        if let Some((_, reg)) = best {
            let s = &mut wc.rounds[i];
            s.regime = reg;
            s.fold_pow = pow_for(target, fold_log_err(reg, r, log_n, cur.fold));
            s.ood = ood_count(reg, r, log_n, cur.num_vars, target);
        }
    }
    for i in 0..wc.rounds.len() {
        if !wc.rounds[i].opens_all() {
            wc.rounds[i].query_pow = query_pow(wc, i, target);
        }
        debug_assert_eq!(wc.rounds[i].queries, lens_rounds[i].queries);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rebalanced schedules keep lens's queries, reach 128 bits on
    /// every term and never grind more than lens's.
    #[test]
    fn rebalanced_schedules_keep_the_queries_and_grind_less() {
        let work = |wc: &WhirConfig, inputs: usize| -> f64 {
            let mut w: f64 = wc.rounds.iter().map(|s| s.fold as f64 * f64::from(s.fold_pow).exp2() + if s.opens_all() { 0.0 } else { f64::from(s.query_pow).exp2() }).sum();
            if inputs > 1 {
                w += f64::from(lens::rspcs::whir::batch::comb_pow(wc, inputs, 128.0)).exp2();
            }
            w
        };
        for (rate, pow, ell, inputs) in [(9u8, 26u8, 20usize, 1usize), (7, 22, 21, 5), (4, 16, 22, 3), (3, 16, 21, 3), (4, 24, 21, 3)] {
            let mut whir = crate::execution::succinct::params_for(20);
            whir.log_inv_rate = rate;
            whir.pow_bits = pow;
            let lens_wc = WhirConfig::derive(&whir, ell).unwrap();
            let mut wc = lens_wc.clone();
            rebalance(&mut wc, inputs, 128.0);
            let q = |c: &WhirConfig| c.rounds.iter().map(|s| s.queries).collect::<Vec<_>>();
            assert_eq!(q(&wc), q(&lens_wc));
            assert!(wc.security_bits() >= 128.0, "{rate}/{pow}: {}", wc.security_bits());
            let comb = lens::rspcs::whir::batch::comb_pow(&wc, inputs, 128.0);
            assert!(lens::rspcs::whir::batch::terms(&wc, inputs, 2 * inputs, comb).iter().all(|(_, b)| *b >= 128.0));
            let show = |c: &WhirConfig| c.rounds.iter().map(|s| format!("{:?} t{} q{} f{} o{}", s.regime, s.queries, s.query_pow, s.fold_pow, s.ood)).collect::<Vec<_>>().join(" | ");
            eprintln!("1/{} pow {pow} ℓ {ell} m {inputs}\n  lens {} · comb {} · work 2^{:.1}\n  here {} · comb {} · work 2^{:.1}", 1u32 << rate, show(&lens_wc), lens::rspcs::whir::batch::comb_pow(&lens_wc, inputs, 128.0), work(&lens_wc, inputs).log2(), show(&wc), comb, work(&wc, inputs).log2());
            assert!(work(&wc, inputs) <= work(&lens_wc, inputs), "{rate}/{pow}");
        }
    }
}

