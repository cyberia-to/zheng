//! Plan the recursion profile (IVC) without proving: for each step size,
//! rate and grinding budget, the step circuit's rows against the step's
//! `2^n` (the verifier of the previous step must fit beside the nox
//! segment), the accumulation's spot checks and grinding, the decider's
//! queries, the weakest ledger row with grinding priced and without, the
//! grinding work of a step and of the decider, and the committed words'
//! sizes.
//!
//! `ivc_plan <steps> <rates> <pows> [folds]`, comma lists, e.g.
//! `ivc_plan 14,15,16 4,5 16,20,24`.

use zheng::recursion::{ivc, params};

fn list(s: &str) -> Vec<u32> {
    s.split(',').map(|x| x.parse().expect("number")).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let steps = list(a.first().map_or("15", |s| s));
    let rates = list(a.get(1).map_or("4", |s| s));
    let pows = list(a.get(2).map_or("24", |s| s));
    let folds = list(a.get(3).map_or("4", |s| s));
    println!(
        "n rate pow k | circuit rows / 2^n (gates, bits, perm blocks) | acc t, query_pow, comb_pow | decider queries | ROM min (term) | interactive min | grinding 2^x per step, decider | word 2^x symbols"
    );
    for &n in &steps {
        for &r in &rates {
            for &k in &folds {
                for &p in &pows {
                    let mut whir = zheng::execution::succinct::params_for(20);
                    whir.log_inv_rate = r as u8;
                    whir.pow_bits = p as u8;
                    whir.folding_factor = k as u8;
                    let head = format!("{n} 1/{} {p} {k}", 1u32 << r);
                    let (pp, rows, census) = match ivc::plan(&whir, n as usize) {
                        Ok(x) => x,
                        Err(e) => {
                            println!("{head} | {e}");
                            continue;
                        }
                    };
                    let led = params::ledger(&pp);
                    let (wn, wb, _) =
                        led.iter()
                            .cloned()
                            .fold((String::new(), f64::INFINITY, 0), |a, x| {
                                if x.1 < a.1 { x } else { a }
                            });
                    let inter = led
                        .iter()
                        .map(|x| x.1 - x.2 as f64)
                        .fold(f64::INFINITY, f64::min);
                    let comb = pp.cfg.comb_pow_for(params::INPUTS);
                    let step_grind = 2f64.powi(pp.cfg.query_pow as i32) + 2f64.powi(comb as i32);
                    let (dq, dgrind) = match zheng::recursion::whir::Config::derive(
                        &whir,
                        pp.vars,
                        &[1, 2],
                        pp.cfg.acc_claims() + 2,
                    ) {
                        Ok(d) => {
                            let q: Vec<usize> = d.wc.rounds.iter().map(|r| r.queries).collect();
                            let mut g = 2f64.powi(d.comb_pow as i32);
                            for s in &d.wc.rounds {
                                g += 2f64.powi(s.query_pow as i32);
                                if s.fold_pow > 0 {
                                    g += s.fold as f64 * 2f64.powi(s.fold_pow as i32);
                                }
                            }
                            (format!("{q:?}"), g.log2())
                        }
                        Err(e) => (e, f64::NAN),
                    };
                    let fits = if rows <= 1 << n {
                        "fits"
                    } else {
                        "DOES NOT FIT"
                    };
                    println!(
                        "{head} | {rows} / {} {fits} ({}, {}, {}) | {}, {}, {comb} | {dq} | {wb:.2} ({wn}) | {inter:.2} | {:.1}, {dgrind:.1} | {}",
                        1u64 << n,
                        census[0],
                        census[1],
                        census[2],
                        pp.cfg.queries,
                        pp.cfg.query_pow,
                        step_grind.log2(),
                        pp.cfg.layout.log_domain
                    );
                }
            }
        }
    }
}
