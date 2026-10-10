//! Plan a chain of wrap levels by shape alone (no key words committed, no
//! proof): every level's circuit rows, size, census and weakest ledger
//! row (the final level's bytes: `wrap_plan`).
//!
//! `wrap_chain <spec>…`, each spec as `wrap_bench`'s `ZHENG_WRAP`
//! (`<log inv rate><i|f>[:<pow>[:<fold>]]`, innermost first). IVC
//! parameters as `wrap_bench` (`ZHENG_RATE`, `ZHENG_POW`, `ZHENG_STEP`).

use std::time::Instant;
use zheng::recursion::ivc;
use zheng::recursion::wrap::{self, Mode, WrapParams};

fn env<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn main() {
    let mut whir = zheng::execution::succinct::params_for(20);
    whir.log_inv_rate = env("ZHENG_RATE", 4);
    whir.pow_bits = env("ZHENG_POW", 24);
    let n: usize = env("ZHENG_STEP", 15);
    let ikey = ivc::key(&whir, n).expect("ivc key");
    for spec in std::env::args().skip(1) {
        let t = Instant::now();
        let mut keys: Vec<wrap::WrapKey> = Vec::new();
        let mut line = Vec::new();
        for l in spec.split(',') {
            let mut parts = l.split(':');
            let head = parts.next().expect("level");
            let (rate, mode) = head.split_at(head.len() - 1);
            let mut w = whir;
            w.pow_bits = 24;
            w.log_inv_rate = rate.parse().expect("rate");
            if let Some(p) = parts.next() {
                w.pow_bits = p.parse().expect("pow");
            }
            if let Some(k) = parts.next() {
                w.folding_factor = k.parse().expect("fold");
            }
            let params = WrapParams { whir: w, n: 0, mode: if mode == "f" { Mode::Final } else { Mode::Inner } };
            let k = match keys.last() {
                None => wrap::derive_shape_ivc(params, &ikey),
                Some(prev) => wrap::derive_shape(params, prev),
            };
            let k = match k {
                Ok(k) => k,
                Err(e) => {
                    line.push(format!("{l}: {e}"));
                    break;
                }
            };
            let reads = k.wiring.as_ref().map_or(0, |w| w.reads);
            let rows = wrap::ledger(&k.params, &k.cfg, k.constraints, reads);
            let weak = rows.iter().map(|r| r.1).fold(f64::INFINITY, f64::min);
            let q: Vec<usize> = k.cfg.wc.rounds.iter().map(|r| r.queries).collect();
            line.push(format!("{l}: {} rows (perm blocks {}) → 2^{} · q {q:?} · {weak:.2} bits", k.rows, k.census[2], k.params.n));
            keys.push(k);
        }
        println!("{spec} ({:.1} s)\n  {}", t.elapsed().as_secs_f64(), line.join("\n  "));
    }
}
