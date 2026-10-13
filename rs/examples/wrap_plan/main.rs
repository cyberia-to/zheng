//! Plan a wrap level's opening without proving: for each parameter set,
//! lens's WHIR schedule, the opening's expected bytes (multi-opening
//! siblings by simulation over random query positions), the native
//! verifier's leaf-and-path permutations, the weakest ledger row with
//! grinding priced (ROM) and without (interactive), the grinding work and
//! the prover's round-0 codeword size.
//!
//! `wrap_plan <n> <rates> <pows> <folds> [final_vars] [arity]`: `n` the
//! level's `log2` rows (`ℓ = n + 6`), the rest comma lists, e.g.
//! `wrap_plan 14 8,9,10 18,20,22,30 4,5 8 2`. `ZHENG_INPUTS=2` plans an
//! inner level's two-word batch (round-0 leaves of both words).

use zheng::recursion::wrap::{self, Mode, WrapParams};

fn list(s: &str) -> Vec<u32> {
    s.split(',').map(|x| x.parse().expect("number")).collect()
}

/// Expected siblings of a multi-opening of `q` uniform leaves in a tree of
/// `depth` levels and fan-in `a` (2 or 4; `a − 1` siblings per level).
fn siblings(q: usize, depth: u32, a: usize) -> f64 {
    let trials = 400;
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let lv = if a == 4 { depth / 2 } else { depth };
    let mut total = 0usize;
    for _ in 0..trials {
        let mut cur: Vec<u64> = (0..q).map(|_| rnd() & ((1u64 << depth) - 1)).collect();
        cur.sort_unstable();
        cur.dedup();
        for _ in 0..lv {
            let mut parents: Vec<u64> = cur.iter().map(|&x| x / a as u64).collect();
            parents.dedup();
            // every parent needs its a children; the known ones are `cur`
            total += parents.len() * a - cur.len();
            cur = parents;
        }
        if a == 4 && depth % 2 == 1 {
            let mut parents: Vec<u64> = cur.iter().map(|&x| x / 2).collect();
            parents.dedup();
            total += parents.len() * 2 - cur.len();
        }
    }
    total as f64 / trials as f64
}

fn distinct(q: usize, depth: u32) -> f64 {
    let n = (1u64 << depth) as f64;
    n * (1.0 - (1.0 - 1.0 / n).powi(q as i32))
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let n: usize = a.first().map_or(14, |x| x.parse().expect("n"));
    let rates = list(a.get(1).map_or("8", |s| s));
    let pows = list(a.get(2).map_or("30", |s| s));
    let folds = list(a.get(3).map_or("4", |s| s));
    let fin: u8 = a.get(4).map_or(8, |x| x.parse().expect("final vars"));
    let arity: usize = a.get(5).map_or(2, |x| x.parse().expect("arity"));
    let inputs: usize = std::env::var("ZHENG_INPUTS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let ell = n + wrap::CBITS;
    println!("n {n} · ℓ {ell} · final vars ≤ {fin} · arity {arity} · inputs {inputs}");
    println!("rate pow k | queries per round | opening B | leaf+path perms | ROM min | interactive min | grind 2^x total | round-0 code (2^)");
    for &r in &rates {
        for &k in &folds {
            for &p in &pows {
                let mut whir = zheng::execution::succinct::params_for(20);
                whir.log_inv_rate = r as u8;
                whir.pow_bits = p as u8;
                whir.folding_factor = k as u8;
                whir.max_final_vars = fin;
                let mode = if inputs == 1 { Mode::Final } else { Mode::Inner };
                let params = WrapParams { whir, n, mode };
                let groups: Vec<usize> = vec![1; inputs];
                let cfg = match zheng::recursion::whir::Config::derive(&whir, ell, &groups, inputs + 3) {
                    Ok(c) => c,
                    Err(e) => {
                        let wc = lens::rspcs::whir::WhirConfig::derive(&whir, ell).expect("schedule");
                        let weak: Vec<String> = wc.terms().into_iter().filter(|t| t.1 < 128.0).map(|(a, b)| format!("{a} {b:.1}")).collect();
                        println!("1/{} {p} {k} | {e} ({})", 1u64 << r, weak.join(", "));
                        continue;
                    }
                };
                let wc = &cfg.wc;
                let mut bytes = 0.0;
                let mut perms = 0.0;
                let mut grind = 0.0f64;
                let mut inter = f64::INFINITY;
                let rows = wrap::ledger(&params, &cfg, 250, 1 << 18);
                let rom = rows.iter().map(|x| x.1).fold(f64::INFINITY, f64::min);
                for (name, b) in &rows {
                    // the grinding each term carries
                    let g = if let Some(i) = name.strip_prefix("shift_") {
                        wc.rounds[i.parse::<usize>().unwrap() - 1].query_pow
                    } else if let Some(i) = name.strip_prefix("fold_") {
                        wc.rounds[i.parse::<usize>().unwrap()].fold_pow
                    } else if name == "fin" {
                        wc.rounds.last().unwrap().query_pow
                    } else {
                        0
                    };
                    inter = inter.min(b - g as f64);
                }
                let mut qs = Vec::new();
                for (i, s) in wc.rounds.iter().enumerate() {
                    let fold_n = if s.fold_pow > 0 { s.fold } else { 0 };
                    bytes += (s.ood * 24 + 2 * s.fold * 24 + 8 * fold_n) as f64;
                    for _ in 0..fold_n {
                        grind += 2f64.powi(s.fold_pow as i32);
                    }
                    if s.query_pow > 0 {
                        grind += 2f64.powi(s.query_pow as i32);
                        bytes += 8.0;
                    }
                    if i > 0 {
                        bytes += 32.0;
                    }
                    let depth = s.log_leaves();
                    let q = s.queries;
                    qs.push(q);
                    let words = if i == 0 { inputs } else { 1 };
                    let sym = if i == 0 { 8.0 } else { 24.0 };
                    let lanes = if i == 0 { 1usize << s.fold } else { 3usize << s.fold };
                    let leaf_perms = (lanes as f64 / 9.0).ceil();
                    bytes += 4.0 * q as f64;
                    bytes += words as f64 * (distinct(q, depth) * sym * (1u64 << s.fold) as f64 + 4.0 + 32.0 * siblings(q, depth, arity));
                    let path = if arity == 4 { (depth / 2 + depth % 2) as f64 } else { depth as f64 };
                    perms += words as f64 * q as f64 * (leaf_perms + path);
                }
                bytes += 24.0 * (1u64 << wc.final_vars) as f64;
                let s0 = wc.rounds[0];
                println!(
                    "1/{} {p} {k} | {:?} | {:.0} | {:.0} | {rom:.2} | {inter:.2} | {:.1} | {}",
                    1u64 << r,
                    qs,
                    bytes,
                    perms,
                    grind.log2(),
                    s0.log_domain
                );
            }
        }
    }
}
