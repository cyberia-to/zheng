//! Size levers of proposal §A, one at a time, on WHIR (the bake-off
//! winner) at a small and a large fixture:
//! - Merkle path deduplication: lens already sends only the siblings the
//!   verifier cannot recompute; the column reports what full per-query paths
//!   would cost on the same proof;
//! - grinding 16 → 20 → 24 bits;
//! - folding factor 2 … 6;
//! - rate 1/2 … 1/32;
//! - encodings: the u32 length prefixes lens writes (every one of them is
//!   implied by the parameters and the size), and field elements as fixed
//!   8-byte limbs against LEB128 varints of the same values.

use super::{Fixture, header, print, run, whir};
use crate::common::{HASH, parse};
use zheng::execution::succinct::{SuccinctProof, Whir, WhirParams};
use lens::rspcs::WhirConfig;
use lens::rspcs::wire::Symbols;

fn leb(v: u64) -> usize {
    ((64 - v.leading_zeros() as usize).div_ceil(7)).max(1)
}

/// `(dedup siblings, full-path siblings, u32 prefixes, limbs, varint bytes of the limbs)`.
fn anatomy(p: &SuccinctProof<Whir>, vars: usize) -> (usize, usize, usize, usize, usize) {
    let w = &p.opening;
    let cfg = WhirConfig::derive(&p.params, vars).unwrap();
    let mut dedup = 0;
    let mut full = 0;
    let openings: Vec<_> = w
        .rounds
        .iter()
        .map(|r| &r.opening)
        .chain(std::iter::once(&w.final_opening))
        .collect();
    for (opening, spec) in openings.iter().zip(&cfg.rounds) {
        let leaves = opening.symbols.len() / opening.width.max(1);
        dedup += opening.siblings.len();
        full += leaves * spec.log_leaves() as usize;
    }
    let prefixes = 4 + 7 * w.rounds.len() + 5;
    let mut limbs: Vec<u64> = Vec::new();
    let mut ext = |xs: &[nebu::Fp3]| {
        for x in xs {
            limbs.extend([x.c0.as_u64(), x.c1.as_u64(), x.c2.as_u64()]);
        }
    };
    ext(&p.matrix_evals);
    for r in p.outer.rounds.iter().chain(&p.inner.rounds) {
        ext(r);
    }
    ext(&[p.witness_eval]);
    ext(&w.ood0);
    ext(&w.sumcheck0);
    ext(&w.final_poly);
    for r in &w.rounds {
        ext(&r.ood);
        ext(&r.sumcheck);
    }
    let mut digests = vec![p.root.0];
    for o in &openings {
        match &o.symbols {
            Symbols::Base(v) => limbs.extend(v.iter().map(|x| x.as_u64())),
            Symbols::Ext(v) => {
                for x in v {
                    limbs.extend([x.c0.as_u64(), x.c1.as_u64(), x.c2.as_u64()]);
                }
            }
        }
        digests.extend(o.siblings.iter().copied());
    }
    digests.extend(w.rounds.iter().map(|r| r.root));
    for d in digests {
        for c in d.as_bytes().chunks_exact(8) {
            limbs.push(u64::from_le_bytes(c.try_into().unwrap()));
        }
    }
    let varint = limbs.iter().map(|&v| leb(v)).sum();
    (dedup, full, prefixes, limbs.len(), varint)
}

fn describe(p: &SuccinctProof<Whir>, vars: usize) -> String {
    let (dedup, full, prefixes, limbs, varint) = anatomy(p, vars);
    let cfg = WhirConfig::derive(&p.params, vars).unwrap();
    let queries: Vec<String> = cfg.rounds.iter().map(|r| r.queries.to_string()).collect();
    format!(
        "t=[{}] siblings {dedup} (full paths {full}, dedup saves {} B); u32 prefixes {prefixes} ({} B); {limbs} limbs: fixed {} B vs varint {varint} B",
        queries.join(" "),
        (full - dedup) * 32,
        prefixes * 4,
        limbs * 8,
    )
}

pub fn levers(reps: usize) {
    let small = || Fixture::Program("hash.tri", parse(HASH), vec![7]);
    let large = || Fixture::Synthetic(20);
    header();
    for (fx, rate, k) in [(small(), 4u8, 4u8), (large(), 4, 4)] {
        let d = |p: &SuccinctProof<Whir>, vars: usize| describe(p, vars);
        for pow in [16u8, 20, 24] {
            let label = format!("WHIR 1/{} k={k} pow={pow}", 1 << rate);
            if let Some(r) = run::<Whir>(&label, whir(rate, k, pow), &fx, reps, d) {
                print(&r);
            }
        }
        for kk in [2u8, 3, 4, 5, 6] {
            let label = format!("WHIR 1/{} k={kk} pow=16", 1 << rate);
            if let Some(r) = run::<Whir>(&label, whir(rate, kk, 16), &fx, reps, d) {
                print(&r);
            }
        }
        for rr in [1u8, 2, 3, 4, 5] {
            let label = format!("WHIR 1/{} k={k} pow=16", 1 << rr);
            if let Some(r) = run::<Whir>(&label, whir(rr, k, 16), &fx, reps, d) {
                print(&r);
            }
        }
    }
}

/// Levers combined: rate × folding factor × grinding × final variables, on
/// one small and two large fixtures (sizes are deterministic; one run each).
pub fn combos(reps: usize) {
    use crate::common::hash_chain;
    header();
    let fixtures = [
        Fixture::Program("hash.tri", parse(HASH), vec![7]),
        Fixture::Program("chain-11 (hemera)", hash_chain(11), vec![7]),
        Fixture::Synthetic(16),
        Fixture::Synthetic(20),
    ];
    for fx in &fixtures {
        for rate in [4u8, 5, 6] {
            for k in [3u8, 4, 5] {
                for pow in [16u8, 20] {
                    for fin in [8u8, 6, 4] {
                        let p = WhirParams {
                            max_final_vars: fin,
                            ..whir(rate, k, pow)
                        };
                        let label = format!("WHIR 1/{} k={k} pow={pow} fin={fin}", 1 << rate);
                        if let Some(r) = run::<Whir>(&label, p, fx, reps, |_, _| String::new()) {
                            print(&r);
                        }
                    }
                }
            }
        }
    }
}
