//! Canonical bytes of a batched field-native WHIR opening. Every shape is
//! fixed by the [`Config`] and the input words' symbol fields, so nothing
//! carries a length but the multi-openings' sibling lists; a grinding
//! nonce is present only where its round grinds.
//!
//! ```text
//! batch     sumcheck (2ℓ Fp3) · μ (m Fp3) · nonce?
//! round 0   OOD answers · folding sumcheck · fold nonces?
//! round i   root · OOD answers · query nonce? · openings of round i−1 ·
//!           folding sumcheck · fold nonces?
//! final     polynomial · nonce? · openings of the last round
//! openings  u32 leaf per query; per tree: the symbols of every distinct
//!           leaf (every member's), u32 count + siblings of the
//!           multi-opening
//! ```

use lens::PcsError;
use lens::rspcs::whir::RoundSpec;
use lens::rspcs::wire::{Reader, Writer};
use nebu::Fp3;

use super::{BatchProof, Config, Proof, Round};
use crate::recursion::wire::{bases, digest, exts, expand, multi_siblings, read_bases, read_digest, read_exts};
use crate::recursion::word::{Arity, Digest, LeafOpening};

type R<T> = Result<T, PcsError>;

fn nonce(w: &mut Writer, bits: u32, n: u64) {
    if bits > 0 {
        w.u64(n);
    }
}

fn read_nonce(r: &mut Reader<'_>, bits: u32) -> R<u64> {
    if bits > 0 { r.u64() } else { Ok(0) }
}

fn nonces(w: &mut Writer, v: &[u64]) {
    for &n in v {
        w.u64(n);
    }
}

fn read_nonces(r: &mut Reader<'_>, s: &RoundSpec) -> R<Vec<u64>> {
    let k = if s.fold_pow > 0 { s.fold } else { 0 };
    (0..k).map(|_| r.u64()).collect()
}

fn queries(s: &RoundSpec) -> usize {
    if s.opens_all() { 1 << s.log_leaves() } else { s.queries }
}

fn openings(w: &mut Writer, open: &[Vec<LeafOpening>], ext: &[bool], depth: usize, arity: Arity) {
    // `ext`: per tree
    let leaves: Vec<usize> = open.iter().map(|q| q[0].leaf.expect("an opening knows its leaf")).collect();
    for &l in &leaves {
        w.u32(l);
    }
    let mut distinct = leaves.clone();
    distinct.sort_unstable();
    distinct.dedup();
    for (word, &x) in ext.iter().enumerate() {
        let ops: Vec<(usize, &LeafOpening)> = distinct
            .iter()
            .map(|&l| (l, &open[leaves.iter().position(|&y| y == l).expect("leaf")][word]))
            .collect();
        for (_, op) in &ops {
            if x {
                exts(w, &op.symbols);
            } else {
                bases(w, &op.symbols.iter().map(|s| s.c0).collect::<Vec<_>>());
            }
        }
        let sib = multi_siblings(&ops, depth, arity);
        w.u32(sib.len());
        for d in &sib {
            digest(w, d);
        }
    }
}

fn read_openings(r: &mut Reader<'_>, s: &RoundSpec, ext: &[bool], members: &[usize], arity: Arity) -> R<Vec<Vec<LeafOpening>>> {
    let depth = s.log_leaves() as usize;
    let leaves: Vec<usize> = (0..queries(s)).map(|_| r.u32()).collect::<R<_>>()?;
    if leaves.iter().any(|&l| l >> depth != 0) {
        return Err(PcsError::Malformed);
    }
    let mut distinct = leaves.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let mut per_word = Vec::with_capacity(ext.len());
    for (&x, &m) in ext.iter().zip(members) {
        let width = m << s.fold;
        let syms: Vec<Vec<Fp3>> = distinct
            .iter()
            .map(|_| if x { read_exts(r, width) } else { Ok(read_bases(r, width)?.into_iter().map(Fp3::from_base).collect()) })
            .collect::<R<_>>()?;
        let ns = r.count(32)?;
        let sib: Vec<Digest> = (0..ns).map(|_| read_digest(r)).collect::<R<_>>()?;
        per_word.push(expand(&distinct, syms, &sib, depth, x, arity)?);
    }
    Ok(leaves
        .iter()
        .map(|l| {
            let q = distinct.binary_search(l).expect("leaf");
            per_word.iter().map(|ops: &Vec<LeafOpening>| ops[q].clone()).collect()
        })
        .collect())
}

/// Write `p`, an opening whose round-0 trees have symbol fields `ext`.
pub fn write(w: &mut Writer, cfg: &Config, ext: &[bool], p: &Proof) {
    let wc = &cfg.wc;
    exts(w, &p.batch.sumcheck);
    exts(w, &p.batch.evals);
    nonce(w, cfg.comb_pow, p.batch.comb_nonce);
    exts(w, &p.ood0);
    exts(w, &p.sumcheck0);
    nonces(w, &p.fold_nonces0);
    for (i, rd) in p.rounds.iter().enumerate() {
        let prev = wc.rounds[i];
        digest(w, &rd.root);
        exts(w, &rd.ood);
        nonce(w, prev.query_pow, rd.query_nonce);
        let e: &[bool] = if i == 0 { ext } else { &[true] };
        openings(w, &rd.open, e, prev.log_leaves() as usize, cfg.arity);
        exts(w, &rd.sumcheck);
        nonces(w, &rd.fold_nonces);
    }
    exts(w, &p.final_poly);
    let last = *wc.rounds.last().expect("a round");
    nonce(w, last.query_pow, p.final_nonce);
    let e: &[bool] = if wc.rounds.len() == 1 { ext } else { &[true] };
    openings(w, &p.final_open, e, last.log_leaves() as usize, cfg.arity);
}

/// Read an opening whose round-0 trees have symbol fields `ext`.
pub fn read(r: &mut Reader<'_>, cfg: &Config, ext: &[bool]) -> R<Proof> {
    let wc = &cfg.wc;
    let ell = wc.num_vars;
    let s0 = wc.rounds[0];
    let sumcheck = read_exts(r, 2 * ell)?;
    let evals = read_exts(r, cfg.inputs)?;
    let comb_nonce = read_nonce(r, cfg.comb_pow)?;
    let ood0 = read_exts(r, s0.ood)?;
    let sumcheck0 = read_exts(r, 2 * s0.fold)?;
    let fold_nonces0 = read_nonces(r, &s0)?;
    let mut rounds = Vec::with_capacity(wc.rounds.len() - 1);
    for i in 1..wc.rounds.len() {
        let (prev, s) = (wc.rounds[i - 1], wc.rounds[i]);
        let root = read_digest(r)?;
        let ood = read_exts(r, s.ood)?;
        let query_nonce = read_nonce(r, prev.query_pow)?;
        let (e, g): (&[bool], &[usize]) = if i == 1 { (ext, &cfg.groups) } else { (&[true], &[1]) };
        let open = read_openings(r, &prev, e, g, cfg.arity)?;
        let sc = read_exts(r, 2 * s.fold)?;
        let fold_nonces = read_nonces(r, &s)?;
        rounds.push(Round { root, ood, query_nonce, open, sumcheck: sc, fold_nonces });
    }
    let final_poly = read_exts(r, 1 << wc.final_vars)?;
    let last = *wc.rounds.last().expect("a round");
    let final_nonce = read_nonce(r, last.query_pow)?;
    let (e, g): (&[bool], &[usize]) = if wc.rounds.len() == 1 { (ext, &cfg.groups) } else { (&[true], &[1]) };
    let final_open = read_openings(r, &last, e, g, cfg.arity)?;
    Ok(Proof {
        batch: BatchProof { sumcheck, evals, comb_nonce },
        ood0,
        sumcheck0,
        fold_nonces0,
        rounds,
        final_poly,
        final_nonce,
        final_open,
    })
}
