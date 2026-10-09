//! Canonical bytes of a recursive proof. Every shape is fixed by the
//! parameters, so nothing but the header carries a length: LE, canonical
//! Goldilocks limbs (8 B), Fp3 = three limbs, digests = four limbs.
//!
//! ```text
//! header   u8 log_rows · u64 start · u64 segments · digest chain
//! state    its items in hashing order
//! step     roots · OOD answers · boundary rows · zerocheck · columns at ρ
//!          · publics · line folds · shift · values · accumulation step
//! decider  lens wire (accumulate::DeciderProof)
//! ```
//!
//! The accumulation step's openings are deduplicated per word: the spot
//! checks' leaf indices (u32 each), then per word the symbols of every
//! distinct leaf and the siblings of a lens-style multi-opening; the
//! reader rebuilds every full path by hashing.

use lens::rspcs::wire::{Reader, Writer};
use lens::PcsError;
use nebu::{Fp3, Goldilocks};

use super::acc::AccProof;
use super::ivc::IvcProof;
use super::params::{BV, Params};
use super::perm;
use super::relation::{COLS, PUB_NOX, PUB_V};
use super::state::{State, StateV};
use super::step::StepProof;
use super::word::{Digest, LeafOpening, leaf_digest};
use crate::accumulate::DeciderProof;
use crate::machine::layout::{W1, W2};

type R<T> = Result<T, PcsError>;

fn digest(w: &mut Writer, d: &Digest) {
    for &x in d {
        w.base(x);
    }
}
fn read_digest(r: &mut Reader<'_>) -> R<Digest> {
    Ok([r.base()?, r.base()?, r.base()?, r.base()?])
}
fn exts(w: &mut Writer, xs: &[Fp3]) {
    for &x in xs {
        w.ext(x);
    }
}
fn read_exts(r: &mut Reader<'_>, k: usize) -> R<Vec<Fp3>> {
    (0..k).map(|_| r.ext()).collect()
}
fn bases(w: &mut Writer, xs: &[Goldilocks]) {
    for &x in xs {
        w.base(x);
    }
}
fn read_bases(r: &mut Reader<'_>, k: usize) -> R<Vec<Goldilocks>> {
    (0..k).map(|_| r.base()).collect()
}

fn state(w: &mut Writer, s: &State) {
    for (v, ext) in s.items() {
        if ext {
            w.ext(v);
        } else {
            w.base(v.c0);
        }
    }
}

fn read_state(r: &mut Reader<'_>, p: &Params) -> R<State> {
    let template = super::program::dummy_state(p);
    let mut vals = Vec::new();
    for (_, ext) in template.items() {
        vals.push(if ext { r.ext()? } else { Fp3::from_base(r.base()?) });
    }
    Ok(StateV::from_items(&p.dims, &vals))
}

/// Sibling digests of a multi-opening of sorted distinct `leaves` (lens
/// order: level by level, increasing index, only those not computable).
fn multi_siblings(paths: &[(usize, &LeafOpening)], depth: usize) -> Vec<Digest> {
    let mut out = Vec::new();
    let mut known: Vec<usize> = paths.iter().map(|p| p.0).collect();
    for level in 0..depth {
        let mut next = Vec::with_capacity(known.len());
        let mut i = 0;
        while i < known.len() {
            let idx = known[i];
            if i + 1 < known.len() && known[i + 1] == idx ^ 1 {
                i += 2;
            } else {
                // the sibling from any path through this node
                let leaf = paths.iter().find(|p| p.0 >> level == idx).expect("a path");
                out.push(leaf.1.path[level]);
                i += 1;
            }
            next.push(idx >> 1);
        }
        next.dedup();
        known = next;
    }
    out
}

fn acc_proof(w: &mut Writer, a: &AccProof, p: &Params) {
    exts(w, &a.sumcheck);
    exts(w, &a.evals);
    w.u64(a.comb_nonce);
    digest(w, &a.root);
    exts(w, &a.ood);
    w.u64(a.query_nonce);
    // leaf of each spot check
    let leaves: Vec<usize> = a.openings.iter().map(|q| leaf_index(&q[0], p)).collect();
    for &l in &leaves {
        w.u32(l);
    }
    let mut distinct = leaves.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let depth = p.cfg.layout.log_leaves() as usize;
    for word in 0..4 {
        let ops: Vec<(usize, &LeafOpening)> = distinct
            .iter()
            .map(|&l| (l, &a.openings[leaves.iter().position(|&x| x == l).expect("leaf")][word]))
            .collect();
        for (_, op) in &ops {
            if word == 0 {
                exts(w, &op.symbols);
            } else {
                bases(w, &op.symbols.iter().map(|s| s.c0).collect::<Vec<_>>());
            }
        }
        let sib = multi_siblings(&ops, depth);
        w.u32(sib.len());
        for d in &sib {
            digest(w, d);
        }
    }
}

/// The leaf an opening proves (from its path's direction is not stored:
/// the prover's openings are indexed by the transcript's positions, which
/// the writer recovers by recomputing the leaf position from the path).
fn leaf_index(op: &LeafOpening, _p: &Params) -> usize {
    op.leaf.expect("an opening knows its leaf")
}

fn read_acc(r: &mut Reader<'_>, p: &Params) -> R<AccProof> {
    let sumcheck = read_exts(r, 2 * p.vars)?;
    let evals = read_exts(r, 4)?;
    let comb_nonce = r.u64()?;
    let root = read_digest(r)?;
    let ood = read_exts(r, p.cfg.ood)?;
    let query_nonce = r.u64()?;
    let depth = p.cfg.layout.log_leaves() as usize;
    let count = 1usize << depth;
    let width = 1usize << p.cfg.layout.log_width;
    let leaves: Vec<usize> = (0..p.cfg.queries).map(|_| r.u32()).collect::<R<_>>()?;
    if leaves.iter().any(|&l| l >= count) {
        return Err(PcsError::Malformed);
    }
    let mut distinct = leaves.clone();
    distinct.sort_unstable();
    distinct.dedup();
    let mut per_word: Vec<Vec<LeafOpening>> = Vec::with_capacity(4);
    for word in 0..4 {
        let syms: Vec<Vec<Fp3>> = distinct
            .iter()
            .map(|_| if word == 0 { read_exts(r, width) } else { Ok(read_bases(r, width)?.into_iter().map(Fp3::from_base).collect()) })
            .collect::<R<_>>()?;
        let ns = r.count(32)?;
        let sib: Vec<Digest> = (0..ns).map(|_| read_digest(r)).collect::<R<_>>()?;
        per_word.push(expand(&distinct, syms, &sib, depth, word == 0)?);
    }
    let openings = leaves
        .iter()
        .map(|l| {
            let q = distinct.binary_search(l).expect("leaf");
            (0..4).map(|wd| per_word[wd][q].clone()).collect()
        })
        .collect();
    Ok(AccProof { sumcheck, evals, comb_nonce, root, ood, query_nonce, openings })
}

/// Full paths of a multi-opening (hashing the computable nodes).
fn expand(leaves: &[usize], syms: Vec<Vec<Fp3>>, sib: &[Digest], depth: usize, ext: bool) -> R<Vec<LeafOpening>> {
    let mut nodes: Vec<(usize, Digest)> = leaves.iter().zip(&syms).map(|(&l, s)| (l, leaf_digest(ext, s))).collect();
    let mut paths: Vec<Vec<Digest>> = vec![Vec::with_capacity(depth); leaves.len()];
    let mut it = sib.iter();
    for level in 0..depth {
        let mut next = Vec::with_capacity(nodes.len());
        let mut i = 0;
        while i < nodes.len() {
            let (idx, h) = nodes[i];
            let (l, r, step) = if i + 1 < nodes.len() && nodes[i + 1].0 == idx ^ 1 {
                (h, nodes[i + 1].1, 2)
            } else {
                let s = *it.next().ok_or(PcsError::Merkle)?;
                if idx & 1 == 0 { (h, s, 1) } else { (s, h, 1) }
            };
            // every leaf under this node gets the sibling of its ancestor
            let sib_of = |x: usize| if x & 1 == 0 { r } else { l };
            for (q, &leaf) in leaves.iter().enumerate() {
                let anc = leaf >> level;
                if anc == idx || (step == 2 && anc == idx ^ 1) {
                    paths[q].push(sib_of(anc));
                }
            }
            next.push((idx >> 1, perm::node_input(l, r)));
            i += step;
        }
        let mut states: Vec<[Goldilocks; 16]> = next.iter().map(|x| x.1).collect();
        perm::permute_many(&mut states);
        nodes = next.iter().zip(&states).map(|(x, s)| (x.0, perm::head(s))).collect();
    }
    if it.next().is_some() {
        return Err(PcsError::Merkle);
    }
    Ok(syms
        .into_iter()
        .zip(paths)
        .zip(leaves)
        .map(|((symbols, path), &l)| LeafOpening { symbols, path, leaf: Some(l) })
        .collect())
}

fn step(w: &mut Writer, s: &StepProof, p: &Params) {
    for d in &s.roots {
        digest(w, d);
    }
    for a in &s.ood {
        exts(w, a);
    }
    bases(w, &s.b_in);
    bases(w, &s.b_out);
    bases(w, &s.b_v);
    for m in &s.zerocheck {
        exts(w, m);
    }
    for v in [&s.local, &s.next, &s.pub_nox, &s.pub_v, &s.fold_g, &s.fold_pn, &s.fold_pv, &s.shift] {
        exts(w, v);
    }
    exts(w, &s.vals);
    acc_proof(w, &s.acc, p);
}

fn read_step(r: &mut Reader<'_>, p: &Params) -> R<StepProof> {
    let roots = [read_digest(r)?, read_digest(r)?, read_digest(r)?];
    let ood = [read_exts(r, p.fresh)?, read_exts(r, p.fresh)?, read_exts(r, p.fresh)?];
    let b_in = read_bases(r, W1 + W2)?;
    let b_out = read_bases(r, W1 + W2)?;
    let b_v = read_bases(r, BV)?;
    let zerocheck = (0..p.n).map(|_| read_exts(r, p.zc_deg())).collect::<R<_>>()?;
    let local = read_exts(r, COLS)?;
    let next = read_exts(r, COLS)?;
    let pub_nox = read_exts(r, PUB_NOX)?;
    let pub_v = read_exts(r, PUB_V)?;
    let fold_g = read_exts(r, p.g_deg - 1)?;
    let fold_pn = read_exts(r, p.pn_deg - 1)?;
    let fold_pv = read_exts(r, p.pv_deg - 1)?;
    let shift = read_exts(r, 2 * p.n)?;
    let v = read_exts(r, 3)?;
    let acc = read_acc(r, p)?;
    Ok(StepProof {
        roots,
        ood,
        b_in,
        b_out,
        b_v,
        zerocheck,
        local,
        next,
        pub_nox,
        pub_v,
        fold_g,
        fold_pn,
        fold_pv,
        shift,
        vals: [v[0], v[1], v[2]],
        acc,
    })
}

impl IvcProof {
    /// Bytes of each part: header, state, step (AIR part), accumulation
    /// step, decider.
    pub fn sizes(&self, p: &Params) -> [(&'static str, usize); 5] {
        let len = |f: &dyn Fn(&mut Writer)| {
            let mut w = Writer::default();
            f(&mut w);
            w.buf.len()
        };
        let all = len(&|w| step(w, &self.step, p));
        let acc = len(&|w| acc_proof(w, &self.step.acc, p));
        [
            ("header", 1 + 8 + 8 + 32),
            ("state", len(&|w| state(w, &self.state))),
            ("step", all - acc),
            ("accumulation", acc),
            ("decider", len(&|w| self.decider.write(w, true))),
        ]
    }

    pub fn to_bytes(&self, p: &Params) -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(self.log_rows as u8);
        w.u64(self.start);
        w.u64(self.segments);
        digest(&mut w, &self.chain);
        state(&mut w, &self.state);
        step(&mut w, &self.step, p);
        self.decider.write(&mut w, true);
        w.buf
    }

    /// Parse under the parameters the header names (`params(log_rows)`).
    pub fn from_bytes(bytes: &[u8], params: impl Fn(u32) -> Result<std::sync::Arc<super::ivc::Key>, String>) -> Result<Self, String> {
        let e = |e: PcsError| format!("recursive proof: {e}");
        let mut r = Reader::new(bytes);
        let log_rows = u32::from(r.u8().map_err(e)?);
        let key = params(log_rows)?;
        let p = &key.params;
        let start = r.u64().map_err(e)?;
        let segments = r.u64().map_err(e)?;
        let chain = read_digest(&mut r).map_err(e)?;
        let st = read_state(&mut r, p).map_err(e)?;
        let stp = read_step(&mut r, p).map_err(e)?;
        let (decider, ext) = DeciderProof::read(&mut r).map_err(e)?;
        r.finish().map_err(e)?;
        if !ext {
            return Err("recursive proof: decider of a base word".into());
        }
        Ok(Self { log_rows, start, segments, chain, state: st, step: stp, decider })
    }
}
