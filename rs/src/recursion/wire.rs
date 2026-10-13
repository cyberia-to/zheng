//! Canonical bytes of a recursive proof. Every shape is fixed by the
//! parameters, so nothing but the header carries a length: LE, canonical
//! Goldilocks limbs (8 B), Fp3 = three limbs, digests = four limbs.
//!
//! ```text
//! header   u8 log_rows · u64 start · u64 segments · digest chain
//! state    its items in hashing order
//! step     roots · OOD answers · boundary rows · zerocheck · columns at ρ
//!          · publics · line folds · shift · values · accumulation step
//! decider  the key claim's two values · the batched WHIR opening
//!          (`whir::wire`) of the accumulator and the key words
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
use super::word::{Arity, Digest, LeafOpening};
use super::decide::Decider;
use super::ivc::Key;
use crate::machine::layout::{W1, W2};

type R<T> = Result<T, PcsError>;

pub(crate) fn digest(w: &mut Writer, d: &Digest) {
    for &x in d {
        w.base(x);
    }
}
pub(crate) fn read_digest(r: &mut Reader<'_>) -> R<Digest> {
    Ok([r.base()?, r.base()?, r.base()?, r.base()?])
}
pub(crate) fn exts(w: &mut Writer, xs: &[Fp3]) {
    for &x in xs {
        w.ext(x);
    }
}
pub(crate) fn read_exts(r: &mut Reader<'_>, k: usize) -> R<Vec<Fp3>> {
    (0..k).map(|_| r.ext()).collect()
}
pub(crate) fn bases(w: &mut Writer, xs: &[Goldilocks]) {
    for &x in xs {
        w.base(x);
    }
}
pub(crate) fn read_bases(r: &mut Reader<'_>, k: usize) -> R<Vec<Goldilocks>> {
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

/// Sibling digests of a multi-opening of sorted distinct `leaves` in a
/// tree of `2^log_leaves` leaves and `arity` (level by level, increasing
/// index, only those not computable).
pub(crate) fn multi_siblings(paths: &[(usize, &LeafOpening)], log_leaves: usize, arity: Arity) -> Vec<Digest> {
    let mut out = Vec::new();
    let mut known: Vec<usize> = paths.iter().map(|p| p.0).collect();
    let (mut off, mut div) = (0, 1usize);
    for a in arity.levels(log_leaves) {
        let mut next = Vec::with_capacity(known.len());
        let mut i = 0;
        while i < known.len() {
            let base = known[i] / a * a;
            let mut present = Vec::new();
            while i < known.len() && known[i] / a * a == base {
                present.push(known[i]);
                i += 1;
            }
            // any path through this group: its siblings are the group's
            // other children in order
            let own = present[0];
            let path = paths.iter().find(|p| p.0 / div == own).expect("a path").1;
            for c in base..base + a {
                if !present.contains(&c) {
                    let rank = c - base - usize::from(c > own);
                    out.push(path.path[off + rank]);
                }
            }
            next.push(base / a);
        }
        known = next;
        off += a - 1;
        div *= a;
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
        let sib = multi_siblings(&ops, depth, Arity::Two);
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
        per_word.push(expand(&distinct, syms, &sib, depth, word == 0, Arity::Two)?);
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

/// A node group of one tree level: the parent at `base / a` and its
/// children, each a node of the level below (`Ok(k)`, the k-th) or a
/// sibling the opening carries (`Err(i)`, the i-th).
struct Group {
    kids: Vec<Result<usize, usize>>,
}

/// Full paths of a multi-opening (hashing the computable nodes). The
/// shape (which children are carried, which computed) is found first
/// without hashing; then every leaf's chain is hashed up to the first
/// node it shares with another leaf, chains split over the verifier's
/// threads, and the shared top of the tree level by level.
pub(crate) fn expand(leaves: &[usize], syms: Vec<Vec<Fp3>>, sib: &[Digest], log_leaves: usize, ext: bool, arity: Arity) -> R<Vec<LeafOpening>> {
    // leaf digests batched (every leaf of one opening has one width)
    let width = syms.first().map_or(0, |s| s.len());
    if syms.iter().any(|s| s.len() != width) {
        return Err(PcsError::Malformed);
    }
    let fans = arity.levels(log_leaves);
    // shape: per level, the groups and each node's parent group
    let mut levels: Vec<Vec<Group>> = Vec::with_capacity(fans.len());
    let mut parent: Vec<Vec<usize>> = Vec::with_capacity(fans.len());
    let mut pos: Vec<usize> = leaves.to_vec();
    let mut used = 0usize;
    for &a in &fans {
        let mut groups = Vec::new();
        let mut par = vec![0usize; pos.len()];
        let mut next = Vec::new();
        let mut i = 0;
        while i < pos.len() {
            let base = pos[i] / a * a;
            let mut kids: Vec<Result<usize, usize>> = Vec::with_capacity(a);
            for c in base..base + a {
                if i < pos.len() && pos[i] == c {
                    par[i] = groups.len();
                    kids.push(Ok(i));
                    i += 1;
                } else {
                    if used >= sib.len() {
                        return Err(PcsError::Merkle);
                    }
                    kids.push(Err(used));
                    used += 1;
                }
            }
            groups.push(Group { kids });
            next.push(base / a);
        }
        levels.push(groups);
        parent.push(par);
        pos = next;
    }
    if used != sib.len() {
        return Err(PcsError::Merkle);
    }
    let input = |kids: &[Digest]| -> [Goldilocks; 16] {
        if kids.len() == 4 { perm::node4_input([kids[0], kids[1], kids[2], kids[3]]) } else { perm::node_input(kids[0], kids[1]) }
    };
    let solo = |g: &Group| g.kids.iter().filter(|k| k.is_ok()).count() == 1;
    // node digests per level (level 0: the leaves)
    let ld = super::word::hash_leaves_with(syms.len(), width, ext, |j, t| syms[j][t], true);
    let mut dig: Vec<Vec<Option<Digest>>> = Vec::with_capacity(fans.len() + 1);
    dig.push(ld.into_iter().map(Some).collect());
    for g in &levels {
        dig.push(vec![None; g.len()]);
    }
    // chains: each leaf up to the first group it shares, in parallel
    let chains = leaves.len();
    let threads = crate::recursion::wrap::verifier_threads().min(chains.div_ceil(3)).max(1);
    let done: Vec<Vec<(usize, usize, Digest)>> = crate::recursion::pool::map_chunks(chains, threads, |r| {
        let mut out = Vec::new();
        // (current level node, its digest) per chain still climbing
        let mut cur: Vec<(usize, Digest)> = r.map(|q| (q, dig[0][q].expect("leaf digest"))).collect();
        for (l, groups) in levels.iter().enumerate() {
            let mut ins = Vec::new();
            let mut gs = Vec::new();
            for &(k, d) in &cur {
                let g = parent[l][k];
                if !solo(&groups[g]) {
                    continue;
                }
                let kids: Vec<Digest> = groups[g].kids.iter().map(|c| match *c {
                    Ok(_) => d,
                    Err(i) => sib[i],
                }).collect();
                ins.push(input(&kids));
                gs.push(g);
            }
            if ins.is_empty() {
                break;
            }
            perm::permute_many_remember(&mut ins);
            cur = gs.iter().zip(&ins).map(|(&g, s)| (g, perm::head(s))).collect();
            for &(g, d) in &cur {
                out.push((l + 1, g, d));
            }
        }
        out
    });
    for (l, g, d) in done.into_iter().flatten() {
        dig[l][g] = Some(d);
    }
    // the shared top, level by level
    for (l, groups) in levels.iter().enumerate() {
        let todo: Vec<usize> = (0..groups.len()).filter(|&g| dig[l + 1][g].is_none()).collect();
        if todo.is_empty() {
            continue;
        }
        let mut ins: Vec<[Goldilocks; 16]> = Vec::with_capacity(todo.len());
        for &g in &todo {
            let kids: Vec<Digest> = groups[g]
                .kids
                .iter()
                .map(|c| match *c {
                    Ok(k) => dig[l][k].expect("a computed child"),
                    Err(i) => sib[i],
                })
                .collect();
            ins.push(input(&kids));
        }
        perm::permute_many_remember(&mut ins);
        for (&g, s) in todo.iter().zip(&ins) {
            dig[l + 1][g] = Some(perm::head(s));
        }
    }
    // paths: per level the siblings of each leaf's ancestor
    let mut paths: Vec<Vec<Digest>> = vec![Vec::with_capacity(arity.path_len(log_leaves)); chains];
    let mut anc: Vec<usize> = (0..chains).collect();
    for (l, groups) in levels.iter().enumerate() {
        for (q, a) in anc.iter_mut().enumerate() {
            let g = parent[l][*a];
            for c in &groups[g].kids {
                match *c {
                    Ok(k) if k == *a => {}
                    Ok(k) => paths[q].push(dig[l][k].expect("a computed node")),
                    Err(i) => paths[q].push(sib[i]),
                }
            }
            *a = g;
        }
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

fn decider_ext(k: &Key) -> [bool; 2] {
    [true, k.key_ext]
}

pub(crate) fn decider(w: &mut Writer, d: &Decider, k: &Key) {
    exts(w, &d.key);
    super::whir::wire::write(w, &k.dcfg, &decider_ext(k), &d.whir);
}

pub(crate) fn read_decider(r: &mut Reader<'_>, k: &Key) -> R<Decider> {
    let v = read_exts(r, 2)?;
    let whir = super::whir::wire::read(r, &k.dcfg, &decider_ext(k))?;
    Ok(Decider { key: [v[0], v[1]], whir })
}

impl IvcProof {
    /// Bytes of each part: header, state, step (AIR part), accumulation
    /// step, decider.
    pub fn sizes(&self, k: &Key) -> [(&'static str, usize); 5] {
        let p = &k.params;
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
            ("decider", len(&|w| decider(w, &self.decider, k))),
        ]
    }

    pub fn to_bytes(&self, k: &Key) -> Vec<u8> {
        let p = &k.params;
        let mut w = Writer::default();
        w.u8(self.log_rows as u8);
        w.u64(self.start);
        w.u64(self.segments);
        digest(&mut w, &self.chain);
        state(&mut w, &self.state);
        step(&mut w, &self.step, p);
        decider(&mut w, &self.decider, k);
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
        let decider = read_decider(&mut r, &key).map_err(e)?;
        r.finish().map_err(e)?;
        Ok(Self { log_rows, start, segments, chain, state: st, step: stp, decider })
    }
}
