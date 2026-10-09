//! Committed words of the recursion profile: the Reed–Solomon codeword of
//! WHIR's round-0 layout (lens `LeafLayout`: leaf `j` holds the folding
//! coset `{j + t·(n/W)}`), under a field-native hemera Merkle tree — a
//! leaf is the duplex sponge (tag `LEAF`) over its symbols, a node is
//! [`super::perm::node_state`]. The code, the domain and the distance are
//! lens's; only the hashing differs from a lens commitment, so the
//! accumulation analysis is unchanged and the recursion circuit can open a
//! word with permutations alone.

use lens::rspcs::field::{mobius_base, mobius_ext, univariate_base, univariate_ext};
use lens::rspcs::rs::{encode_base, encode_ext};
use lens::rspcs::whir::LeafLayout;
use nebu::{Fp3, Goldilocks};

use super::ops::Ops;
use super::perm::{self, RATE, WIDTH, tag};
use super::sponge::Sponge;

pub type Digest = [Goldilocks; 4];

enum Data {
    Base { evals: Vec<Goldilocks>, coeffs: Vec<Goldilocks>, code: Vec<Goldilocks> },
    Ext { evals: Vec<Fp3>, coeffs: Vec<Fp3>, code: Vec<Fp3> },
    /// A word committed from its coefficients alone (a WHIR round's
    /// folded function): no evaluation table.
    Coeffs { coeffs: Vec<Fp3>, code: Vec<Fp3> },
}

/// A committed word: message, codeword and tree.
pub struct Word {
    pub num_vars: usize,
    pub layout: LeafLayout,
    data: Data,
    /// `levels[0]` = leaf digests, last = `[root]`.
    levels: Vec<Vec<Digest>>,
}

/// One opened leaf: its symbols and its sibling path (leaf level first).
/// `leaf` is the prover's note of the index (the encoding uses it; the
/// verifier derives positions from the transcript and ignores it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafOpening {
    pub symbols: Vec<Fp3>,
    pub path: Vec<Digest>,
    pub leaf: Option<usize>,
}

fn par_chunks<T: Send, F: Fn(usize, &mut [T]) + Sync>(v: &mut [T], f: F) {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16);
    let chunk = v.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        for (i, c) in v.chunks_mut(chunk).enumerate() {
            let f = &f;
            s.spawn(move || f(i * chunk, c));
        }
    });
}

/// Leaf digests of `leaves` leaves of `width` symbols each (`ext`: Fp3
/// symbols), `symbol(j, t)` the `t`-th symbol of leaf `j` — the sponge of
/// [`leaf_digest`], batched.
fn leaf_digests(leaves: usize, width: usize, ext: bool, symbol: impl Fn(usize, usize) -> Fp3 + Sync) -> Vec<Digest> {
    let lanes: Vec<usize> = if ext { vec![3; width] } else { vec![1; width] };
    // block boundaries: items never straddle the rate
    let mut blocks: Vec<Vec<usize>> = vec![vec![]];
    let mut used = 0;
    for (t, &w) in lanes.iter().enumerate() {
        if used + w > RATE {
            blocks.push(vec![]);
            used = 0;
        }
        blocks.last_mut().expect("block").push(t);
        used += w;
        if used == RATE && t + 1 < width {
            blocks.push(vec![]);
            used = 0;
        }
    }
    let mut out = vec![[Goldilocks::ZERO; 4]; leaves];
    par_chunks(&mut out, |start, chunk| {
        let mut states: Vec<[Goldilocks; WIDTH]> = (0..chunk.len())
            .map(|_| {
                let mut s = [Goldilocks::ZERO; WIDTH];
                s[RATE] = Goldilocks::new(tag::LEAF);
                s
            })
            .collect();
        for blk in &blocks {
            for (k, s) in states.iter_mut().enumerate() {
                let j = start + k;
                let mut lane = 0;
                for &t in blk {
                    let v = symbol(j, t);
                    if ext {
                        s[lane] = v.c0;
                        s[lane + 1] = v.c1;
                        s[lane + 2] = v.c2;
                        lane += 3;
                    } else {
                        s[lane] = v.c0;
                        lane += 1;
                    }
                }
                for x in s.iter_mut().take(RATE).skip(lane) {
                    *x = Goldilocks::ZERO;
                }
            }
            perm::permute_many(&mut states);
        }
        for (o, s) in chunk.iter_mut().zip(&states) {
            *o = perm::head(s);
        }
    });
    out
}

fn parents(level: &[Digest]) -> Vec<Digest> {
    let mut out = vec![[Goldilocks::ZERO; 4]; level.len() / 2];
    par_chunks(&mut out, |start, chunk| {
        let mut states: Vec<[Goldilocks; WIDTH]> = (0..chunk.len())
            .map(|k| perm::node_input(level[2 * (start + k)], level[2 * (start + k) + 1]))
            .collect();
        perm::permute_many(&mut states);
        for (o, s) in chunk.iter_mut().zip(&states) {
            *o = perm::head(s);
        }
    });
    out
}

impl Word {
    fn build(num_vars: usize, layout: LeafLayout, data: Data) -> Self {
        let leaves = 1usize << layout.log_leaves();
        let width = 1usize << layout.log_width;
        let digests = match &data {
            Data::Base { code, .. } => {
                leaf_digests(leaves, width, false, |j, t| Fp3::from_base(code[j + t * leaves]))
            }
            Data::Ext { code, .. } | Data::Coeffs { code, .. } => {
                leaf_digests(leaves, width, true, |j, t| code[j + t * leaves])
            }
        };
        let mut levels = vec![digests];
        while levels.last().expect("level").len() > 1 {
            let next = parents(levels.last().expect("level"));
            levels.push(next);
        }
        Self { num_vars, layout, data, levels }
    }

    /// Commit a Goldilocks table of `2^ℓ` entries under `layout`.
    /// A base word without its own tree (a member of a [`Group`]).
    pub fn member_base(layout: LeafLayout, evals: &[Goldilocks]) -> Self {
        let num_vars = evals.len().trailing_zeros() as usize;
        assert!(evals.len().is_power_of_two() && layout.log_domain as usize > num_vars);
        let mut coeffs = evals.to_vec();
        mobius_base(&mut coeffs);
        let code = encode_base(&coeffs, layout.log_domain);
        Self { num_vars, layout, data: Data::Base { evals: evals.to_vec(), coeffs, code }, levels: Vec::new() }
    }

    pub fn commit_base(layout: LeafLayout, evals: &[Goldilocks]) -> Self {
        let num_vars = evals.len().trailing_zeros() as usize;
        assert!(evals.len().is_power_of_two() && layout.log_domain as usize > num_vars);
        let mut coeffs = evals.to_vec();
        mobius_base(&mut coeffs);
        let code = encode_base(&coeffs, layout.log_domain);
        Self::build(num_vars, layout, Data::Base { evals: evals.to_vec(), coeffs, code })
    }

    /// Commit an Fp3 table.
    pub fn commit_ext(layout: LeafLayout, evals: &[Fp3]) -> Self {
        let num_vars = evals.len().trailing_zeros() as usize;
        assert!(evals.len().is_power_of_two() && layout.log_domain as usize > num_vars);
        let mut coeffs = evals.to_vec();
        mobius_ext(&mut coeffs);
        let code = encode_ext(&coeffs, layout.log_domain);
        Self::build(num_vars, layout, Data::Ext { evals: evals.to_vec(), coeffs, code })
    }

    /// Commit an Fp3 polynomial given by its `2^ℓ` monomial coefficients.
    pub fn commit_coeffs(layout: LeafLayout, coeffs: Vec<Fp3>) -> Self {
        let num_vars = coeffs.len().trailing_zeros() as usize;
        assert!(coeffs.len().is_power_of_two() && layout.log_domain as usize > num_vars);
        let code = encode_ext(&coeffs, layout.log_domain);
        Self::build(num_vars, layout, Data::Coeffs { coeffs, code })
    }

    /// The monomial coefficients, lifted to Fp3.
    pub fn coeffs(&self) -> Vec<Fp3> {
        match &self.data {
            Data::Base { coeffs, .. } => coeffs.iter().map(|&x| Fp3::from_base(x)).collect(),
            Data::Ext { coeffs, .. } | Data::Coeffs { coeffs, .. } => coeffs.clone(),
        }
    }

    pub fn root(&self) -> Digest {
        self.levels.last().expect("root")[0]
    }
    pub fn is_ext(&self) -> bool {
        !matches!(self.data, Data::Base { .. })
    }
    /// The table, lifted to Fp3 (a word committed from coefficients has
    /// none: its table is computed from them).
    pub fn table(&self) -> Vec<Fp3> {
        match &self.data {
            Data::Base { evals, .. } => evals.iter().map(|&x| Fp3::from_base(x)).collect(),
            Data::Ext { evals, .. } => evals.clone(),
            Data::Coeffs { coeffs, .. } => {
                // zeta transform: f(b) = Σ_{S ⊆ b} c_S
                let mut t = coeffs.clone();
                let mut h = 1;
                while h < t.len() {
                    for i in 0..t.len() {
                        if i & h != 0 {
                            t[i] = t[i] + t[i ^ h];
                        }
                    }
                    h <<= 1;
                }
                t
            }
        }
    }
    /// `f̂(z)` (out-of-domain answers).
    pub fn univariate(&self, z: Fp3) -> Fp3 {
        match &self.data {
            Data::Base { coeffs, .. } => univariate_base(coeffs, z),
            Data::Ext { coeffs, .. } | Data::Coeffs { coeffs, .. } => univariate_ext(coeffs, z),
        }
    }
    /// Codeword symbol `s`.
    pub fn symbol(&self, s: usize) -> Fp3 {
        match &self.data {
            Data::Base { code, .. } => Fp3::from_base(code[s]),
            Data::Ext { code, .. } | Data::Coeffs { code, .. } => code[s],
        }
    }
    /// Leaf `j`: its symbols in coset order and its sibling path.
    pub fn open(&self, j: usize) -> LeafOpening {
        let leaves = 1usize << self.layout.log_leaves();
        let width = 1usize << self.layout.log_width;
        let symbols = (0..width).map(|t| self.symbol(j + t * leaves)).collect();
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        let mut idx = j;
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[idx ^ 1]);
            idx >>= 1;
        }
        LeafOpening { symbols, path, leaf: Some(j) }
    }
}

/// Words committed under one tree: leaf `j` is the leaf sponge over every
/// member's symbols of leaf `j` in member order (one path opens them all).
pub struct Group {
    pub words: Vec<Word>,
    pub layout: LeafLayout,
    levels: Vec<Vec<Digest>>,
}

impl Group {
    /// Members of one layout and one symbol field (built with
    /// [`Word::member_base`] or committed alone; their own trees unused).
    pub fn new(words: Vec<Word>) -> Self {
        let layout = words[0].layout;
        let ext = words[0].is_ext();
        assert!(words.iter().all(|w| w.layout == layout && w.is_ext() == ext), "group members");
        let leaves = 1usize << layout.log_leaves();
        let width = 1usize << layout.log_width;
        let m = words.len();
        let digests = leaf_digests(leaves, width * m, ext, |j, t| words[t / width].symbol(j + (t % width) * leaves));
        let mut levels = vec![digests];
        while levels.last().expect("level").len() > 1 {
            let next = parents(levels.last().expect("level"));
            levels.push(next);
        }
        Self { words, layout, levels }
    }
    pub fn root(&self) -> Digest {
        self.levels.last().expect("root")[0]
    }
    /// Leaf `j` of every member (concatenated) and the group's path.
    pub fn open(&self, j: usize) -> LeafOpening {
        let leaves = 1usize << self.layout.log_leaves();
        let width = 1usize << self.layout.log_width;
        let symbols = self.words.iter().flat_map(|w| (0..width).map(move |t| w.symbol(j + t * leaves))).collect();
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        let mut idx = j;
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[idx ^ 1]);
            idx >>= 1;
        }
        LeafOpening { symbols, path, leaf: Some(j) }
    }
}

/// The digest of a leaf, generically: the leaf sponge over its symbols
/// (written: the prover supplies them), then `path` nodes up to `root`.
/// Returns the symbol variables.
#[allow(clippy::too_many_arguments)]
pub fn verify_leaf<O: Ops>(
    o: &mut O,
    ext: bool,
    opening: &LeafOpening,
    bits: &[O::V],
    root: [O::V; 4],
    what: &'static str,
) -> Vec<O::V> {
    assert_eq!(bits.len(), opening.path.len(), "path length");
    let mut sp = Sponge::new(o, tag::LEAF);
    let syms: Vec<O::V> = opening
        .symbols
        .iter()
        .map(|&x| if ext { sp.absorb_free_ext(o, x) } else { sp.absorb_free(o, x.c0) })
        .collect();
    if sp.has_pending() {
        sp.flush(o);
    }
    let mut chain = sp.chain;
    for (&b, &sib) in bits.iter().zip(&opening.path) {
        o.node(&mut chain, b, sib);
    }
    o.digest_eq(&chain, root, what);
    syms
}

/// The leaf digest natively (tests and the prover's checks).
pub fn leaf_digest(ext: bool, symbols: &[Fp3]) -> Digest {
    let mut o = super::ops::Native::new();
    let mut sp = Sponge::new(&mut o, tag::LEAF);
    for &x in symbols {
        if ext {
            sp.absorb_free_ext(&mut o, x);
        } else {
            sp.absorb_free(&mut o, x.c0);
        }
    }
    if sp.has_pending() {
        sp.flush(&mut o);
    }
    let s: Vec<Fp3> = (0..4).map(|i| o.out_base(&sp.chain, i)).collect();
    [s[0].c0, s[1].c0, s[2].c0, s[3].c0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::ops::{Native, Ops};
    use lens::rspcs::field::ml_eval_ext;

    fn layout(num_vars: usize) -> LeafLayout {
        LeafLayout { log_domain: num_vars as u32 + 2, log_width: 2 }
    }

    #[test]
    fn words_open_and_verify_generically() {
        for ext in [false, true] {
            let n = 6;
            let evals: Vec<Fp3> = (0..1u64 << n)
                .map(|i| {
                    if ext {
                        Fp3::new(Goldilocks::new(i), Goldilocks::new(i * 3 + 1), Goldilocks::new(7))
                    } else {
                        Fp3::from_base(Goldilocks::new(i * i + 5))
                    }
                })
                .collect();
            let w = if ext {
                Word::commit_ext(layout(n), &evals)
            } else {
                Word::commit_base(layout(n), &evals.iter().map(|x| x.c0).collect::<Vec<_>>())
            };
            // the RS word encodes the message: f̂(ω^s) = f(pow(ω^s))
            let s = 13;
            let x = Fp3::from_base(w.layout.point(s));
            assert_eq!(w.symbol(s), w.univariate(x));
            let z: Vec<Fp3> = lens::rspcs::field::pow_point(x, n);
            assert_eq!(ml_eval_ext(&w.table(), &z), w.symbol(s));
            let leaves = 1usize << w.layout.log_leaves();
            for j in [0, 5, leaves - 1] {
                let op = w.open(j);
                assert_eq!(leaf_digest(ext, &op.symbols), w.levels[0][j]);
                let mut o = Native::new();
                let bits: Vec<Fp3> = (0..op.path.len())
                    .map(|k| Fp3::from_base(Goldilocks::new(((j >> k) & 1) as u64)))
                    .collect();
                let root = w.root().map(Fp3::from_base);
                verify_leaf(&mut o, ext, &op, &bits, root, "root");
                assert!(o.error.is_none(), "leaf {j}");
                // a wrong symbol, a wrong index, a wrong sibling fail
                let mut bad = op.clone();
                bad.symbols[1] += Fp3::ONE;
                let mut o = Native::new();
                verify_leaf(&mut o, ext, &bad, &bits, root, "root");
                assert!(o.error.is_some());
                let mut o = Native::new();
                let mut flipped = bits.clone();
                flipped[0] = Fp3::ONE - flipped[0];
                verify_leaf(&mut o, ext, &op, &flipped, root, "root");
                assert!(o.error.is_some());
                let mut bad = op.clone();
                bad.path[2][1] += Goldilocks::ONE;
                let mut o = Native::new();
                verify_leaf(&mut o, ext, &bad, &bits, root, "root");
                assert!(o.error.is_some());
                let _ = o.value(Fp3::ZERO);
            }
        }
    }
}
