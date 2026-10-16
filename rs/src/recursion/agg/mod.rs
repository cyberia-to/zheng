//! Block aggregation: one proof per block (`specs/aggregation.md`).
//!
//! A block of `N` transactions, each with a field-native zk proof
//! (`execution::veil::rec`) of one relation, is proved by a binary tree of
//! wrap proofs of fixed depth `D` (`N ≤ 2^D`):
//!
//! ```text
//! level 0      one leaf a transaction: veil-r verified in the circuit,
//!              X = H_TX(vk ‖ pins)
//! level 1..D   one node a pair: both children verified,
//!              X = H_NODE(X_l ‖ X_r ‖ h) (h = 0: a lone child, X_r = X_l)
//! top          the root verified, X = H_BLOCK(X_root ‖ N ‖ fields)
//! final        the top verified, X = H_PASS(X_block) — the block proof
//! ```
//!
//! Levels 0..D are inner wrap levels at rate 1/16 (`4i:16`), the top an
//! inner level at 1/128 (`7i:22`), the final level a final-mode level at
//! 1/512 (`9f:26`) — profile 6's chain (`wrap::SHIPPED`) after the tree.
//! A node at level `j` embeds level `j − 1`'s key root, so every level has
//! its own key; the final key's proofs are bounded by
//! [`wrap::wire::max_bytes`] ≤ 64 KiB.
//!
//! The block verifier recomputes `X` natively from the statement — the
//! verifying key's digest, every transaction's pins in order, `N`, the
//! block's fields — and verifies the final proof against it. It never
//! reads a transaction proof.

pub mod program;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use nebu::{Fp3, Goldilocks};

use crate::execution::veil::rec::{RecKey, RecProof};
use crate::recursion::circuit::builder::Builder;
use crate::recursion::ops::Native;
use crate::recursion::word::Digest;
use crate::recursion::wrap::{self, Mode, WrapKey, WrapParams, WrapProof};
use program::Child;

/// The aggregation chain's levels: the tree's, the top's, the final's.
pub fn chain_params() -> [WrapParams; 3] {
    let (_, levels) = crate::envelope::wrapped::chain();
    levels
}

/// Every key of one aggregation chain.
pub struct AggKeys {
    pub veil: Arc<RecKey>,
    pub depth: usize,
    /// `levels[0]` the leaves', `levels[j]` the nodes' of tree level `j`.
    pub levels: Vec<WrapKey>,
    pub top: WrapKey,
    pub last: WrapKey,
}

fn key_with(params: WrapParams, program: impl FnOnce(&mut Builder)) -> Result<WrapKey, String> {
    // no recursive proof under the chain: its leaf level's parameters
    // stand in the field a wrap key records for it
    wrap::derive_key_with(params, (params.whir, 15), 0, None, program)
}

fn timer(what: &str) -> impl Fn(&str) + '_ {
    let t = std::time::Instant::now();
    move |s: &str| {
        if std::env::var_os("ZHENG_TIMING").is_some() {
            eprintln!("  agg {what} {s}: {:.2} s", t.elapsed().as_secs_f64());
        }
    }
}

impl AggKeys {
    /// Derive the chain for blocks of up to `2^depth` transactions of
    /// `veil`'s relation.
    pub fn derive(veil: Arc<RecKey>, depth: usize) -> Result<Self, String> {
        let [tree, top_p, last_p] = chain_params();
        let lap = timer("keys");
        let zero = [Goldilocks::ZERO; 4];
        let pins = vec![Goldilocks::ZERO; veil.pins()];
        let dummy = RecProof::dummy(&veil);
        let leaf = key_with(tree, |b| {
            let (_, c) = program::leaf(b, &veil, &pins, &dummy);
            b.set_output(&c);
        })?;
        lap(&format!("leaf 2^{} ({} rows)", leaf.params.n, leaf.rows));
        let mut levels = vec![leaf];
        for j in 1..=depth {
            let below = levels.last().expect("a level");
            let d = wrap::dummy_proof(below);
            let child = Child { proof: &d, x: zero };
            let k = key_with(tree, |b| {
                let (_, c) = program::node(b, below, &child, Some(&child));
                b.set_output(&c);
            })?;
            lap(&format!("node {j} 2^{} ({} rows)", k.params.n, k.rows));
            levels.push(k);
        }
        let root = levels.last().expect("a level");
        let d = wrap::dummy_proof(root);
        let top = key_with(top_p, |b| {
            let (_, c) = program::top(b, root, &Child { proof: &d, x: zero }, 0, &zero);
            b.set_output(&c);
        })?;
        lap(&format!("top 2^{} ({} rows)", top.params.n, top.rows));
        let d = wrap::dummy_proof(&top);
        let last = key_with(last_p, |b| {
            let (_, c) = program::last(b, &top, &Child { proof: &d, x: zero });
            b.set_output(&c);
        })?;
        lap(&format!("final 2^{} ({} rows)", last.params.n, last.rows));
        if last.params.mode != Mode::Final || wrap::wire::max_bytes(&last) > wrap::MAX_FINAL_BYTES {
            return Err(format!("agg: the final key's proofs exceed {} B", wrap::MAX_FINAL_BYTES));
        }
        Ok(Self { veil, depth, levels, top, last })
    }

    /// The most bytes a block proof takes, over every transcript.
    pub fn max_proof_bytes(&self) -> usize {
        wrap::wire::max_bytes(&self.last)
    }
}

/// A block's public statement: every transaction's pins in order and the
/// block's own fields (chain, height, parent — four limbs the caller
/// derives).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockStatement {
    pub txs: Vec<Vec<Goldilocks>>,
    pub fields: Digest,
}

fn native<T>(f: impl FnOnce(&mut Native) -> T) -> T {
    let mut o = Native::new();
    let t = f(&mut o);
    o.finish().expect("digest arithmetic has no checks to fail");
    t
}

fn base(x: [Fp3; 4]) -> Digest {
    x.map(|v| v.c0)
}

/// The tree's digests, natively: per level, per node.
fn tree_digests(keys: &AggKeys, st: &BlockStatement) -> Vec<Vec<Digest>> {
    let mut level: Vec<Digest> = st.txs.iter().map(|p| native(|o| base(program::tx_digest(o, &keys.veil.vk_digest, p).0.0))).collect();
    let mut all = vec![level.clone()];
    for _ in 0..keys.depth {
        level = level
            .chunks(2)
            .map(|c| {
                let r = c.get(1).unwrap_or(&c[0]);
                native(|o| base(program::node_digest(o, &c[0], r, c.len() == 2).0.0))
            })
            .collect();
        all.push(level.clone());
    }
    all
}

/// The public input of a block proof: `H_PASS(H_BLOCK(root ‖ N ‖ fields))`.
pub fn public_input(keys: &AggKeys, st: &BlockStatement) -> Result<Digest, String> {
    let n = st.txs.len();
    if n == 0 || n > 1 << keys.depth {
        return Err(format!("agg: {n} transactions, the chain takes 1..={}", 1usize << keys.depth));
    }
    if st.txs.iter().any(|p| p.len() != keys.veil.pins()) {
        return Err("agg: a transaction's pin count".into());
    }
    let root = tree_digests(keys, st).last().expect("root")[0];
    let block = native(|o| base(program::block_digest(o, &root, n as u64, &st.fields).0.0));
    Ok(native(|o| base(program::pass_digest(o, &block).0.0)))
}

/// Verify a block proof natively (never the transactions' proofs).
pub fn verify(keys: &AggKeys, st: &BlockStatement, proof: &WrapProof) -> Result<(), String> {
    let x = public_input(keys, st)?;
    wrap::check_shape(&keys.last, proof)?;
    wrap::verify_native(&keys.last, x, proof)
}

/// Prover timings, seconds: leaves, each tree level, top, final.
#[derive(Clone, Debug, Default)]
pub struct Timings {
    pub leaves: Vec<f64>,
    pub levels: Vec<f64>,
    pub top: f64,
    pub last: f64,
}

/// Prove a block: every transaction proof is checked natively first (an
/// invalid one is refused before any proving), then the tree, the top and
/// the final level.
pub fn prove(keys: &AggKeys, st: &BlockStatement, proofs: &[RecProof]) -> Result<(WrapProof, Timings), String> {
    public_input(keys, st)?;
    if proofs.len() != st.txs.len() {
        return Err("agg: one proof a transaction".into());
    }
    for (i, (p, pf)) in st.txs.iter().zip(proofs).enumerate() {
        crate::execution::veil::rec::verify_pins(&keys.veil, p, pf).map_err(|e| format!("agg: transaction {i}: {e}"))?;
    }
    let digests = tree_digests(keys, st);
    let mut tm = Timings::default();
    let clock = std::time::Instant::now;
    let mut below: Vec<WrapProof> = Vec::with_capacity(proofs.len());
    for (i, (p, pf)) in st.txs.iter().zip(proofs).enumerate() {
        let t = clock();
        let (w, x) = wrap::prove_with(&keys.levels[0], |b| {
            let (x, c) = program::leaf(b, &keys.veil, p, pf);
            b.set_output(&c);
            x
        })?;
        debug_assert_eq!(x, digests[0][i]);
        below.push(w);
        tm.leaves.push(t.elapsed().as_secs_f64());
    }
    for j in 1..=keys.depth {
        let t = clock();
        let k = &keys.levels[j];
        let mut next = Vec::with_capacity(below.len().div_ceil(2));
        for (i, pair) in below.chunks(2).enumerate() {
            let l = Child { proof: &pair[0], x: digests[j - 1][2 * i] };
            let r = pair.get(1).map(|p| Child { proof: p, x: digests[j - 1][2 * i + 1] });
            let (w, x) = wrap::prove_with(k, |b| {
                let (x, c) = program::node(b, &keys.levels[j - 1], &l, r.as_ref());
                b.set_output(&c);
                x
            })?;
            debug_assert_eq!(x, digests[j][i]);
            next.push(w);
        }
        below = next;
        tm.levels.push(t.elapsed().as_secs_f64());
    }
    let root = Child { proof: &below[0], x: digests[keys.depth][0] };
    let t = clock();
    let (top, xb) = wrap::prove_with(&keys.top, |b| {
        let (x, c) = program::top(b, &keys.levels[keys.depth], &root, st.txs.len() as u64, &st.fields);
        b.set_output(&c);
        x
    })?;
    tm.top = t.elapsed().as_secs_f64();
    let t = clock();
    let (last, _) = wrap::prove_with(&keys.last, |b| {
        let (x, c) = program::last(b, &keys.top, &Child { proof: &top, x: xb });
        b.set_output(&c);
        x
    })?;
    tm.last = t.elapsed().as_secs_f64();
    Ok((last, tm))
}
