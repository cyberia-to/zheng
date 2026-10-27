//! The aggregation programs, written once over [`Ops`]: the circuit of
//! each aggregation level runs one of them (`Builder`), the native block
//! verifier recomputes their digests (`Native`).
//!
//! ```text
//! leaf   X = H_TX(vk ‖ pins); veil-r verifies the transaction proof
//!        against those pins
//! node   X = H_NODE(X_l ‖ X_r ‖ h), h a bit, h = 0 ⇒ X_r = X_l; both
//!        children verified under their digests
//! top    X = H_BLOCK(X_root ‖ N ‖ fields); the root verified
//! final  X = H_PASS(X_block); the top verified
//! ```
//!
//! Every digest is four output limbs of the chain's last block, the
//! public-input row of the level's circuit.

use nebu::{Fp3, Goldilocks};

use crate::execution::veil::rec::{self, RecKey, RecProof};
use crate::recursion::ops::{Arith, Gate, Ops};
use crate::recursion::perm::tag;
use crate::recursion::sponge::Sponge;
use crate::recursion::word::Digest;
use crate::recursion::wrap::{self, WrapKey, WrapProof};

/// A digest output by a chain: its four limbs and the chain.
pub type Out<O> = ([<O as Ops>::V; 4], <O as Ops>::Chain);

fn squeeze4<O: Ops>(o: &mut O, sp: &mut Sponge<O>) -> [O::V; 4] {
    core::array::from_fn(|_| sp.squeeze(o))
}

fn absorb4<O: Ops>(o: &mut O, sp: &mut Sponge<O>, d: &Digest) -> [O::V; 4] {
    core::array::from_fn(|i| sp.absorb_free(o, d[i]))
}

/// `H_TX(vk ‖ pins)`; returns the digest, its chain and the pins as
/// base values (each allocated once, by this sponge).
pub fn tx_digest<O: Ops>(o: &mut O, vk: &Digest, pins: &[Goldilocks]) -> (Out<O>, Vec<O::V>) {
    let mut sp = Sponge::new(o, tag::AGG_TX);
    for &l in vk {
        let c = o.constant(Fp3::from_base(l));
        sp.absorb(o, c);
    }
    let pv: Vec<O::V> = pins.iter().map(|&p| sp.absorb_free(o, p)).collect();
    let x = squeeze4(o, &mut sp);
    ((x, sp.chain), pv)
}

/// `H_NODE(X_l ‖ X_r ‖ h)` with `h` a bit and `h = 0 ⇒ X_r = X_l`;
/// returns the digest and the children's digests.
pub fn node_digest<O: Ops>(o: &mut O, xl: &Digest, xr: &Digest, has_right: bool) -> (Out<O>, [O::V; 4], [O::V; 4]) {
    let mut sp = Sponge::new(o, tag::AGG_NODE);
    let l = absorb4(o, &mut sp, xl);
    let r = absorb4(o, &mut sp, xr);
    let h = sp.absorb_free(o, Goldilocks::new(u64::from(has_right)));
    let x = squeeze4(o, &mut sp);
    // h² − h = 0
    o.assert_gate(Gate { qm: Fp3::ONE, qa: -Fp3::ONE, ..Gate::default() }, h, h, h, "agg: the right-child flag is a bit");
    for i in 0..4 {
        // (1 − h)·(X_r − X_l) = 0
        let d = o.sub(r[i], l[i]);
        o.assert_gate(Gate { qm: -Fp3::ONE, qa: Fp3::ONE, ..Gate::default() }, d, h, h, "agg: a lone child is its own sibling");
    }
    ((x, sp.chain), l, r)
}

/// `H_BLOCK(X_root ‖ N ‖ fields)`; returns the digest and the root's.
pub fn block_digest<O: Ops>(o: &mut O, root: &Digest, n: u64, fields: &Digest) -> (Out<O>, [O::V; 4]) {
    let mut sp = Sponge::new(o, tag::AGG_BLOCK);
    let r = absorb4(o, &mut sp, root);
    sp.absorb_free(o, Goldilocks::new(n));
    absorb4(o, &mut sp, fields);
    let x = squeeze4(o, &mut sp);
    ((x, sp.chain), r)
}

/// `H_PASS(X_block)`; returns the digest and the block's.
pub fn pass_digest<O: Ops>(o: &mut O, block: &Digest) -> (Out<O>, [O::V; 4]) {
    let mut sp = Sponge::new(o, tag::AGG_PASS);
    let b = absorb4(o, &mut sp, block);
    let x = squeeze4(o, &mut sp);
    ((x, sp.chain), b)
}

/// The leaf: one transaction proof verified against its pins.
pub fn leaf<O: Ops>(o: &mut O, key: &RecKey, pins: &[Goldilocks], pf: &RecProof) -> Out<O> {
    let (out, pv) = tx_digest(o, &key.vk_digest, pins);
    rec::verify::verify(o, key, &pv, pf);
    out
}

/// A child: its wrap proof and the digest it was proved under.
pub struct Child<'a> {
    pub proof: &'a WrapProof,
    pub x: Digest,
}

/// A node: two children of the level below (`right = None`: the left
/// child alone, verified twice).
pub fn node<O: Ops>(o: &mut O, child: &WrapKey, left: &Child<'_>, right: Option<&Child<'_>>) -> Out<O> {
    let r = right.unwrap_or(left);
    let (out, l, rv) = node_digest(o, &left.x, &r.x, right.is_some());
    wrap::verify(o, child, l, left.proof);
    wrap::verify(o, child, rv, r.proof);
    out
}

/// The top level: the root verified, the block digest output.
pub fn top<O: Ops>(o: &mut O, root_key: &WrapKey, root: &Child<'_>, n: u64, fields: &Digest) -> Out<O> {
    let (out, r) = block_digest(o, &root.x, n, fields);
    wrap::verify(o, root_key, r, root.proof);
    out
}

/// The final level: the top verified, its digest passed on.
pub fn last<O: Ops>(o: &mut O, top_key: &WrapKey, top: &Child<'_>) -> Out<O> {
    let (out, b) = pass_digest(o, &top.x);
    wrap::verify(o, top_key, b, top.proof);
    out
}
