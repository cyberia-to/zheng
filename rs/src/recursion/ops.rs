//! The operations a verifier is written in, once, for two interpreters:
//! [`Native`] computes values and records the first failed check (the
//! final verifier, the prover's own transcript); the recursion circuit
//! ([`super::circuit::Builder`]) records the same operations as rows of
//! the verifier AIR and keeps their values as its witness.
//!
//! Every value is an Fp3 element (base values have zero extension
//! coefficients). Arithmetic is one Plonk-style gate
//! `out = qm·x·(y + qs·z) + qa·x + qb·y + qc·z + qk` with Fp3 selectors;
//! hashing is hemera's permutation in *chains* (a duplex sponge, a leaf
//! sponge followed by Merkle nodes); bits are canonical 64-bit
//! decompositions.

use nebu::{Fp3, Goldilocks};

use super::perm::{self, NODE_TAG, RATE, WIDTH};

/// `out = qm·x·(y + qs·z) + qa·x + qb·y + qc·z + qk`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gate {
    pub qm: Fp3,
    pub qs: Fp3,
    pub qa: Fp3,
    pub qb: Fp3,
    pub qc: Fp3,
    pub qk: Fp3,
}

impl Gate {
    pub fn eval(&self, x: Fp3, y: Fp3, z: Fp3) -> Fp3 {
        self.qm * x * (y + self.qs * z) + self.qa * x + self.qb * y + self.qc * z + self.qk
    }
}

/// One item of a permutation's rate lanes.
#[derive(Clone, Copy, Debug)]
pub enum In<V> {
    /// A value already computed (read): one lane, or three for an Fp3.
    Var(V, bool),
    /// A fresh witness value ([`Ops::alloc`]) the block writes: one lane,
    /// or three for an Fp3.
    Free(V, bool),
    /// The lane is zero.
    Zero,
    /// The lane keeps the previous output (zero on a chain's first block).
    Keep,
}

impl<V> In<V> {
    pub fn width(&self) -> usize {
        match self {
            In::Var(_, true) | In::Free(_, true) => 3,
            _ => 1,
        }
    }
}

/// An interpreter of verifier operations.
pub trait Ops {
    type V: Copy + core::fmt::Debug;
    type Chain;

    fn value(&self, v: Self::V) -> Fp3;
    fn gate(&mut self, g: Gate, x: Self::V, y: Self::V, z: Self::V) -> Self::V;
    /// The gate's output must be zero.
    fn assert_gate(&mut self, g: Gate, x: Self::V, y: Self::V, z: Self::V, what: &'static str);
    /// A value the prover supplies (written by a gate).
    fn witness(&mut self, x: Fp3) -> Self::V;
    /// A value the prover supplies that a later permutation block writes
    /// (an `In::Free` item); every allocated value must be placed once.
    fn alloc(&mut self, x: Fp3) -> Self::V;
    fn constant(&mut self, x: Fp3) -> Self::V;

    /// A new chain whose first block carries `tag` in capacity lane 0.
    fn chain(&mut self, tag: u64) -> Self::Chain;
    /// One permutation on the chain: rate lanes from `items` (widths
    /// summing to [`RATE`]; a three-lane item never straddles), capacity
    /// from the previous block (or the tag).
    fn permute(&mut self, c: &mut Self::Chain, items: &[In<Self::V>]);
    /// Output lane `lane` of the chain's last block, as a base value.
    fn out_base(&mut self, c: &Self::Chain, lane: usize) -> Self::V;
    /// Output lanes `lane..lane + 3` of the chain's last block, as an Fp3.
    fn out_ext(&mut self, c: &Self::Chain, lane: usize) -> Self::V;
    /// A Merkle node over the chain's last output (lanes 0..4) and a
    /// sibling: `bit = 0` puts the current digest left.
    fn node(&mut self, c: &mut Self::Chain, bit: Self::V, sibling: [Goldilocks; 4]);
    /// A 4-ary Merkle node: the chain's last output sits at position
    /// `bits[0] + 2·bits[1]`, the siblings fill the others in order.
    fn node4(&mut self, c: &mut Self::Chain, bits: [Self::V; 2], siblings: [[Goldilocks; 4]; 3]);
    /// The chain's last output (lanes 0..4) equals `root`.
    fn digest_eq(&mut self, c: &Self::Chain, root: [Self::V; 4], what: &'static str);
    /// The canonical 64-bit decomposition of a base value; returns its
    /// low `want` bits.
    fn bits(&mut self, v: Self::V, want: usize) -> Vec<Self::V>;
}

/// Native interpretation: values, and the first failed check.
#[derive(Default)]
pub struct Native {
    pub error: Option<String>,
    /// Defer leaf-and-path chains and hash them in batches at
    /// [`Native::finish`] (the final verifier); off, every permutation is
    /// computed at once.
    pub batch: bool,
    deferred: Vec<(Vec<NOp>, [Goldilocks; 4], &'static str)>,
}

/// A deferred chain operation: a block's rate lanes (`None` keeps) or a
/// Merkle node.
#[derive(Clone)]
enum NOp {
    Block([Option<Goldilocks>; RATE]),
    Node(bool, [Goldilocks; 4]),
    Node4(usize, [[Goldilocks; 4]; 3]),
}

/// A chain's state after its last block (`None` before the first).
#[derive(Clone)]
pub struct NChain {
    tag: u64,
    state: Option<[Goldilocks; WIDTH]>,
    ops: Option<Vec<NOp>>,
}

impl NChain {
    /// The permutation input a block of `items` would have (the prover's
    /// grinding; no checks).
    pub fn input(&self, items: &[In<Fp3>]) -> [Goldilocks; WIDTH] {
        let mut s = self.state.unwrap_or_else(|| {
            let mut s = [Goldilocks::ZERO; WIDTH];
            s[RATE] = Goldilocks::new(self.tag);
            s
        });
        let fresh = self.state.is_none();
        let mut lane = 0;
        for it in items {
            match *it {
                In::Var(v, ext) | In::Free(v, ext) => {
                    s[lane] = v.c0;
                    if ext {
                        s[lane + 1] = v.c1;
                        s[lane + 2] = v.c2;
                    }
                }
                In::Zero => s[lane] = Goldilocks::ZERO,
                In::Keep => {
                    if fresh {
                        s[lane] = Goldilocks::ZERO;
                    }
                }
            }
            lane += it.width();
        }
        s
    }
}

impl Native {
    pub fn new() -> Self {
        Self::default()
    }
    /// A native interpreter that batches Merkle openings.
    pub fn batched() -> Self {
        Self { batch: true, ..Self::default() }
    }
    fn fail(&mut self, what: &str) {
        if self.error.is_none() {
            self.error = Some(what.to_string());
        }
    }
    /// Hash the deferred openings; `Ok` when no check failed.
    pub fn finish(&mut self) -> Result<(), String> {
        let jobs = core::mem::take(&mut self.deferred);
        if self.error.is_none() && !jobs.is_empty() {
            let mut fresh = [Goldilocks::ZERO; WIDTH];
            fresh[RATE] = Goldilocks::new(super::perm::tag::LEAF);
            let mut states = vec![fresh; jobs.len()];
            let longest = jobs.iter().map(|j| j.0.len()).max().unwrap_or(0);
            for k in 0..longest {
                let idx: Vec<usize> = (0..jobs.len()).filter(|&q| k < jobs[q].0.len()).collect();
                let mut batch: Vec<[Goldilocks; WIDTH]> = idx
                    .iter()
                    .map(|&q| {
                        let prev = states[q];
                        match &jobs[q].0[k] {
                            NOp::Block(l) => {
                                let mut x = prev;
                                for (i, v) in l.iter().enumerate() {
                                    match v {
                                        Some(v) => x[i] = *v,
                                        None if k == 0 => x[i] = Goldilocks::ZERO,
                                        None => {}
                                    }
                                }
                                x
                            }
                            NOp::Node(right, sib) => {
                                let cur = [prev[0], prev[1], prev[2], prev[3]];
                                let (l, r) = if *right { (*sib, cur) } else { (cur, *sib) };
                                perm::node_input(l, r)
                            }
                            NOp::Node4(pos, sibs) => {
                                let cur = [prev[0], prev[1], prev[2], prev[3]];
                                perm::node4_input(perm::children4(cur, *pos, *sibs))
                            }
                        }
                    })
                    .collect();
                perm::permute_many(&mut batch);
                for (&q, s) in idx.iter().zip(batch) {
                    states[q] = s;
                }
            }
            for (s, j) in states.iter().zip(&jobs) {
                if [s[0], s[1], s[2], s[3]] != j.1 {
                    self.fail(j.2);
                    break;
                }
            }
        }
        match &self.error {
            None => Ok(()),
            Some(e) => Err(format!("recursion: {e}")),
        }
    }
}

fn base_of(x: Fp3) -> Option<Goldilocks> {
    (x.c1 == Goldilocks::ZERO && x.c2 == Goldilocks::ZERO).then_some(x.c0)
}

impl Ops for Native {
    type V = Fp3;
    type Chain = NChain;

    fn value(&self, v: Fp3) -> Fp3 {
        v
    }
    fn gate(&mut self, g: Gate, x: Fp3, y: Fp3, z: Fp3) -> Fp3 {
        g.eval(x, y, z)
    }
    fn assert_gate(&mut self, g: Gate, x: Fp3, y: Fp3, z: Fp3, what: &'static str) {
        if g.eval(x, y, z) != Fp3::ZERO {
            self.fail(what);
        }
    }
    fn witness(&mut self, x: Fp3) -> Fp3 {
        x
    }
    fn alloc(&mut self, x: Fp3) -> Fp3 {
        x
    }
    fn constant(&mut self, x: Fp3) -> Fp3 {
        x
    }
    fn chain(&mut self, tag: u64) -> NChain {
        let ops = (self.batch && tag == super::perm::tag::LEAF).then(Vec::new);
        NChain { tag, state: None, ops }
    }
    fn permute(&mut self, c: &mut NChain, items: &[In<Fp3>]) {
        if let Some(ops) = &mut c.ops {
            let mut l = [None; RATE];
            let mut lane = 0;
            for it in items {
                match *it {
                    In::Var(v, ext) | In::Free(v, ext) => {
                        if ext {
                            l[lane] = Some(v.c0);
                            l[lane + 1] = Some(v.c1);
                            l[lane + 2] = Some(v.c2);
                        } else {
                            if base_of(v).is_none() {
                                self.error.get_or_insert_with(|| "a base lane holds an extension value".into());
                            }
                            l[lane] = Some(v.c0);
                        }
                    }
                    In::Zero => l[lane] = Some(Goldilocks::ZERO),
                    In::Keep => {}
                }
                lane += it.width();
            }
            ops.push(NOp::Block(l));
            return;
        }
        let mut s = match c.state {
            Some(s) => s,
            None => {
                let mut s = [Goldilocks::ZERO; WIDTH];
                s[RATE] = Goldilocks::new(c.tag);
                s
            }
        };
        let fresh = c.state.is_none();
        let mut lane = 0;
        for it in items {
            let w = it.width();
            assert!(lane + w <= RATE, "permutation items straddle the rate");
            match *it {
                In::Var(v, ext) | In::Free(v, ext) => {
                    if ext {
                        s[lane] = v.c0;
                        s[lane + 1] = v.c1;
                        s[lane + 2] = v.c2;
                    } else {
                        match base_of(v) {
                            Some(b) => s[lane] = b,
                            None => {
                                self.fail("a base lane holds an extension value");
                                s[lane] = v.c0;
                            }
                        }
                    }
                }
                In::Zero => s[lane] = Goldilocks::ZERO,
                In::Keep => {
                    if fresh {
                        s[lane] = Goldilocks::ZERO;
                    }
                }
            }
            lane += w;
        }
        assert_eq!(lane, RATE, "permutation items cover the rate");
        // once a check failed the outcome is fixed: skip the hashing
        if self.error.is_none() {
            perm::permute(&mut s);
        }
        c.state = Some(s);
    }
    fn out_base(&mut self, c: &NChain, lane: usize) -> Fp3 {
        Fp3::from_base(c.state.expect("a block")[lane])
    }
    fn out_ext(&mut self, c: &NChain, lane: usize) -> Fp3 {
        let s = c.state.expect("a block");
        Fp3::new(s[lane], s[lane + 1], s[lane + 2])
    }
    fn node(&mut self, c: &mut NChain, bit: Fp3, sibling: [Goldilocks; 4]) {
        if let Some(ops) = &mut c.ops {
            if bit != Fp3::ONE && bit != Fp3::ZERO {
                self.error.get_or_insert_with(|| "a Merkle direction is not a bit".into());
            }
            ops.push(NOp::Node(bit == Fp3::ONE, sibling));
            return;
        }
        let s = c.state.expect("a block");
        let cur = [s[0], s[1], s[2], s[3]];
        let right = if bit == Fp3::ONE {
            true
        } else {
            if bit != Fp3::ZERO {
                self.fail("a Merkle direction is not a bit");
            }
            false
        };
        let (l, r) = if right { (sibling, cur) } else { (cur, sibling) };
        c.state = Some(if self.error.is_none() { perm::node_state(l, r) } else { perm::node_input(l, r) });
    }
    fn node4(&mut self, c: &mut NChain, bits: [Fp3; 2], siblings: [[Goldilocks; 4]; 3]) {
        let mut pos = 0;
        for (k, &b) in bits.iter().enumerate() {
            if b == Fp3::ONE {
                pos |= 1 << k;
            } else if b != Fp3::ZERO {
                self.fail("a Merkle direction is not a bit");
            }
        }
        if let Some(ops) = &mut c.ops {
            ops.push(NOp::Node4(pos, siblings));
            return;
        }
        let s = c.state.expect("a block");
        let mut x = perm::node4_input(perm::children4([s[0], s[1], s[2], s[3]], pos, siblings));
        if self.error.is_none() {
            perm::permute(&mut x);
        }
        c.state = Some(x);
    }
    fn digest_eq(&mut self, c: &NChain, root: [Fp3; 4], what: &'static str) {
        if let Some(ops) = &c.ops {
            match root.iter().map(|r| base_of(*r)).collect::<Option<Vec<_>>>() {
                Some(r) => self.deferred.push((ops.clone(), [r[0], r[1], r[2], r[3]], what)),
                None => self.fail(what),
            }
            return;
        }
        let s = c.state.expect("a block");
        if (0..4).any(|i| Fp3::from_base(s[i]) != root[i]) {
            self.fail(what);
        }
    }
    fn bits(&mut self, v: Fp3, want: usize) -> Vec<Fp3> {
        let Some(b) = base_of(v) else {
            self.fail("bits of an extension value");
            return vec![Fp3::ZERO; want];
        };
        let x = b.as_u64();
        (0..want).map(|i| Fp3::from_base(Goldilocks::new((x >> i) & 1))).collect()
    }
}

/// The node permutation's output for children `l`, `r` (the full state;
/// the digest is lanes 0..4).
pub fn node_digest(l: [Goldilocks; 4], r: [Goldilocks; 4]) -> [Goldilocks; 4] {
    let s = perm::node_state(l, r);
    [s[0], s[1], s[2], s[3]]
}

/// Arithmetic helpers on top of [`Ops::gate`].
pub trait Arith: Ops {
    fn zero(&mut self) -> Self::V {
        self.constant(Fp3::ZERO)
    }
    fn one(&mut self) -> Self::V {
        self.constant(Fp3::ONE)
    }
    fn add(&mut self, x: Self::V, y: Self::V) -> Self::V {
        let g = Gate { qa: Fp3::ONE, qb: Fp3::ONE, ..Gate::default() };
        self.gate(g, x, y, y)
    }
    fn sub(&mut self, x: Self::V, y: Self::V) -> Self::V {
        let g = Gate { qa: Fp3::ONE, qb: -Fp3::ONE, ..Gate::default() };
        self.gate(g, x, y, y)
    }
    fn mul(&mut self, x: Self::V, y: Self::V) -> Self::V {
        let g = Gate { qm: Fp3::ONE, ..Gate::default() };
        self.gate(g, x, y, y)
    }
    /// `x·y + z`.
    fn mul_add(&mut self, x: Self::V, y: Self::V, z: Self::V) -> Self::V {
        let g = Gate { qm: Fp3::ONE, qc: Fp3::ONE, ..Gate::default() };
        self.gate(g, x, y, z)
    }
    /// `c·x + z` for a constant `c`.
    fn scale_add(&mut self, c: Fp3, x: Self::V, z: Self::V) -> Self::V {
        let g = Gate { qa: c, qc: Fp3::ONE, ..Gate::default() };
        self.gate(g, x, z, z)
    }
    /// `c·x + k`.
    fn affine(&mut self, c: Fp3, x: Self::V, k: Fp3) -> Self::V {
        let g = Gate { qa: c, qk: k, ..Gate::default() };
        self.gate(g, x, x, x)
    }
    /// `a + r·(b − a)`.
    fn lerp(&mut self, r: Self::V, a: Self::V, b: Self::V) -> Self::V {
        let g = Gate { qm: Fp3::ONE, qs: -Fp3::ONE, qc: Fp3::ONE, ..Gate::default() };
        self.gate(g, r, b, a)
    }
    /// `x·y + k`.
    fn mul_const_add(&mut self, x: Self::V, y: Self::V, k: Fp3) -> Self::V {
        let g = Gate { qm: Fp3::ONE, qk: k, ..Gate::default() };
        self.gate(g, x, y, y)
    }
    fn assert_eq(&mut self, x: Self::V, y: Self::V, what: &'static str) {
        let g = Gate { qa: Fp3::ONE, qb: -Fp3::ONE, ..Gate::default() };
        self.assert_gate(g, x, y, y, what);
    }
    fn assert_const(&mut self, x: Self::V, c: Fp3, what: &'static str) {
        let g = Gate { qa: Fp3::ONE, qk: -c, ..Gate::default() };
        self.assert_gate(g, x, x, x, what);
    }
    /// `1/x` (the prover's witness, checked: `x·w = 1`).
    fn inv(&mut self, x: Self::V, what: &'static str) -> Self::V {
        let xv = self.value(x);
        let w = self.witness(if xv == Fp3::ZERO { Fp3::ZERO } else { xv.inv() });
        let g = Gate { qm: Fp3::ONE, qk: -Fp3::ONE, ..Gate::default() };
        self.assert_gate(g, x, w, w, what);
        w
    }
    /// `x ≠ c`.
    fn assert_ne_const(&mut self, x: Self::V, c: Fp3, what: &'static str) {
        let d = self.affine(Fp3::ONE, x, -c);
        self.inv(d, what);
    }
    /// `Σ_i c_i·x_i` for constants `c_i`.
    fn lin(&mut self, terms: &[(Fp3, Self::V)]) -> Self::V {
        let mut acc = self.zero();
        for &(c, x) in terms {
            acc = self.scale_add(c, x, acc);
        }
        acc
    }
    /// `Σ_i x_i·y_i`.
    fn dot(&mut self, xs: &[Self::V], ys: &[Self::V]) -> Self::V {
        let mut acc = self.zero();
        for (&x, &y) in xs.iter().zip(ys) {
            acc = self.mul_add(x, y, acc);
        }
        acc
    }
    fn sum(&mut self, xs: &[Self::V]) -> Self::V {
        let mut acc = self.zero();
        for &x in xs {
            acc = self.add(acc, x);
        }
        acc
    }
}

impl<O: Ops> Arith for O {}

/// The node tag (capacity of a Merkle node), re-exported for layouts.
pub const NODE: u64 = NODE_TAG;
