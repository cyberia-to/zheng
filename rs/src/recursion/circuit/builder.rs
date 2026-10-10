//! The circuit interpreter of [`Ops`]: every operation becomes rows of the
//! recursion circuit, every value a write-once memory cell. The order of
//! operations fixes the layout; a verifier run on any data of the right
//! shape produces the same preprocessed columns (the circuit's key).

use std::collections::HashMap;

use nebu::{Fp3, Goldilocks};

use crate::recursion::ops::{Gate, In, Ops};
use crate::recursion::perm::{self, RATE, WIDTH};

/// A memory cell (its address is `id + 1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Var(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateKind {
    Compute,
    Assert,
    Free,
}

pub struct GateRec {
    pub g: Gate,
    pub ops: [Var; 3],
    pub used: [bool; 3],
    pub out: Option<Var>,
    pub kind: GateKind,
}

pub enum BlockIn {
    /// Rate items (as given to `permute`).
    Sponge(Vec<In<Var>>),
    /// A Merkle node: the direction bit and the sibling.
    Node(Var, [Goldilocks; 4]),
    /// A 4-ary Merkle node: the two direction bits and the siblings.
    Node4([Var; 2], [[Goldilocks; 4]; 3]),
}

pub struct BlockRec {
    pub input: BlockIn,
    /// The permutation input and output.
    pub x: [Goldilocks; WIDTH],
    pub y: [Goldilocks; WIDTH],
    /// Output lanes written: `(lane, wide, var)`.
    pub outs: Vec<(usize, bool, Var)>,
    pub root: Option<[Var; 4]>,
}

pub struct ChainRec {
    pub tag: u64,
    pub blocks: Vec<BlockRec>,
}

pub struct BitsRec {
    pub v: Var,
    pub value: u64,
    /// The written low bits.
    pub bits: Vec<Var>,
}

/// Records a verifier run as circuit operations.
pub struct Builder {
    pub vals: Vec<Fp3>,
    pub reads: Vec<u32>,
    pub gates: Vec<GateRec>,
    pub chains: Vec<ChainRec>,
    pub bits: Vec<BitsRec>,
    /// Values allocated for a permutation block and not yet placed.
    pending: usize,
    pub live: Var,
    pub live_value: bool,
    pub errors: Vec<&'static str>,
    consts: HashMap<[u64; 3], Var>,
    /// The chain whose last block outputs the public input.
    pub out_chain: Option<usize>,
}

/// A chain handle: its index.
pub struct BChain(pub usize);

fn key(x: Fp3) -> [u64; 3] {
    [x.c0.as_u64(), x.c1.as_u64(), x.c2.as_u64()]
}

impl Builder {
    /// A builder for a step whose assertions are on (`live`) or off (the
    /// base step).
    pub fn new(live: bool) -> Self {
        let mut b = Self {
            vals: Vec::new(),
            reads: Vec::new(),
            gates: Vec::new(),
            chains: Vec::new(),
            bits: Vec::new(),
            pending: 0,
            live: Var(0),
            live_value: live,
            errors: Vec::new(),
            consts: HashMap::new(),
            out_chain: None,
        };
        b.live = b.new_var(if live { Fp3::ONE } else { Fp3::ZERO });
        b
    }

    fn new_var(&mut self, x: Fp3) -> Var {
        self.vals.push(x);
        self.reads.push(0);
        Var(self.vals.len() as u32 - 1)
    }

    fn read(&mut self, v: Var) {
        self.reads[v.0 as usize] += 1;
    }

    fn check(&mut self, ok: bool, what: &'static str) {
        if !ok && self.live_value {
            self.errors.push(what);
        }
    }

    /// Mark `c`'s last block as the public-input row.
    pub fn set_output(&mut self, c: &BChain) {
        self.out_chain = Some(c.0);
    }

    /// The live variable (1 in every step but the base step).
    pub fn live_var(&self) -> Var {
        self.live
    }

    /// `Err` when a live assertion failed or an allocated value was never
    /// placed.
    pub fn finish(&self) -> Result<(), String> {
        if self.pending != 0 {
            return Err(format!("circuit: {} allocated values not placed", self.pending));
        }
        match self.errors.first() {
            None => Ok(()),
            Some(e) => Err(format!("circuit: {e}")),
        }
    }

    fn gate_rec(&mut self, g: Gate, ops: [Var; 3], kind: GateKind, out: Option<Var>) {
        let z = Fp3::ZERO;
        let used = [
            g.qm != z || g.qa != z,
            g.qm != z || g.qb != z,
            (g.qm != z && g.qs != z) || g.qc != z,
        ];
        for (v, &u) in ops.iter().zip(&used) {
            if u {
                self.read(*v);
            }
        }
        self.gates.push(GateRec { g, ops, used, out, kind });
    }
}

impl Ops for Builder {
    type V = Var;
    type Chain = BChain;

    fn value(&self, v: Var) -> Fp3 {
        self.vals[v.0 as usize]
    }
    fn gate(&mut self, g: Gate, x: Var, y: Var, z: Var) -> Var {
        let out = self.new_var(g.eval(self.value(x), self.value(y), self.value(z)));
        self.gate_rec(g, [x, y, z], GateKind::Compute, Some(out));
        out
    }
    fn assert_gate(&mut self, g: Gate, x: Var, y: Var, z: Var, what: &'static str) {
        let ok = g.eval(self.value(x), self.value(y), self.value(z)) == Fp3::ZERO;
        self.check(ok, what);
        self.gate_rec(g, [x, y, z], GateKind::Assert, None);
    }
    fn witness(&mut self, x: Fp3) -> Var {
        let out = self.new_var(x);
        let any = self.live;
        self.gate_rec(Gate::default(), [any, any, any], GateKind::Free, Some(out));
        out
    }
    fn alloc(&mut self, x: Fp3) -> Var {
        self.pending += 1;
        self.new_var(x)
    }
    fn constant(&mut self, x: Fp3) -> Var {
        if let Some(&v) = self.consts.get(&key(x)) {
            return v;
        }
        let g = Gate { qk: x, ..Gate::default() };
        let any = self.live;
        let out = self.new_var(x);
        self.gate_rec(g, [any, any, any], GateKind::Compute, Some(out));
        self.consts.insert(key(x), out);
        out
    }
    fn chain(&mut self, tag: u64) -> BChain {
        self.chains.push(ChainRec { tag, blocks: Vec::new() });
        BChain(self.chains.len() - 1)
    }
    fn permute(&mut self, c: &mut BChain, items: &[In<Var>]) {
        let ch = &self.chains[c.0];
        let prev = ch.blocks.last().map(|b| b.y);
        let mut x = [Goldilocks::ZERO; WIDTH];
        match prev {
            Some(y) => x[RATE..].copy_from_slice(&y[RATE..]),
            None => x[RATE] = Goldilocks::new(ch.tag),
        }
        let mut lane = 0;
        let mut reads = Vec::new();
        for it in items {
            let w = it.width();
            assert!(lane + w <= RATE, "permutation items straddle the rate");
            match *it {
                In::Var(v, ext) | In::Free(v, ext) => {
                    if matches!(it, In::Var(..)) {
                        reads.push(v);
                    } else {
                        self.pending -= 1;
                    }
                    let val = self.vals[v.0 as usize];
                    if ext {
                        x[lane] = val.c0;
                        x[lane + 1] = val.c1;
                        x[lane + 2] = val.c2;
                    } else {
                        let ok = val.c1 == Goldilocks::ZERO && val.c2 == Goldilocks::ZERO;
                        self.check(ok, "a base lane holds an extension value");
                        x[lane] = val.c0;
                    }
                }
                In::Zero => x[lane] = Goldilocks::ZERO,
                In::Keep => x[lane] = prev.map_or(Goldilocks::ZERO, |y| y[lane]),
            }
            lane += w;
        }
        assert_eq!(lane, RATE, "permutation items cover the rate");
        for v in reads {
            self.read(v);
        }
        let mut y = x;
        perm::permute(&mut y);
        self.chains[c.0].blocks.push(BlockRec {
            input: BlockIn::Sponge(items.to_vec()),
            x,
            y,
            outs: Vec::new(),
            root: None,
        });
    }
    fn out_base(&mut self, c: &BChain, lane: usize) -> Var {
        self.output(c, lane, false)
    }
    fn out_ext(&mut self, c: &BChain, lane: usize) -> Var {
        self.output(c, lane, true)
    }
    fn node(&mut self, c: &mut BChain, bit: Var, sibling: [Goldilocks; 4]) {
        let y = self.chains[c.0].blocks.last().expect("a block").y;
        let cur = perm::head(&y);
        let bv = self.value(bit);
        self.check(bv == Fp3::ZERO || bv == Fp3::ONE, "a Merkle direction is not a bit");
        let (l, r) = if bv == Fp3::ONE { (sibling, cur) } else { (cur, sibling) };
        let x = perm::node_input(l, r);
        let mut y2 = x;
        perm::permute(&mut y2);
        self.read(bit);
        self.chains[c.0].blocks.push(BlockRec {
            input: BlockIn::Node(bit, sibling),
            x,
            y: y2,
            outs: Vec::new(),
            root: None,
        });
    }
    fn node4(&mut self, c: &mut BChain, bits: [Var; 2], siblings: [[Goldilocks; 4]; 3]) {
        let y = self.chains[c.0].blocks.last().expect("a block").y;
        let cur = perm::head(&y);
        let mut pos = 0;
        for (k, &b) in bits.iter().enumerate() {
            let bv = self.value(b);
            self.check(bv == Fp3::ZERO || bv == Fp3::ONE, "a Merkle direction is not a bit");
            if bv == Fp3::ONE {
                pos |= 1 << k;
            }
            self.read(b);
        }
        let x = perm::node4_input(perm::children4(cur, pos, siblings));
        let mut y2 = x;
        perm::permute(&mut y2);
        self.chains[c.0].blocks.push(BlockRec {
            input: BlockIn::Node4(bits, siblings),
            x,
            y: y2,
            outs: Vec::new(),
            root: None,
        });
    }
    fn digest_eq(&mut self, c: &BChain, root: [Var; 4], what: &'static str) {
        let y = self.chains[c.0].blocks.last().expect("a block").y;
        let ok = (0..4).all(|i| Fp3::from_base(y[i]) == self.value(root[i]));
        self.check(ok, what);
        for &r in &root {
            self.read(r);
        }
        let blk = self.chains[c.0].blocks.last_mut().expect("a block");
        assert!(blk.root.is_none(), "one root check per block");
        blk.root = Some(root);
    }
    fn bits(&mut self, v: Var, want: usize) -> Vec<Var> {
        let x = self.value(v);
        let ok = x.c1 == Goldilocks::ZERO && x.c2 == Goldilocks::ZERO;
        self.check(ok, "bits of an extension value");
        let value = x.c0.as_u64();
        self.read(v);
        let bits: Vec<Var> = (0..want)
            .map(|i| self.new_var(Fp3::from_base(Goldilocks::new((value >> i) & 1))))
            .collect();
        self.bits.push(BitsRec { v, value, bits: bits.clone() });
        bits
    }
}

impl Builder {
    fn output(&mut self, c: &BChain, lane: usize, wide: bool) -> Var {
        let blk = self.chains[c.0].blocks.last().expect("a block");
        if let Some(&(_, w, v)) = blk.outs.iter().find(|o| o.0 == lane) {
            assert_eq!(w, wide, "an output lane read two ways");
            return v;
        }
        let y = blk.y;
        let val = if wide {
            Fp3::new(y[lane], y[lane + 1], y[lane + 2])
        } else {
            Fp3::from_base(y[lane])
        };
        let v = self.new_var(val);
        self.chains[c.0].blocks.last_mut().expect("a block").outs.push((lane, wide, v));
        v
    }

    /// Rows the recorded operations need.
    pub fn rows(&self) -> usize {
        let arith = self.gates.len().div_ceil(crate::recursion::circuit::layout::GATES).max(1);
        let blocks: usize = self.chains.iter().map(|c| c.blocks.len()).sum();
        arith + 4 * self.bits.len() + 4 * blocks
    }
}
