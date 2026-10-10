//! Constraint arithmetic written once for two interpreters: [`Fp3`]
//! (the prover's and the verifier's evaluation) and [`Sym`], which records
//! the same operations as an expression graph so a relation's constraint
//! polynomial can be compiled into the recursion circuit
//! (`recursion::expr`).
//!
//! A [`Sym`] is a constant or a node of a thread-local arena; operations
//! on constants fold, `x + 0`, `x·1` and `x·0` simplify. The arena is
//! reset by [`record`], which runs a closure over fresh inputs and returns
//! the graph its outputs depend on.

use core::cell::RefCell;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use nebu::{Fp3, Goldilocks};

/// The arithmetic a constraint is written in.
pub trait Num:
    Copy
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
{
    const ZERO: Self;
    const ONE: Self;
    fn from_fp3(c: Fp3) -> Self;
    fn from_base(c: Goldilocks) -> Self {
        Self::from_fp3(Fp3::from_base(c))
    }
    fn from_u64(v: u64) -> Self {
        Self::from_base(Goldilocks::new(v))
    }
}

impl Num for Fp3 {
    const ZERO: Self = Fp3::ZERO;
    const ONE: Self = Fp3::ONE;
    fn from_fp3(c: Fp3) -> Self {
        c
    }
}

/// A recorded value: a constant or an arena node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sym {
    C(Fp3),
    N(u32),
}

/// A node of the expression graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Input(u32),
    Add(Sym, Sym),
    Sub(Sym, Sym),
    Mul(Sym, Sym),
    Neg(Sym),
}

thread_local! {
    static ARENA: RefCell<Vec<Node>> = const { RefCell::new(Vec::new()) };
}

fn push(n: Node) -> Sym {
    ARENA.with(|a| {
        let mut a = a.borrow_mut();
        a.push(n);
        Sym::N(a.len() as u32 - 1)
    })
}

/// A recorded run: the arena and the outputs.
#[derive(Clone, Debug)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub inputs: usize,
    pub outputs: Vec<Sym>,
}

/// Run `f` over `inputs` fresh symbolic inputs and record the graph of its
/// outputs (the arena is this thread's and is cleared around the run).
pub fn record(inputs: usize, f: impl FnOnce(&[Sym]) -> Vec<Sym>) -> Graph {
    ARENA.with(|a| a.borrow_mut().clear());
    let ins: Vec<Sym> = (0..inputs as u32).map(|i| push(Node::Input(i))).collect();
    let outputs = f(&ins);
    let nodes = ARENA.with(|a| core::mem::take(&mut *a.borrow_mut()));
    Graph { nodes, inputs, outputs }
}

impl Graph {
    /// Which inputs the outputs depend on.
    pub fn used_inputs(&self) -> Vec<bool> {
        let mut need = vec![false; self.nodes.len()];
        for s in &self.outputs {
            if let Sym::N(i) = s {
                need[*i as usize] = true;
            }
        }
        let mut used = vec![false; self.inputs];
        for i in (0..self.nodes.len()).rev() {
            if !need[i] {
                continue;
            }
            let mut mark = |s: Sym| {
                if let Sym::N(j) = s {
                    need[j as usize] = true;
                }
            };
            match self.nodes[i] {
                Node::Input(k) => used[k as usize] = true,
                Node::Add(a, b) | Node::Sub(a, b) | Node::Mul(a, b) => {
                    mark(a);
                    mark(b);
                }
                Node::Neg(a) => mark(a),
            }
        }
        used
    }

    /// Evaluate at `inputs` (a reference for the compiled circuit).
    pub fn eval(&self, inputs: &[Fp3]) -> Vec<Fp3> {
        let mut v = Vec::with_capacity(self.nodes.len());
        let get = |v: &Vec<Fp3>, s: Sym| match s {
            Sym::C(c) => c,
            Sym::N(i) => v[i as usize],
        };
        for n in &self.nodes {
            let x = match *n {
                Node::Input(i) => inputs[i as usize],
                Node::Add(a, b) => get(&v, a) + get(&v, b),
                Node::Sub(a, b) => get(&v, a) - get(&v, b),
                Node::Mul(a, b) => get(&v, a) * get(&v, b),
                Node::Neg(a) => -get(&v, a),
            };
            v.push(x);
        }
        self.outputs.iter().map(|&s| get(&v, s)).collect()
    }
}

/// A graph pruned to the nodes its outputs need, inputs and constants
/// resolved to slots, a product by a base-field constant specialised
/// (the native verifier evaluates `G` once per proof).
#[derive(Clone, Debug)]
pub struct Compiled {
    /// `(op, a, b)` over slots: inputs first, then constants, then nodes.
    ops: Vec<(u8, u32, u32)>,
    consts: Vec<Fp3>,
    inputs: usize,
    outputs: Vec<u32>,
}

const OP_ADD: u8 = 0;
const OP_SUB: u8 = 1;
const OP_MUL: u8 = 2;
const OP_NEG: u8 = 3;
/// `a · c` with `c` a base constant: `b` indexes `consts`.
const OP_MULB: u8 = 4;

impl Graph {
    /// The compiled form ([`Compiled`]); `eval` of both agree.
    pub fn compile(&self) -> Compiled {
        let n = self.nodes.len();
        let mut need = vec![false; n];
        for s in &self.outputs {
            if let Sym::N(i) = s {
                need[*i as usize] = true;
            }
        }
        for i in (0..n).rev() {
            if !need[i] {
                continue;
            }
            let mut mark = |s: Sym| {
                if let Sym::N(j) = s {
                    need[j as usize] = true;
                }
            };
            match self.nodes[i] {
                Node::Input(_) => {}
                Node::Add(a, b) | Node::Sub(a, b) | Node::Mul(a, b) => {
                    mark(a);
                    mark(b);
                }
                Node::Neg(a) => mark(a),
            }
        }
        // constants get slots after the inputs; nodes after the constants
        let mut consts: Vec<Fp3> = Vec::new();
        let mut cidx = std::collections::BTreeMap::<[u64; 3], u32>::new();
        let mut slot = vec![u32::MAX; n];
        let mut ops = Vec::new();
        let mut pending: Vec<(u8, Sym, Sym)> = Vec::new();
        let mut order = Vec::new();
        for i in 0..n {
            if !need[i] {
                continue;
            }
            match self.nodes[i] {
                Node::Input(k) => slot[i] = k,
                Node::Add(a, b) => pending.push((OP_ADD, a, b)),
                Node::Sub(a, b) => pending.push((OP_SUB, a, b)),
                Node::Mul(a, b) => pending.push((OP_MUL, a, b)),
                Node::Neg(a) => pending.push((OP_NEG, a, a)),
            }
            if !matches!(self.nodes[i], Node::Input(_)) {
                order.push(i);
            }
        }
        let mut cslot = |c: Fp3, consts: &mut Vec<Fp3>| -> u32 {
            let key = [c.c0.as_u64(), c.c1.as_u64(), c.c2.as_u64()];
            *cidx.entry(key).or_insert_with(|| {
                consts.push(c);
                (consts.len() - 1) as u32
            })
        };
        // first pass: register constants (their slots must precede nodes)
        let is_base = |c: Fp3| c.c1 == Goldilocks::ZERO && c.c2 == Goldilocks::ZERO;
        for &(op, a, b) in &pending {
            for x in [a, b] {
                if let Sym::C(c) = x {
                    cslot(c, &mut consts);
                }
            }
            let _ = op;
        }
        for s in &self.outputs {
            if let Sym::C(c) = s {
                cslot(*c, &mut consts);
            }
        }
        let base = self.inputs + consts.len();
        let mut next = base as u32;
        let resolve = |x: Sym, slot: &[u32], cidx: &std::collections::BTreeMap<[u64; 3], u32>| -> u32 {
            match x {
                Sym::N(j) => slot[j as usize],
                Sym::C(c) => self.inputs as u32 + cidx[&[c.c0.as_u64(), c.c1.as_u64(), c.c2.as_u64()]],
            }
        };
        for (&i, &(op, a, b)) in order.iter().zip(&pending) {
            let e = match (op, a, b) {
                (OP_MUL, x, Sym::C(c)) | (OP_MUL, Sym::C(c), x) if is_base(c) && !matches!(x, Sym::C(_)) => {
                    (OP_MULB, resolve(x, &slot, &cidx), cidx[&[c.c0.as_u64(), c.c1.as_u64(), c.c2.as_u64()]])
                }
                _ => (op, resolve(a, &slot, &cidx), resolve(b, &slot, &cidx)),
            };
            ops.push(e);
            slot[i] = next;
            next += 1;
        }
        let outputs = self.outputs.iter().map(|&s| resolve(s, &slot, &cidx)).collect();
        Compiled { ops, consts, inputs: self.inputs, outputs }
    }
}

impl Compiled {
    /// Evaluate at `inputs`.
    pub fn eval(&self, inputs: &[Fp3]) -> Vec<Fp3> {
        assert_eq!(inputs.len(), self.inputs, "graph inputs");
        let mut v = Vec::with_capacity(self.inputs + self.consts.len() + self.ops.len());
        v.extend_from_slice(inputs);
        v.extend_from_slice(&self.consts);
        for &(op, a, b) in &self.ops {
            let x = v[a as usize];
            let r = match op {
                OP_ADD => x + v[b as usize],
                OP_SUB => x - v[b as usize],
                OP_MUL => x * v[b as usize],
                OP_NEG => -x,
                _ => {
                    let c = self.consts[b as usize].c0;
                    Fp3::new(x.c0 * c, x.c1 * c, x.c2 * c)
                }
            };
            v.push(r);
        }
        self.outputs.iter().map(|&o| v[o as usize]).collect()
    }
    /// Operations evaluated.
    pub fn len(&self) -> usize {
        self.ops.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

impl Add for Sym {
    type Output = Sym;
    fn add(self, o: Sym) -> Sym {
        match (self, o) {
            (Sym::C(a), Sym::C(b)) => Sym::C(a + b),
            (Sym::C(z), x) | (x, Sym::C(z)) if z == Fp3::ZERO => x,
            _ => push(Node::Add(self, o)),
        }
    }
}

impl Sub for Sym {
    type Output = Sym;
    fn sub(self, o: Sym) -> Sym {
        match (self, o) {
            (Sym::C(a), Sym::C(b)) => Sym::C(a - b),
            (x, Sym::C(z)) if z == Fp3::ZERO => x,
            _ => push(Node::Sub(self, o)),
        }
    }
}

impl Mul for Sym {
    type Output = Sym;
    fn mul(self, o: Sym) -> Sym {
        match (self, o) {
            (Sym::C(a), Sym::C(b)) => Sym::C(a * b),
            (Sym::C(z), _) | (_, Sym::C(z)) if z == Fp3::ZERO => Sym::C(Fp3::ZERO),
            (Sym::C(u), x) | (x, Sym::C(u)) if u == Fp3::ONE => x,
            _ => push(Node::Mul(self, o)),
        }
    }
}

impl Neg for Sym {
    type Output = Sym;
    fn neg(self) -> Sym {
        match self {
            Sym::C(a) => Sym::C(-a),
            _ => push(Node::Neg(self)),
        }
    }
}

impl AddAssign for Sym {
    fn add_assign(&mut self, o: Sym) {
        *self = *self + o;
    }
}
impl SubAssign for Sym {
    fn sub_assign(&mut self, o: Sym) {
        *self = *self - o;
    }
}
impl MulAssign for Sym {
    fn mul_assign(&mut self, o: Sym) {
        *self = *self * o;
    }
}

impl Num for Sym {
    const ZERO: Self = Sym::C(Fp3::ZERO);
    const ONE: Self = Sym::C(Fp3::ONE);
    fn from_fp3(c: Fp3) -> Self {
        Sym::C(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poly<T: Num>(x: T, y: T) -> T {
        let three = T::from_u64(3);
        x * x * y - three * y + T::ONE - (x + T::ZERO) * T::ONE + -y
    }

    #[test]
    fn a_recorded_graph_evaluates_as_the_field() {
        let g = record(2, |i| vec![poly(i[0], i[1]), poly(Sym::C(Fp3::ONE), i[1])]);
        let x = Fp3::new(Goldilocks::new(5), Goldilocks::new(7), Goldilocks::new(11));
        let y = Fp3::new(Goldilocks::new(2), Goldilocks::new(0), Goldilocks::new(9));
        assert_eq!(g.eval(&[x, y]), vec![poly(x, y), poly(Fp3::ONE, y)]);
    }
}
