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
