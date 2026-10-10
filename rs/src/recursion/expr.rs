//! A recorded constraint graph ([`crate::air::num::Graph`]) as verifier
//! operations: the polynomial the native verifier evaluates in the field
//! becomes gates of the recursion circuit.
//!
//! Sums stay symbolic as affine forms `Σ c_i·v_i + k` over computed values
//! and become gates only where a product or an output needs them: a
//! product `x·(c_y·y + c_z·z + k)` is one gate
//! (`q_m = c_y, q_s = c_z/c_y, q_a = k`), an affine form of `t` terms
//! takes `⌈(t − 1)/2⌉` gates (three inputs a gate).

use nebu::Fp3;

use super::ops::{Gate, Ops};
use crate::air::num::{Graph, Node, Sym};

#[derive(Clone, Debug)]
struct Lin<V> {
    terms: Vec<(Fp3, V)>,
    k: Fp3,
}

impl<V: Copy> Lin<V> {
    fn var(v: V) -> Self {
        Self { terms: vec![(Fp3::ONE, v)], k: Fp3::ZERO }
    }
    fn constant(k: Fp3) -> Self {
        Self { terms: Vec::new(), k }
    }
    fn scaled(&self, c: Fp3) -> Self {
        Self { terms: self.terms.iter().map(|&(a, v)| (a * c, v)).collect(), k: self.k * c }
    }
    fn plus(&self, o: &Self, sign: Fp3) -> Self {
        let mut terms = self.terms.clone();
        terms.extend(o.terms.iter().map(|&(a, v)| (a * sign, v)));
        Self { terms, k: self.k + sign * o.k }
    }
}

struct Compiler<'a, O: Ops> {
    g: &'a Graph,
    lin: Vec<Option<Lin<O::V>>>,
    mat: Vec<Option<O::V>>,
}

impl<O: Ops> Compiler<'_, O> {
    fn lin_of(&self, s: Sym) -> Lin<O::V> {
        match s {
            Sym::C(c) => Lin::constant(c),
            Sym::N(i) => self.lin[i as usize].clone().expect("an earlier node"),
        }
    }

    fn materialize_lin(o: &mut O, l: &Lin<O::V>) -> O::V {
        if l.terms.is_empty() {
            return o.constant(l.k);
        }
        if l.terms.len() == 1 && l.terms[0].0 == Fp3::ONE && l.k == Fp3::ZERO {
            return l.terms[0].1;
        }
        let mut it = l.terms.iter();
        let (ca, a) = *it.next().expect("a term");
        let (cb, b) = it.next().copied().unwrap_or((Fp3::ZERO, a));
        let (cc, c) = it.next().copied().unwrap_or((Fp3::ZERO, a));
        let mut acc = o.gate(Gate { qa: ca, qb: cb, qc: cc, qk: l.k, ..Gate::default() }, a, b, c);
        let rest: Vec<(Fp3, O::V)> = it.copied().collect();
        for pair in rest.chunks(2) {
            let (cb, b) = pair[0];
            let (cc, c) = pair.get(1).copied().unwrap_or((Fp3::ZERO, b));
            acc = o.gate(Gate { qa: Fp3::ONE, qb: cb, qc: cc, ..Gate::default() }, acc, b, c);
        }
        acc
    }

    fn materialize(&mut self, o: &mut O, s: Sym) -> O::V {
        match s {
            Sym::C(c) => o.constant(c),
            Sym::N(i) => {
                let i = i as usize;
                if let Some(v) = self.mat[i] {
                    return v;
                }
                let l = self.lin[i].clone().expect("an earlier node");
                let v = Self::materialize_lin(o, &l);
                self.mat[i] = Some(v);
                v
            }
        }
    }

    /// `x·b` for a computed `x` and an affine `b` of at most two terms.
    fn product(o: &mut O, x: O::V, b: &Lin<O::V>) -> O::V {
        let (cy, y) = b.terms[0];
        let (cz, z) = b.terms.get(1).copied().unwrap_or((Fp3::ZERO, y));
        let g = Gate { qm: cy, qs: cz * cy.inv(), qa: b.k, ..Gate::default() };
        o.gate(g, x, y, z)
    }

    fn mul(&mut self, o: &mut O, a: Sym, b: Sym) -> Lin<O::V> {
        let (la, lb) = (self.lin_of(a), self.lin_of(b));
        if la.terms.is_empty() {
            return lb.scaled(la.k);
        }
        if lb.terms.is_empty() {
            return la.scaled(lb.k);
        }
        let out = if lb.terms.len() <= 2 && lb.terms[0].0 != Fp3::ZERO {
            let x = self.materialize(o, a);
            Self::product(o, x, &lb)
        } else if la.terms.len() <= 2 && la.terms[0].0 != Fp3::ZERO {
            let x = self.materialize(o, b);
            Self::product(o, x, &la)
        } else {
            let x = self.materialize(o, a);
            let y = self.materialize(o, b);
            o.gate(Gate { qm: Fp3::ONE, ..Gate::default() }, x, y, y)
        };
        Lin::var(out)
    }
}

/// Compile `g` with its inputs bound to `inputs`; returns the outputs.
pub fn compile<O: Ops>(o: &mut O, g: &Graph, inputs: &[O::V]) -> Vec<O::V> {
    assert_eq!(inputs.len(), g.inputs, "graph inputs");
    let n = g.nodes.len();
    // only what the outputs depend on
    let mut need = vec![false; n];
    for s in &g.outputs {
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
        match g.nodes[i] {
            Node::Input(_) => {}
            Node::Add(a, b) | Node::Sub(a, b) | Node::Mul(a, b) => {
                mark(a);
                mark(b);
            }
            Node::Neg(a) => mark(a),
        }
    }
    let mut c: Compiler<'_, O> = Compiler { g, lin: vec![None; n], mat: vec![None; n] };
    for (i, &needed) in need.iter().enumerate() {
        if !needed {
            continue;
        }
        let l = match c.g.nodes[i] {
            Node::Input(j) => {
                c.mat[i] = Some(inputs[j as usize]);
                Lin::var(inputs[j as usize])
            }
            Node::Add(a, b) => c.lin_of(a).plus(&c.lin_of(b), Fp3::ONE),
            Node::Sub(a, b) => c.lin_of(a).plus(&c.lin_of(b), -Fp3::ONE),
            Node::Neg(a) => c.lin_of(a).scaled(-Fp3::ONE),
            Node::Mul(a, b) => c.mul(o, a, b),
        };
        c.lin[i] = Some(l);
    }
    g.outputs.clone().into_iter().map(|s| c.materialize(o, s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::num::{Num, record};
    use crate::recursion::circuit::builder::Builder;
    use crate::recursion::ops::{Native, Ops};
    use nebu::Goldilocks;

    fn e(i: u64) -> Fp3 {
        Fp3::new(Goldilocks::new(i * 7 + 1), Goldilocks::new(i * i + 11), Goldilocks::new(3 * i + 2))
    }

    fn poly<T: Num>(x: &[T]) -> Vec<T> {
        let a = x[0] * x[1] + x[2] * T::from_u64(3) - x[3];
        let b = (x[0] + x[1] + x[2] + x[3] + T::ONE) * (x[1] - x[2] * T::from_u64(5));
        let mut s = T::ZERO;
        for &v in x {
            s += v * v * T::from_u64(9) + v;
        }
        vec![a, b, s * a - b, -a + T::from_u64(7), T::from_u64(4)]
    }

    #[test]
    fn a_compiled_graph_computes_the_polynomial() {
        let g = record(4, poly);
        let x: Vec<Fp3> = (0..4).map(e).collect();
        let want = poly(&x);
        assert_eq!(g.eval(&x), want);
        let mut o = Native::new();
        assert_eq!(compile(&mut o, &g, &x), want);
        let mut b = Builder::new(true);
        let ins: Vec<_> = x.iter().map(|&v| b.witness(v)).collect();
        let outs = compile(&mut b, &g, &ins);
        let got: Vec<Fp3> = outs.iter().map(|&v| b.value(v)).collect();
        assert_eq!(got, want);
        b.finish().unwrap();
    }

    #[test]
    fn the_step_relation_compiles_to_its_constraint_polynomial() {
        use crate::machine::air::{Constants, KConst, KCONSTS, Machine};
        use crate::recursion::relation::{G_POINT, Relation};
        let n = 10;
        let constants = Constants { fml0: 3, obj0: 4, p: 9, output: [Goldilocks::new(5); 4], cycles: 77, root: [Goldilocks::ZERO; 4] };
        let rel = Relation::new(Machine::new(constants, &[], 1 << n, 0, 1 << n), [e(1), e(2)]);
        let g = record(G_POINT + 2 + KCONSTS, |i| {
            let (pt, rest) = i.split_at(G_POINT);
            vec![rel.g_with(pt, &[rest[0], rest[1]], &KConst::from_slice(&rest[2..]))]
        });
        let x: Vec<Fp3> = (0..(G_POINT + 2 + KCONSTS) as u64).map(|i| e(i + 40)).collect();
        let (pt, rest) = x.split_at(G_POINT);
        let want = rel.g_with(pt, &[rest[0], rest[1]], &KConst::from_slice(&rest[2..]));
        assert_eq!(g.eval(&x), vec![want]);
        let mut b = Builder::new(true);
        let ins: Vec<_> = x.iter().map(|&v| b.witness(v)).collect();
        let outs = compile(&mut b, &g, &ins);
        assert_eq!(b.value(outs[0]), want);
        eprintln!("G: {} constraints, {} graph nodes, {} gates", rel.constraints(), g.nodes.len(), b.gates.len());
    }
}
