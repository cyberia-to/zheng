use super::*;
use std::collections::BTreeMap;
pub(super) struct Builder {
    inputs: usize,
    ops: Vec<Op>,
    rows: Vec<(Linear, Linear, Linear)>,
    nodes: usize,
    pub calls: usize,
    pub digests: BTreeMap<usize, [Wire; 4]>,
    pub atom_digests: BTreeMap<Wire, [Wire; 4]>,
    pub pair_digests: BTreeMap<([Wire; 4], [Wire; 4]), [Wire; 4]>,
}
impl Builder {
    pub fn new(inputs: usize) -> Self {
        Self {
            inputs,
            ops: vec![],
            rows: vec![(vec![(ZERO, F::ONE)], vec![(ONE, F::ONE)], vec![])],
            nodes: 0,
            calls: 0,
            digests: BTreeMap::new(),
            atom_digests: BTreeMap::new(),
            pair_digests: BTreeMap::new(),
        }
    }
    fn row(&mut self, a: Linear, b: Linear, c: Linear) -> Result<(), Error> {
        if self.rows.len() >= MAX_GATES {
            return Err(Error::Limit);
        }
        self.rows.push((a, b, c));
        Ok(())
    }
    pub fn alloc(&mut self, op: Op) -> Result<Wire, Error> {
        if self.ops.len() >= MAX_GATES {
            return Err(Error::Limit);
        }
        let wire = 2 + self.inputs + self.ops.len();
        self.ops.push(op);
        Ok(wire)
    }
    pub fn lin(&mut self, l: Linear) -> Result<Wire, Error> {
        let w = self.alloc(Op::Linear(l.clone()))?;
        self.row(l, vec![(ONE, F::ONE)], vec![(w, F::ONE)])?;
        Ok(w)
    }
    pub fn mul(&mut self, a: Wire, b: Wire) -> Result<Wire, Error> {
        let w = self.alloc(Op::Product(a, b))?;
        self.row(vec![(a, F::ONE)], vec![(b, F::ONE)], vec![(w, F::ONE)])?;
        Ok(w)
    }
    pub fn zero_product(&mut self, a: Wire, b: Linear) -> Result<(), Error> {
        self.row(vec![(a, F::ONE)], b, vec![])
    }
    pub fn inv(&mut self, a: Wire) -> Result<Wire, Error> {
        self.alloc(Op::Inverse(a))
    }
    pub fn constant(&mut self, x: u64) -> Result<Wire, Error> {
        match x {
            0 => Ok(ZERO),
            1 => Ok(ONE),
            _ => self.lin(vec![(ONE, F::new(x))]),
        }
    }
    pub fn node(
        &mut self,
        tag: Wire,
        value: Wire,
        children: Option<(Rc<Node>, Rc<Node>)>,
    ) -> Result<Rc<Node>, Error> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(Error::Limit);
        }
        self.zero_product(tag, vec![(ONE, F::ONE), (tag, -F::ONE)])?;
        self.zero_product(tag, vec![(value, F::ONE)])?;
        if let Some((a, b)) = &children {
            for c in [a, b] {
                self.row(
                    vec![(ONE, F::ONE), (tag, -F::ONE)],
                    vec![(c.tag, F::ONE)],
                    vec![],
                )?;
                self.row(
                    vec![(ONE, F::ONE), (tag, -F::ONE)],
                    vec![(c.value, F::ONE)],
                    vec![],
                )?;
            }
        } else {
            self.zero_product(ONE, vec![(tag, F::ONE)])?;
        }
        Ok(Rc::new(Node {
            id: self.nodes,
            tag,
            value,
            children,
        }))
    }
    pub fn zero(&mut self) -> Result<Rc<Node>, Error> {
        self.node(ZERO, ZERO, None)
    }
    pub fn subject(&mut self, s: &SubjectShape, next: &mut Wire) -> Result<Rc<Node>, Error> {
        match s {
            SubjectShape::Atom => {
                let w = *next;
                *next += 1;
                self.node(ZERO, w, None)
            }
            SubjectShape::Pair(a, b) => {
                let a = self.subject(a, next)?;
                let b = self.subject(b, next)?;
                self.node(ONE, ZERO, Some((a, b)))
            }
        }
    }
    pub fn quoted(&mut self, n: &Noun, active: Wire) -> Result<Rc<Node>, Error> {
        match n {
            Noun::Atom(v) => {
                let c = self.constant(*v)?;
                let v = self.mul(active, c)?;
                self.node(ZERO, v, None)
            }
            Noun::Pair(a, b) => {
                let a = self.quoted(a, active)?;
                let b = self.quoted(b, active)?;
                self.node(active, ZERO, Some((a, b)))
            }
        }
    }
    pub fn mask(&mut self, n: &Rc<Node>, active: Wire) -> Result<Rc<Node>, Error> {
        // Verifier-known unit activity preserves carrier identity and lets
        // repeated axis/hash consumers share the same constrained digest.
        if active == ONE {
            return Ok(n.clone());
        }
        let tag = self.mul(active, n.tag)?;
        let value = self.mul(active, n.value)?;
        let children = if let Some((a, b)) = &n.children {
            Some((self.mask(a, active)?, self.mask(b, active)?))
        } else {
            None
        };
        self.node(tag, value, children)
    }
    pub fn atom(&mut self, n: &Node, active: Wire) -> Result<Wire, Error> {
        self.zero_product(active, vec![(n.tag, F::ONE)])?;
        Ok(n.value)
    }
    pub fn select(&mut self, s: Wire, a: Wire, b: Wire) -> Result<Wire, Error> {
        let delta = self.lin(vec![(b, F::ONE), (a, -F::ONE)])?;
        let v = self.mul(s, delta)?;
        self.lin(vec![(a, F::ONE), (v, F::ONE)])
    }
    pub fn mux(&mut self, s: Wire, a: &Rc<Node>, b: &Rc<Node>) -> Result<Rc<Node>, Error> {
        let tag = self.select(s, a.tag, b.tag)?;
        let value = self.select(s, a.value, b.value)?;
        let children = match (&a.children, &b.children) {
            (None, None) => None,
            (Some((al, ar)), Some((bl, br))) => Some((self.mux(s, al, bl)?, self.mux(s, ar, br)?)),
            (Some((al, ar)), None) => {
                let z = self.zero()?;
                Some((self.mux(s, al, &z)?, self.mux(s, ar, &z)?))
            }
            (None, Some((bl, br))) => {
                let z = self.zero()?;
                Some((self.mux(s, &z, bl)?, self.mux(s, &z, br)?))
            }
        };
        self.node(tag, value, children)
    }
    pub fn finish(
        self,
        output: Rc<Node>,
        cost: Wire,
        max_cost: u64,
    ) -> Result<TaggedRelation, Error> {
        fn depth(n: &Node, d: usize) -> Result<(), Error> {
            if d > MAX_DEPTH {
                return Err(Error::Limit);
            }
            if let Some((a, b)) = &n.children {
                depth(a, d + 1)?;
                depth(b, d + 1)?;
            }
            Ok(())
        }
        depth(&output, 0)?;
        let rows = self.rows.len().max(2).next_power_of_two();
        let cols = (2 + self.inputs + self.ops.len())
            .max(64)
            .next_power_of_two();
        let mut matrices = vec![SparseMatrix::new(rows, cols); 3];
        for (r, (a, b, c)) in self.rows.into_iter().enumerate() {
            matrices[0].entries[r] = a;
            matrices[1].entries[r] = b;
            matrices[2].entries[r] = c;
        }
        Ok(TaggedRelation {
            instance: CCSInstance {
                matrices,
                multisets: vec![vec![0, 1], vec![2]],
                coeffs: vec![F::ONE, -F::ONE],
                num_rows: rows,
                num_cols: cols,
            },
            inputs: (2..2 + self.inputs).collect(),
            output,
            cost,
            max_cost,
            ops: self.ops,
        })
    }
}
