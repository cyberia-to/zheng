//! Experimental tagged noun CCS kernel. Not used by any production proof path.
//! Contract: specs/props/tagged-symbolic-relation.md. Rows alone do not bind z[0].
use super::relation::{ExecutionNoun as Noun, RelationError as Error, SubjectShape};
use crate::types::{CCSInstance, CCSWitness, SparseMatrix};
use nebu::Goldilocks as F;
use std::rc::Rc;
mod build;
mod eval;
mod hash;
#[cfg(test)]
mod hash_tests;
#[cfg(test)]
mod tests;
mod word;
#[cfg(test)]
mod word_tests;

type Wire = usize;
type Linear = Vec<(Wire, F)>;
const ONE: Wire = 0;
const ZERO: Wire = 1;
const MAX_NODES: usize = 4096;
const MAX_DEPTH: usize = 128;
const MAX_GATES: usize = 32768;
#[derive(Clone, Debug)]
struct Node {
    id: usize,
    tag: Wire,
    value: Wire,
    children: Option<(Rc<Node>, Rc<Node>)>,
}
#[derive(Clone, Debug)]
enum Op {
    Linear(Linear),
    Product(Wire, Wire),
    Inverse(Wire),
    Bit(Wire, usize),
}

/// Verifier-derived experimental relation. No serialized/public proof API.
/// Authenticate `public_coordinates` under the same commitment as these matrices.
#[derive(Clone, Debug)]
pub struct TaggedRelation {
    instance: CCSInstance,
    inputs: Vec<Wire>,
    output: Rc<Node>,
    cost: Wire,
    max_cost: u64,
    ops: Vec<Op>,
}
impl TaggedRelation {
    pub fn instance(&self) -> &CCSInstance {
        &self.instance
    }
    pub fn max_cost(&self) -> u64 {
        self.max_cost
    }
    /// Produce a candidate witness; native errors still yield unsatisfied rows.
    /// This method is deliberately not the verifier.
    pub fn witness(&self, inputs: &[u64]) -> Result<CCSWitness, Error> {
        if inputs.len() != self.inputs.len() {
            return Err(Error::InputCount);
        }
        if inputs.iter().any(|&x| x >= nebu::field::P) {
            return Err(Error::NonCanonical);
        }
        let mut z = vec![F::ONE, F::ZERO];
        z.extend(inputs.iter().copied().map(F::new));
        for op in &self.ops {
            let v = match op {
                Op::Linear(l) => l.iter().fold(F::ZERO, |v, &(i, c)| v + z[i] * c),
                Op::Product(a, b) => z[*a] * z[*b],
                Op::Bit(a, k) => F::new((z[*a].canonicalize().as_u64() >> k) & 1),
                Op::Inverse(a) => {
                    if z[*a] == F::ZERO {
                        F::ZERO
                    } else {
                        z[*a].inv()
                    }
                }
            };
            z.push(v);
        }
        z.resize(self.instance.num_cols, F::ZERO);
        Ok(CCSWitness { z })
    }
    pub fn public_coordinates(
        &self,
        inputs: &[u64],
        output: &Noun,
        cost: u64,
        budget: u64,
    ) -> Result<Vec<(usize, F)>, Error> {
        if inputs.len() != self.inputs.len() {
            return Err(Error::InputCount);
        }
        if cost > budget || cost > self.max_cost || budget >= nebu::field::P {
            return Err(Error::Limit);
        }
        check_noun(output, 0, &mut 0)?;
        if inputs.iter().any(|&x| x >= nebu::field::P) {
            return Err(Error::NonCanonical);
        }
        let mut pins = vec![(ONE, F::ONE), (ZERO, F::ZERO), (self.cost, F::new(cost))];
        pins.extend(
            self.inputs
                .iter()
                .zip(inputs)
                .map(|(&i, &v)| (i, F::new(v))),
        );
        bind_output(&self.output, Some(output), &mut pins)?;
        Ok(pins)
    }
    pub fn verify_witness(
        &self,
        inputs: &[u64],
        output: &Noun,
        cost: u64,
        budget: u64,
        witness: &CCSWitness,
    ) -> bool {
        if witness.z.len() != self.instance.num_cols {
            return false;
        }
        let Ok(pins) = self.public_coordinates(inputs, output, cost, budget) else {
            return false;
        };
        pins.into_iter().all(|(i, v)| witness.z[i] == v) && self.instance.is_satisfied_by(witness)
    }
}
fn bind_output(node: &Node, noun: Option<&Noun>, pins: &mut Vec<(usize, F)>) -> Result<(), Error> {
    let (tag, value, left, right) = match noun {
        Some(Noun::Atom(x)) => (F::ZERO, F::new(*x), None, None),
        Some(Noun::Pair(a, b)) => (F::ONE, F::ZERO, Some(a.as_ref()), Some(b.as_ref())),
        None => (F::ZERO, F::ZERO, None, None),
    };
    pins.push((node.tag, tag));
    pins.push((node.value, value));
    match &node.children {
        Some((a, b)) => {
            bind_output(a, left, pins)?;
            bind_output(b, right, pins)?;
        }
        None if left.is_some() => return Err(Error::Malformed),
        None => {}
    }
    Ok(())
}
fn check_noun(n: &Noun, depth: usize, count: &mut usize) -> Result<(), Error> {
    *count += 1;
    if depth > MAX_DEPTH || *count > MAX_NODES {
        return Err(Error::Limit);
    }
    match n {
        Noun::Atom(x) if *x >= nebu::field::P => Err(Error::NonCanonical),
        Noun::Atom(_) => Ok(()),
        Noun::Pair(a, b) => {
            check_noun(a, depth + 1, count)?;
            check_noun(b, depth + 1, count)
        }
    }
}
fn shape_inputs(s: &SubjectShape, depth: usize, nodes: &mut usize) -> Result<usize, Error> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(Error::Limit);
    }
    match s {
        SubjectShape::Atom => Ok(1),
        SubjectShape::Pair(a, b) => {
            Ok(shape_inputs(a, depth + 1, nodes)? + shape_inputs(b, depth + 1, nodes)?)
        }
    }
}
/// Compile only the documented tagged kernel. Matrices depend exclusively on
/// the canonical formula and subject topology, never input/output values.
pub fn compile(program: &Noun, subject: &SubjectShape) -> Result<TaggedRelation, Error> {
    check_noun(program, 0, &mut 0)?;
    let inputs = shape_inputs(subject, 0, &mut 0)?;
    let mut b = build::Builder::new(inputs);
    let obj = b.subject(subject, &mut 2)?;
    let (output, cost, max_cost) = b.eval(&obj, program, ONE, 0)?;
    if max_cost >= nebu::field::P {
        return Err(Error::Limit);
    }
    b.finish(output, cost, max_cost)
}
