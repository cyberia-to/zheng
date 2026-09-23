//! Bounded symbolic nox execution, with shared wires for all data movement.
//!
//! This is a restricted public-input circuit, not the complete nox VM. Dynamic
//! continuations, state and mismatched branch shapes fail closed. Calls carry
//! atom witnesses checked by their continuation under the selected branch.
//! Matrices depend on program and subject shape, never witness/input values.
use crate::types::{CCSInstance, CCSWitness, SparseMatrix};
use nebu::Goldilocks as F;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ExecutionNoun {
    Atom(u64),
    Pair(Box<Self>, Box<Self>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectShape {
    Atom,
    Pair(Box<Self>, Box<Self>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelationError {
    Unsupported(&'static str),
    Malformed,
    NonCanonical,
    Limit,
    InputCount,
    SecretCount,
    LookupUnavailable,
}

#[derive(Clone, Debug)]
enum Value {
    Constant(F),
    Wire(usize),
    Pair(Box<Self>, Box<Self>),
}
type Linear = Vec<(usize, F)>;
#[derive(Clone, Debug)]
enum Op {
    Linear(Linear),
    Product(Linear, Linear),
    Inverse(Linear),
    Bit(Linear, usize),
    Secret(Linear),
    Look {
        active: Linear,
        root: [Linear; 4],
        namespace: Linear,
        key: Linear,
    },
}

/// Wire zero MUST be authenticated as one by the outer public-input protocol.
/// Input wires and returned output/cost wires MUST be bound under that SAME PCS.
#[derive(Clone, Debug)]
pub struct ExecutionRelation {
    pub instance: CCSInstance,
    pub input_indices: Vec<usize>,
    pub output_indices: Vec<usize>,
    pub output_shape: SubjectShape,
    pub cost_index: usize,
    pub max_cost: u64,
    pub lookups: Vec<LookupCoordinates>,
    ops: Vec<Op>,
}
impl ExecutionRelation {
    pub fn witness(&self, inputs: &[F]) -> Result<CCSWitness, RelationError> {
        self.witness_with_secrets(inputs, &[])
    }
    pub fn witness_with_secrets(
        &self,
        inputs: &[F],
        secrets: &[F],
    ) -> Result<CCSWitness, RelationError> {
        self.witness_with_provider(inputs, secrets, &mut |_, _, _| None)
    }
    pub fn witness_with_provider(
        &self,
        inputs: &[F],
        secrets: &[F],
        provider: &mut dyn FnMut([F; 4], F, F) -> Option<F>,
    ) -> Result<CCSWitness, RelationError> {
        if inputs.len() != self.input_indices.len() {
            return Err(RelationError::InputCount);
        }
        let mut secret_index = 0;
        let mut z = vec![F::ONE];
        z.extend_from_slice(inputs);
        for op in &self.ops {
            let eval = |l: &Linear| l.iter().fold(F::ZERO, |s, &(i, c)| s + z[i] * c);
            let v = match op {
                Op::Look {
                    active,
                    root,
                    namespace,
                    key,
                } => {
                    if eval(active) == F::ZERO {
                        F::ZERO
                    } else {
                        let root = std::array::from_fn(|i| eval(&root[i]));
                        let namespace = eval(namespace);
                        if namespace.as_u64() > 9 {
                            return Err(RelationError::LookupUnavailable);
                        }
                        provider(root, namespace, eval(key))
                            .ok_or(RelationError::LookupUnavailable)?
                    }
                }
                Op::Secret(active) => {
                    if eval(active) == F::ZERO {
                        F::ZERO
                    } else {
                        let v = *secrets
                            .get(secret_index)
                            .ok_or(RelationError::SecretCount)?;
                        secret_index += 1;
                        v
                    }
                }
                Op::Linear(a) => eval(a),
                Op::Product(a, b) => eval(a) * eval(b),
                Op::Bit(a, k) => F::new((eval(a).canonicalize().as_u64() >> k) & 1),
                Op::Inverse(a) => {
                    let v = eval(a);
                    if v == F::ZERO { F::ZERO } else { v.inv() }
                }
            };
            z.push(v);
        }
        if secret_index != secrets.len() {
            return Err(RelationError::SecretCount);
        }
        z.resize(self.instance.num_cols, F::ZERO);
        Ok(CCSWitness { z })
    }
}
struct Builder {
    inputs: usize,
    ops: Vec<Op>,
    rows: Vec<(Linear, Linear, Linear)>,
    calls: usize,
    active: Value,
    lookups: Vec<LookupCoordinates>,
    state: Option<PublicStateTables>,
}
const MAX_CALLS: usize = 4096;
const MAX_DEPTH: usize = 128;
impl Builder {
    fn wire(&mut self, op: Op) -> usize {
        let i = 1 + self.inputs + self.ops.len();
        self.ops.push(op);
        i
    }
    fn linear(&self, v: &Value) -> Result<Linear, RelationError> {
        match v {
            Value::Constant(c) => Ok(vec![(0, *c)]),
            Value::Wire(i) => Ok(vec![(*i, F::ONE)]),
            _ => Err(RelationError::Unsupported("atom required")),
        }
    }
    fn alloc_linear(&mut self, l: Linear) -> Value {
        let i = self.wire(Op::Linear(l.clone()));
        self.rows.push((l, vec![(0, F::ONE)], vec![(i, F::ONE)]));
        Value::Wire(i)
    }
    fn product(&mut self, a: Linear, b: Linear) -> Value {
        let i = self.wire(Op::Product(a.clone(), b.clone()));
        self.rows.push((a, b, vec![(i, F::ONE)]));
        Value::Wire(i)
    }
    fn add(&mut self, a: &Value, b: &Value, negative: bool) -> Result<Value, RelationError> {
        let mut l = self.linear(a)?;
        l.extend(
            self.linear(b)?
                .into_iter()
                .map(|(i, c)| (i, if negative { -c } else { c })),
        );
        Ok(self.alloc_linear(l))
    }
    fn nonzero(&mut self, v: &Value) -> Result<Value, RelationError> {
        let l = self.linear(v)?;
        let inv = self.wire(Op::Inverse(l.clone()));
        let s = self.product(l.clone(), vec![(inv, F::ONE)]);
        let mut one_minus = vec![(0, F::ONE)];
        one_minus.extend(self.linear(&s)?.into_iter().map(|(i, c)| (i, -c)));
        self.rows.push((l, one_minus.clone(), vec![]));
        self.rows.push((self.linear(&s)?, one_minus, vec![]));
        Ok(s)
    }
    fn mux(&mut self, s: &Value, yes: &Value, no: &Value) -> Result<Value, RelationError> {
        match (yes, no) {
            (Value::Pair(a, b), Value::Pair(c, d)) => Ok(Value::Pair(
                Box::new(self.mux(s, a, c)?),
                Box::new(self.mux(s, b, d)?),
            )),
            (Value::Pair(..), _) | (_, Value::Pair(..)) => {
                Err(RelationError::Unsupported("branch output shapes differ"))
            }
            _ => {
                let delta = self.add(no, yes, true)?;
                let p = self.product(self.linear(s)?, self.linear(&delta)?);
                self.add(yes, &p, false)
            }
        }
    }
    fn equal(&mut self, a: &Value, b: &Value) -> Result<Value, RelationError> {
        if !matches!(a, Value::Pair(..)) && !matches!(b, Value::Pair(..)) {
            let delta = self.add(a, b, true)?;
            return self.nonzero(&delta);
        }
        let left = self.structural_digest(a, 0)?;
        let right = self.structural_digest(b, 0)?;
        let mut unequal = Value::Constant(F::ZERO);
        for (a, b) in left.iter().zip(right.iter()) {
            let delta = self.add(a, b, true)?;
            let bit = self.nonzero(&delta)?;
            let both = self.product(self.linear(&unequal)?, self.linear(&bit)?);
            let sum = self.add(&unequal, &bit, false)?;
            unequal = self.add(&sum, &both, true)?;
        }
        Ok(unequal)
    }
    fn enforce_equal(&mut self, mut a: Linear, b: Linear) -> Result<(), RelationError> {
        a.extend(b.into_iter().map(|(i, c)| (i, -c)));
        self.rows.push((a, self.linear(&self.active)?, vec![]));
        Ok(())
    }
}

fn check_value(v: &Value, d: usize, count: &mut usize) -> Result<(), RelationError> {
    *count += 1;
    if d > MAX_DEPTH || *count > MAX_CALLS {
        return Err(RelationError::Limit);
    }
    if let Value::Pair(a, b) = v {
        check_value(a, d + 1, count)?;
        check_value(b, d + 1, count)?;
    }
    Ok(())
}
fn pair(n: &ExecutionNoun) -> Result<(&ExecutionNoun, &ExecutionNoun), RelationError> {
    match n {
        ExecutionNoun::Pair(a, b) => Ok((a, b)),
        _ => Err(RelationError::Malformed),
    }
}
fn constant(n: &ExecutionNoun, d: usize) -> Result<Value, RelationError> {
    if d > MAX_DEPTH {
        return Err(RelationError::Limit);
    }
    Ok(match n {
        ExecutionNoun::Atom(a) => Value::Constant(F::new(*a).canonicalize()),
        ExecutionNoun::Pair(a, b) => {
            Value::Pair(Box::new(constant(a, d + 1)?), Box::new(constant(b, d + 1)?))
        }
    })
}
fn static_noun(v: &Value, d: usize) -> Result<ExecutionNoun, RelationError> {
    if d > MAX_DEPTH {
        return Err(RelationError::Limit);
    }
    Ok(match v {
        Value::Constant(a) => ExecutionNoun::Atom(a.as_u64()),
        Value::Pair(a, b) => ExecutionNoun::Pair(
            Box::new(static_noun(a, d + 1)?),
            Box::new(static_noun(b, d + 1)?),
        ),
        _ => return Err(RelationError::Unsupported("dynamic continuation")),
    })
}
fn subject(s: &SubjectShape, next: &mut usize, d: usize) -> Result<Value, RelationError> {
    if d > MAX_DEPTH || *next > MAX_CALLS {
        return Err(RelationError::Limit);
    }
    Ok(match s {
        SubjectShape::Atom => {
            let i = *next;
            *next += 1;
            Value::Wire(i)
        }
        SubjectShape::Pair(a, b) => Value::Pair(
            Box::new(subject(a, next, d + 1)?),
            Box::new(subject(b, next, d + 1)?),
        ),
    })
}
fn outputs(
    b: &mut Builder,
    v: &Value,
    indices: &mut Vec<usize>,
) -> Result<SubjectShape, RelationError> {
    Ok(match v {
        Value::Pair(a, c) => SubjectShape::Pair(
            Box::new(outputs(b, a, indices)?),
            Box::new(outputs(b, c, indices)?),
        ),
        _ => {
            let w = b.alloc_linear(b.linear(v)?);
            if let Value::Wire(i) = w {
                indices.push(i)
            };
            SubjectShape::Atom
        }
    })
}
fn validate_program(n: &ExecutionNoun, d: usize, count: &mut usize) -> Result<(), RelationError> {
    *count += 1;
    if d > MAX_DEPTH || *count > MAX_CALLS {
        return Err(RelationError::Limit);
    }
    match n {
        ExecutionNoun::Atom(a) => {
            if F::new(*a).canonicalize().as_u64() != *a {
                Err(RelationError::NonCanonical)
            } else {
                Ok(())
            }
        }
        ExecutionNoun::Pair(a, b) => {
            validate_program(a, d + 1, count)?;
            validate_program(b, d + 1, count)
        }
    }
}
/// Compile solely from the public formula and public subject tree shape.
/// All possible costs are below the field modulus. Callers must bind the
/// selected cost as canonical public cycles and require cycles <= budget.
pub fn compile_relation(
    program: &ExecutionNoun,
    shape: &SubjectShape,
) -> Result<ExecutionRelation, RelationError> {
    compile_relation_internal(program, shape, None)
}
/// Public tables MUST have been authenticated against this root by the owner.
#[derive(Clone, Debug)]
pub struct PublicStateTables {
    pub root: [F; 4],
    pub dimensions: [Vec<F>; 10],
}
pub fn compile_relation_with_state(
    program: &ExecutionNoun,
    shape: &SubjectShape,
    state: &PublicStateTables,
) -> Result<ExecutionRelation, RelationError> {
    if state.dimensions.iter().map(Vec::len).sum::<usize>() > 2048 {
        return Err(RelationError::Limit);
    }
    compile_relation_internal(program, shape, Some(state.clone()))
}
fn compile_relation_internal(
    program: &ExecutionNoun,
    shape: &SubjectShape,
    state: Option<PublicStateTables>,
) -> Result<ExecutionRelation, RelationError> {
    validate_program(program, 0, &mut 0)?;
    let mut next = 1;
    let obj = subject(shape, &mut next, 0)?;
    let mut b = Builder {
        inputs: next - 1,
        ops: vec![],
        rows: vec![],
        calls: 0,
        active: Value::Constant(F::ONE),
        lookups: vec![],
        state,
    };
    let (value, cost, max_cost) = b.eval(&obj, program, 0)?;
    // Public cycles have an unambiguous integer interpretation. Bounding the
    // entire circuit below p prevents a selected cost from wrapping in F_p.
    if max_cost >= nebu::field::P {
        return Err(RelationError::Limit);
    }
    let mut output_indices = vec![];
    let output_shape = outputs(&mut b, &value, &mut output_indices)?;
    let cost_index = match b.alloc_linear(b.linear(&cost)?) {
        Value::Wire(i) => i,
        _ => unreachable!(),
    };
    let rows = b.rows.len().max(2).next_power_of_two();
    let cols = (next + b.ops.len()).max(64).next_power_of_two();
    let mut matrices = vec![SparseMatrix::new(rows, cols); 3];
    for (r, (a, c, d)) in b.rows.into_iter().enumerate() {
        matrices[0].entries[r] = a;
        matrices[1].entries[r] = c;
        matrices[2].entries[r] = d;
    }
    Ok(ExecutionRelation {
        instance: CCSInstance {
            matrices,
            multisets: vec![vec![0, 1], vec![2]],
            coeffs: vec![F::ONE, -F::ONE],
            num_rows: rows,
            num_cols: cols,
        },
        input_indices: (1..next).collect(),
        output_indices,
        output_shape,
        cost_index,
        max_cost,
        lookups: b.lookups,
        ops: b.ops,
    })
}

#[cfg(test)]
#[path = "relation_tests.rs"]
mod tests;

#[path = "relation_bits.rs"]
mod bits;

#[path = "hash.rs"]
mod hash;

#[path = "relation_eval.rs"]
mod eval;

#[path = "relation_look.rs"]
mod look;
pub use look::LookupCoordinates;
