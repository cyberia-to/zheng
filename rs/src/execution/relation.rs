//! Bounded symbolic nox execution, with shared wires for all data movement.
//!
//! This is a restricted public-input circuit, not the complete nox VM. Dynamic
//! continuations, state, calls and mismatched branch shapes fail closed.
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
    ops: Vec<Op>,
}
impl ExecutionRelation {
    pub fn witness(&self, inputs: &[F]) -> Result<CCSWitness, RelationError> {
        if inputs.len() != self.input_indices.len() {
            return Err(RelationError::InputCount);
        }
        let mut z = vec![F::ONE];
        z.extend_from_slice(inputs);
        for op in &self.ops {
            let eval = |l: &Linear| l.iter().fold(F::ZERO, |s, &(i, c)| s + z[i] * c);
            let v = match op {
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
        z.resize(self.instance.num_cols, F::ZERO);
        Ok(CCSWitness { z })
    }
}
struct Builder {
    inputs: usize,
    ops: Vec<Op>,
    rows: Vec<(Linear, Linear, Linear)>,
    calls: usize,
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
    fn eval(
        &mut self,
        obj: &Value,
        f: &ExecutionNoun,
        depth: usize,
    ) -> Result<(Value, Value, u64), RelationError> {
        if self.ops.len() > 32768 || self.rows.len() > 32768 {
            return Err(RelationError::Limit);
        }
        let result = self.eval_inner(obj, f, depth)?;
        check_value(&result.0, 0, &mut 0)?;
        if self.ops.len() > 32768 || self.rows.len() > 32768 {
            return Err(RelationError::Limit);
        }
        Ok(result)
    }
    fn eval_inner(
        &mut self,
        obj: &Value,
        f: &ExecutionNoun,
        depth: usize,
    ) -> Result<(Value, Value, u64), RelationError> {
        self.calls += 1;
        if self.calls > MAX_CALLS || depth > MAX_DEPTH {
            return Err(RelationError::Limit);
        }
        let (tag, body) = pair(f)?;
        let tag = match tag {
            ExecutionNoun::Atom(t) => *t,
            _ => return Err(RelationError::Malformed),
        };
        let one = Value::Constant(F::ONE);
        match tag {
            0 => {
                let a = match body {
                    ExecutionNoun::Atom(a) => *a,
                    _ => return Err(RelationError::Malformed),
                };
                if a == 0 {
                    return Ok((self.axis_hash(obj)?, one, 1));
                }
                let mut v = obj;
                let bits = 63 - a.leading_zeros();
                for b in (0..bits).rev() {
                    v = match v {
                        Value::Pair(l, r) => {
                            if (a >> b) & 1 == 0 {
                                l
                            } else {
                                r
                            }
                        }
                        _ => return Err(RelationError::Unsupported("axis into atom")),
                    };
                }
                Ok((v.clone(), one, 1))
            }
            1 => Ok((constant(body, depth + 1)?, one, 1)),
            15 => {
                let (v, c, m) = self.eval(obj, body, depth + 1)?;
                let out = self.hash(&v)?;
                let cost = self.add(&c, &Value::Constant(F::new(25)), false)?;
                Ok((out, cost, m + 25))
            }
            13 => {
                let (v, c, m) = self.eval(obj, body, depth + 1)?;
                let bits = self.bits(&v, 32)?;
                let word = self.pack(&bits)?;
                let out = self.add(&Value::Constant(F::new(u32::MAX as u64)), &word, true)?;
                let cost = self.add(&c, &Value::Constant(F::new(32)), false)?;
                Ok((out, cost, m + 32))
            }
            8 => {
                let (v, c, m) = self.eval(obj, body, depth + 1)?;
                let a = self.linear(&v)?;
                let i = self.wire(Op::Inverse(a.clone()));
                self.rows.push((a, vec![(i, F::ONE)], vec![(0, F::ONE)]));
                let cost = self.add(&c, &Value::Constant(F::new(64)), false)?;
                Ok((Value::Wire(i), cost, m + 64))
            }
            2 | 3 | 5 | 6 | 7 | 9 | 10 | 11 | 12 | 14 => {
                let (a, b) = pair(body)?;
                let (av, ac, am) = self.eval(obj, a, depth + 1)?;
                let (bv, bc, bm) = self.eval(obj, b, depth + 1)?;
                let own_cost = if tag == 10 {
                    64
                } else if tag >= 11 {
                    32
                } else {
                    1
                };
                let ab = self.add(&ac, &bc, false)?;
                let mut cost = self.add(&Value::Constant(F::new(own_cost)), &ab, false)?;
                let mut max = own_cost + am + bm;
                let value = match tag {
                    2 => {
                        let continuation = static_noun(&bv, depth + 1)?;
                        let (v, c, m) = self.eval(&av, &continuation, depth + 1)?;
                        cost = self.add(&cost, &c, false)?;
                        max += m;
                        v
                    }
                    3 => Value::Pair(Box::new(av), Box::new(bv)),
                    5 | 6 => self.add(&av, &bv, tag == 6)?,
                    7 => self.product(self.linear(&av)?, self.linear(&bv)?),
                    9 => {
                        let diff = self.add(&av, &bv, true)?;
                        self.nonzero(&diff)?
                    }
                    10 => self.less_than(&av, &bv)?,
                    11 | 12 | 14 => self.word_binary(tag, &av, &bv)?,
                    _ => unreachable!(),
                };
                Ok((value, cost, max))
            }
            4 => {
                let (t, arms) = pair(body)?;
                let (a, b) = pair(arms)?;
                let (tv, tc, tm) = self.eval(obj, t, depth + 1)?;
                let s = self.nonzero(&tv)?;
                let (av, ac, am) = self.eval(obj, a, depth + 1)?;
                let (bv, bc, bm) = self.eval(obj, b, depth + 1)?;
                let value = self.mux(&s, &av, &bv)?;
                let arm = self.mux(&s, &ac, &bc)?;
                let c = self.add(&tc, &arm, false)?;
                let c = self.add(&one, &c, false)?;
                Ok((value, c, 1 + tm + am.max(bm)))
            }
            _ => Err(RelationError::Unsupported(
                "pattern requires an execution gadget",
            )),
        }
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
/// Caller must require budget >= max_cost and bind every public coordinate.
pub fn compile_relation(
    program: &ExecutionNoun,
    shape: &SubjectShape,
) -> Result<ExecutionRelation, RelationError> {
    validate_program(program, 0, &mut 0)?;
    let mut next = 1;
    let obj = subject(shape, &mut next, 0)?;
    let mut b = Builder {
        inputs: next - 1,
        ops: vec![],
        rows: vec![],
        calls: 0,
    };
    let (value, cost, max_cost) = b.eval(&obj, program, 0)?;
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
