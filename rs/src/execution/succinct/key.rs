//! A proving key for the one-relation profile: what a prover derives once
//! per program and input count and reuses across proofs of the same
//! statement shape — the compiled relation and its verifying key, the
//! column layout and the relabelled relation. A device that proves the
//! same statement type repeatedly (tickets, membership, tips) holds one;
//! the proof is the one [`super::prove_with`] makes (same bytes).

use nebu::Goldilocks;

use super::protocol::{self, Layout};
use super::{SuccinctProof, Whir, WhirParams, keyed_statement, with_constant};
use crate::envelope::AnySuccinct;
use crate::execution::{ExecutionNoun, ExecutionStatement, VerifyingKey};
use crate::types::CCSInstance;

/// The one-relation profile's prover state for one program and input count.
pub struct ProvingKey {
    vk: VerifyingKey,
    /// pinned columns, `(0, ·)` first, in the order the layout assigns slots
    pinned: Vec<usize>,
    layout: Layout,
    relabelled: CCSInstance,
}

impl ProvingKey {
    /// Compile `program` for `inputs` public inputs.
    pub fn new(program: &ExecutionNoun, inputs: usize) -> Result<Self, String> {
        let shape = ExecutionStatement {
            program: ExecutionStatement::encode_program(program)?,
            public_input: vec![0; inputs],
            public_output: vec![],
            cycles: 0,
            budget: 0,
        };
        let relation = shape.relation()?;
        let skeleton = ExecutionStatement {
            public_output: vec![0; relation.output_indices.len()],
            ..shape
        };
        let pins = with_constant(skeleton.bindings(&relation)?);
        let vk = VerifyingKey::new(skeleton.program_key(), relation);
        let layout = Layout::new(&vk.relation().instance, &pins)?;
        let relabelled = layout.instance(&vk.relation().instance);
        let pinned = pins.iter().map(|&(i, _)| i).collect();
        Ok(Self { vk, pinned, layout, relabelled })
    }

    /// The verifying key this proving key carries.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }

    /// Committed variables of the relation.
    pub fn vars(&self) -> usize {
        self.layout.vars
    }
}

/// [`super::prove_with`] with a held key: no relation compile, no key
/// digest, no relabelling. The program and input count must be the key's.
pub fn prove_with_key(
    key: &ProvingKey,
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    choose: impl Fn(usize) -> WhirParams,
) -> Result<(ExecutionStatement, AnySuccinct), String> {
    let mut statement = ExecutionStatement {
        program: ExecutionStatement::encode_program(program)?,
        public_input: input.to_vec(),
        public_output: vec![],
        cycles: 0,
        budget,
    };
    if statement.program_key() != key.vk.program_key() {
        return Err("proving key was derived for another program or input count".into());
    }
    let relation = key.vk.relation();
    let witness = relation
        .witness(&statement.inputs())
        .map_err(|e| format!("execution witness: {e:?}"))?;
    statement.public_output = relation.output_indices.iter().map(|&i| witness.z[i].as_u64()).collect();
    statement.cycles = witness.z[relation.cost_index].as_u64();
    if statement.cycles > budget {
        return Err("execution cost exceeds budget".into());
    }
    let pins = with_constant(statement.bindings(relation)?);
    if pins.len() != key.pinned.len() || pins.iter().zip(&key.pinned).any(|(&(i, _), &j)| i != j) {
        return Err("succinct: pinned coordinates differ from the key's".into());
    }
    if witness.z.len() != relation.instance.num_cols || pins.iter().any(|&(i, v)| witness.z[i] != v) {
        return Err("succinct: witness disagrees with the statement".into());
    }
    let layout = Layout {
        vars: key.layout.vars,
        map: key.layout.map.clone(),
        public: pins.iter().enumerate().map(|(slot, &(_, v))| (slot, v)).collect::<Vec<(usize, Goldilocks)>>(),
    };
    let proof: SuccinctProof<Whir> = protocol::prove_laid_out(
        &choose(layout.vars),
        &layout,
        &key.relabelled,
        &witness.z,
        &keyed_statement(&key.vk, &statement.transcript_bytes()),
    )?;
    Ok((statement, proof.into()))
}

/// A proving key for a relation the caller built itself (not compiled from
/// a program): the column layout and the relabelled relation, which depend
/// on the pinned positions only. [`prove_relation_with_key`] makes the
/// proof [`super::prove_relation`] makes (same bytes).
pub struct RelationKey {
    layout: Layout,
    relabelled: CCSInstance,
    pinned: Vec<usize>,
    num_cols: usize,
}

impl RelationKey {
    /// `pinned`: the pinned columns in increasing order, column 0 (the
    /// constant one) first.
    pub fn new(instance: &CCSInstance, pinned: &[usize]) -> Result<Self, String> {
        let pins: Vec<(usize, Goldilocks)> = pinned
            .iter()
            .map(|&i| (i, if i == 0 { Goldilocks::ONE } else { Goldilocks::ZERO }))
            .collect();
        let layout = Layout::new(instance, &pins)?;
        let relabelled = layout.instance(instance);
        Ok(Self { layout, relabelled, pinned: pinned.to_vec(), num_cols: instance.num_cols })
    }

    /// Committed variables of the relation.
    pub fn vars(&self) -> usize {
        self.layout.vars
    }
}

/// [`super::prove_relation`] with a held [`RelationKey`]: `pins` must name
/// the key's columns, `(0, 1)` first, with this statement's values, and
/// `z` must agree with them.
pub fn prove_relation_with_key<P: super::SuccinctPcs>(
    params: &P::Params,
    key: &RelationKey,
    z: &[Goldilocks],
    pins: &[(usize, Goldilocks)],
    statement: &[u8],
) -> Result<SuccinctProof<P>, String> {
    if pins.len() != key.pinned.len()
        || pins.iter().zip(&key.pinned).any(|(&(i, _), &j)| i != j)
        || pins.first() != Some(&(0, Goldilocks::ONE))
    {
        return Err("succinct: pinned coordinates differ from the key's".into());
    }
    if z.len() != key.num_cols || pins.iter().any(|&(i, v)| z[i] != v) {
        return Err("succinct: witness disagrees with the statement".into());
    }
    let layout = Layout {
        vars: key.layout.vars,
        map: key.layout.map.clone(),
        public: pins.iter().enumerate().map(|(slot, &(_, v))| (slot, v)).collect(),
    };
    protocol::prove_laid_out(params, &layout, &key.relabelled, z, statement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, SuccinctStatement};
    use crate::execution::ExecutionNoun as N;

    fn parse(text: &str) -> N {
        fn go(t: &[u8], i: &mut usize) -> N {
            while t[*i] == b' ' {
                *i += 1;
            }
            if t[*i] == b'[' {
                *i += 1;
                let mut items = vec![];
                loop {
                    while t[*i] == b' ' {
                        *i += 1;
                    }
                    if t[*i] == b']' {
                        *i += 1;
                        break;
                    }
                    items.push(go(t, i));
                }
                let mut it = items.into_iter().rev();
                let mut acc = it.next().expect("non-empty cell");
                for x in it {
                    acc = N::Pair(Box::new(x), Box::new(acc));
                }
                acc
            } else {
                let start = *i;
                while t[*i].is_ascii_digit() {
                    *i += 1;
                }
                N::Atom(std::str::from_utf8(&t[start..*i]).unwrap().parse().unwrap())
            }
        }
        go(text.as_bytes(), &mut 0)
    }

    // hash.tri: hash(a, 0⁷)
    const HASH: &str = "[2 [[3 [[4 [[9 [[0 3] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [1 0]]] [1 [15 [3 [[0 2] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [1 0]]]]]]]]]]]]]]]]]]]]]]]]]]]";

    #[test]
    fn a_held_key_proves_the_same_bytes_and_refuses_other_programs() {
        let program = parse(HASH);
        let key = ProvingKey::new(&program, 1).unwrap();
        for x in [7u64, 9, 0] {
            let (s1, p1) = super::super::prove_default(&program, &[x], 1_000_000).unwrap();
            let (s2, p2) = prove_with_key(&key, &program, &[x], 1_000_000, super::super::device_params).unwrap();
            let e1 = Envelope::Succinct { statement: SuccinctStatement::Execution(s1), proof: p1 };
            let e2 = Envelope::Succinct { statement: SuccinctStatement::Execution(s2), proof: p2 };
            assert_eq!(e1.to_bytes(), e2.to_bytes());
            e2.verify(None).unwrap();
        }
        assert!(prove_with_key(&key, &program, &[7, 8], 1_000_000, super::super::device_params).is_err());
        // a caller-built relation: the held relation key proves the same
        // bytes as prove_relation, verifies, decodes from its bytes
        let (statement, relation, witness, public) =
            crate::execution::statement::prepare(&program, &[9], 1_000_000).unwrap();
        let pins = with_constant(public);
        let indices: Vec<usize> = pins.iter().map(|&(i, _)| i).collect();
        let rk = RelationKey::new(&relation.instance, &indices).unwrap();
        let params = super::super::device_params(rk.vars());
        let bytes = statement.transcript_bytes();
        let a = super::super::prove_relation::<Whir>(&params, &relation.instance, &witness.z, &pins, &bytes).unwrap();
        let b = prove_relation_with_key::<Whir>(&params, &rk, &witness.z, &pins, &bytes).unwrap();
        let (ea, eb) = (crate::envelope::succinct_proof_bytes(&a.into()), crate::envelope::succinct_proof_bytes(&b.into()));
        assert_eq!(ea, eb);
        let decoded = crate::envelope::succinct_proof_from_bytes(&eb).unwrap();
        let crate::envelope::AnySuccinct::Whir(d) = decoded else { panic!("whir") };
        super::super::verify_relation(&relation.instance, &pins, &bytes, &d).unwrap();
        let mut bad = eb.clone();
        bad.push(0);
        assert!(crate::envelope::succinct_proof_from_bytes(&bad).is_err());
        let mut wrong = pins.clone();
        wrong.pop();
        assert!(prove_relation_with_key::<Whir>(&params, &rk, &witness.z, &wrong, &bytes).is_err());
        let other = parse("[0 2]");
        assert!(prove_with_key(&key, &other, &[7], 1_000_000, super::super::device_params).is_err());
    }
}
