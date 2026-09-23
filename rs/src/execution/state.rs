//! Public authenticated lookup coordinates in a verifier-derived execution CCS.
//! Lookup authentication belongs to the state owner and must precede verification.
use super::relation::{ExecutionRelation, SubjectShape, compile_relation};
use super::{DirectProof, ExecutionNoun, ExecutionStatement, proof};
use nebu::Goldilocks as F;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicLookup {
    pub active: bool,
    pub namespace: u64,
    pub key: u64,
    pub value: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateStatement {
    pub execution: ExecutionStatement,
    pub state_root: [u64; 4],
    pub context: [u8; 32],
    /// Compiler state ABI places the root in the subject head. Raw formulas
    /// may instead construct the root explicitly inside their program.
    pub root_in_subject: bool,
    #[cfg_attr(feature = "serde", serde(deserialize_with = "reads_wire"))]
    pub reads: Vec<PublicLookup>,
}
#[cfg(feature = "serde")]
fn reads_wire<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<PublicLookup>, D::Error> {
    super::statement_wire::bounded::<D, PublicLookup, 4096>(d)
}
impl StateStatement {
    pub(super) fn inputs(&self) -> Vec<F> {
        let mut input = Vec::new();
        if self.root_in_subject {
            input.extend(self.state_root.map(F::new));
        }
        input.extend(self.execution.inputs());
        input
    }
    fn relation(&self) -> Result<ExecutionRelation, String> {
        self.execution.validate_bounds()?;
        if self.state_root.iter().any(|&v| v >= nebu::field::P) || self.reads.len() > 4096 {
            return Err("invalid state execution bounds".into());
        }
        let mut shape = SubjectShape::Atom;
        for _ in &self.execution.public_input {
            shape = SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(shape));
        }
        if self.root_in_subject {
            let a = || Box::new(SubjectShape::Atom);
            let root = SubjectShape::Pair(
                a(),
                Box::new(SubjectShape::Pair(
                    a(),
                    Box::new(SubjectShape::Pair(a(), a())),
                )),
            );
            shape = SubjectShape::Pair(Box::new(root), Box::new(shape));
        }
        let relation = compile_relation(&self.execution.program_noun()?, &shape)
            .map_err(|e| format!("unsupported state execution relation: {e:?}"))?;
        Ok(relation)
    }
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut bytes = b"zheng-nox-public-state-execution-v1".to_vec();
        bytes.extend(self.execution.transcript_bytes());
        bytes.extend(self.context);
        for v in self.state_root {
            bytes.extend(v.to_le_bytes());
        }
        bytes.push(u8::from(self.root_in_subject));
        bytes.extend((self.reads.len() as u64).to_le_bytes());
        for r in &self.reads {
            bytes.push(u8::from(r.active));
            for v in [r.namespace, r.key, r.value] {
                bytes.extend(v.to_le_bytes());
            }
        }
        bytes
    }
    fn bindings(
        &self,
        relation: &ExecutionRelation,
        lookup: &mut dyn FnMut(u64, u64) -> Option<u64>,
    ) -> Result<Vec<(usize, F)>, String> {
        if self.reads.len() != relation.lookups.len() {
            return Err("state lookup count mismatch".into());
        }
        let mut coordinates = self
            .execution
            .bindings_with_inputs(relation, &self.inputs())?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let mut pin = |i, v| -> Result<(), String> {
            if coordinates
                .insert(i, F::new(v))
                .is_some_and(|old| old != F::new(v))
            {
                return Err("conflicting state execution bindings".into());
            }
            Ok(())
        };
        for (read, wires) in self.reads.iter().zip(&relation.lookups) {
            pin(wires.active, u64::from(read.active))?;
            if !read.active {
                if (read.namespace, read.key, read.value) != (0, 0, 0) {
                    return Err("inactive lookup carries data".into());
                }
                continue;
            }
            if read.namespace > 9
                || read.key >= nebu::field::P
                || read.value >= nebu::field::P
                || lookup(read.namespace, read.key) != Some(read.value)
            {
                return Err("state cell authentication failed".into());
            }
            for (i, value) in wires.root.iter().zip(self.state_root) {
                pin(*i, value)?;
            }
            pin(wires.namespace, read.namespace)?;
            pin(wires.key, read.key)?;
            pin(wires.value, read.value)?;
        }
        Ok(coordinates.into_iter().collect())
    }
    /// The callback MUST read authenticated values from this exact state_root.
    pub fn verify(
        &self,
        proof: &DirectProof,
        lookup: &mut dyn FnMut(u64, u64) -> Option<u64>,
    ) -> Result<(), String> {
        let relation = self.relation()?;
        let public = self.bindings(&relation, lookup)?;
        proof::verify(&relation.instance, proof, &self.transcript_bytes(), &public)
            .map_err(|e| e.to_string())
    }
}
/// Public only: the direct proof discloses all columns. No secret stream is taken.
pub fn prove_state_execution(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    state_root: [u64; 4],
    root_in_subject: bool,
    context: [u8; 32],
    lookup: &mut dyn FnMut(u64, u64) -> Option<u64>,
) -> Result<(StateStatement, DirectProof), String> {
    let mut statement = StateStatement {
        execution: ExecutionStatement {
            program: ExecutionStatement::encode_program(program)?,
            public_input: input.to_vec(),
            public_output: vec![],
            cycles: 0,
            budget,
        },
        state_root,
        context,
        root_in_subject,
        reads: vec![],
    };
    let relation = statement.relation()?;
    let witness = relation
        .witness_with_provider(&statement.inputs(), &[], &mut |root, ns, key| {
            if root.map(|v| v.as_u64()) != state_root {
                return None;
            }
            lookup(ns.as_u64(), key.as_u64())
                .filter(|&v| v < nebu::field::P)
                .map(F::new)
        })
        .map_err(|e| format!("state execution witness: {e:?}"))?;
    let value = |i: usize| witness.z[i].as_u64();
    statement.execution.public_output = relation.output_indices.iter().map(|&i| value(i)).collect();
    statement.execution.cycles = value(relation.cost_index);
    for wires in &relation.lookups {
        let active = value(wires.active) == 1;
        statement.reads.push(if active {
            PublicLookup {
                active,
                namespace: value(wires.namespace),
                key: value(wires.key),
                value: value(wires.value),
            }
        } else {
            PublicLookup {
                active: false,
                namespace: 0,
                key: 0,
                value: 0,
            }
        });
    }
    let public = statement.bindings(&relation, lookup)?;
    let proof = proof::prove(
        &relation.instance,
        &witness,
        &statement.transcript_bytes(),
        &public,
    )
    .map_err(|e| e.to_string())?;
    Ok((statement, proof))
}
