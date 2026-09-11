//! Canonical, bounded public statements; no trace or prover-defined matrices.
use super::relation::{ExecutionNoun, ExecutionRelation, SubjectShape, compile_relation};
use super::{DirectProof, proof};
use nebu::Goldilocks as F;
use std::collections::BTreeMap;

pub const MAX_PROGRAM_NODES: usize = 4096;
pub const MAX_DEPTH: usize = 128;
pub const MAX_INPUTS: usize = 64;
pub const MAX_OUTPUTS: usize = 4096;

/// Flat prefix encoding avoids recursive untrusted deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NounToken {
    Atom(u64),
    Pair,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecutionStatement {
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "super::statement_wire::program")
    )]
    pub program: Vec<NounToken>,
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "super::statement_wire::inputs")
    )]
    pub public_input: Vec<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "super::statement_wire::outputs")
    )]
    pub public_output: Vec<u64>,
    pub cycles: u64,
    pub budget: u64,
}

fn canonical(values: &[u64]) -> bool {
    values.iter().all(|&v| v < nebu::field::P)
}

impl ExecutionStatement {
    pub fn program_noun(&self) -> Result<ExecutionNoun, String> {
        if self.program.is_empty() || self.program.len() > MAX_PROGRAM_NODES {
            return Err("program size limit".into());
        }
        let mut stack: Vec<(ExecutionNoun, usize)> = Vec::new();
        for token in self.program.iter().rev() {
            match token {
                NounToken::Atom(v) => {
                    if *v >= nebu::field::P {
                        return Err("noncanonical program atom".into());
                    }
                    stack.push((ExecutionNoun::Atom(*v), 0));
                }
                NounToken::Pair => {
                    let (a, da) = stack.pop().ok_or("malformed program prefix")?;
                    let (b, db) = stack.pop().ok_or("malformed program prefix")?;
                    let depth = 1 + da.max(db);
                    if depth > MAX_DEPTH {
                        return Err("program depth limit".into());
                    }
                    stack.push((ExecutionNoun::Pair(Box::new(a), Box::new(b)), depth));
                }
            }
        }
        if stack.len() != 1 {
            return Err("trailing program tokens".into());
        }
        stack
            .pop()
            .map(|(n, _)| n)
            .ok_or_else(|| "empty program".into())
    }

    fn relation(&self) -> Result<ExecutionRelation, String> {
        if self.public_input.len() > MAX_INPUTS
            || self.public_output.len() > MAX_OUTPUTS
            || !canonical(&self.public_input)
            || !canonical(&self.public_output)
            || self.budget >= nebu::field::P
            || self.cycles > self.budget
        {
            return Err("invalid public statement bounds or field values".into());
        }
        let mut shape = SubjectShape::Atom;
        for _ in &self.public_input {
            shape = SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(shape));
        }
        let relation = compile_relation(&self.program_noun()?, &shape)
            .map_err(|e| format!("unsupported execution relation: {e:?}"))?;
        if self.budget < relation.max_cost {
            return Err(format!(
                "budget must cover conservative bound {}",
                relation.max_cost
            ));
        }
        Ok(relation)
    }

    fn inputs(&self) -> Vec<F> {
        self.public_input
            .iter()
            .rev()
            .map(|&v| F::new(v))
            .chain([F::ZERO])
            .collect()
    }

    fn bindings(&self, relation: &ExecutionRelation) -> Result<Vec<(usize, F)>, String> {
        if self.public_output.len() != relation.output_indices.len() {
            return Err("output shape does not match program".into());
        }
        let mut result = BTreeMap::new();
        for (i, v) in relation
            .input_indices
            .iter()
            .copied()
            .zip(self.inputs())
            .chain(
                relation
                    .output_indices
                    .iter()
                    .copied()
                    .zip(self.public_output.iter().map(|&v| F::new(v))),
            )
            .chain([(relation.cost_index, F::new(self.cycles))])
        {
            if result.insert(i, v).is_some_and(|old| old != v) {
                return Err("conflicting public coordinates".into());
            }
        }
        Ok(result.into_iter().collect())
    }

    /// Stable encoding independent of serde, usize width and JSON formatting.
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut bytes = b"zheng-nox-public-execution-v1".to_vec();
        bytes.extend_from_slice(&(self.program.len() as u64).to_le_bytes());
        for token in &self.program {
            match token {
                NounToken::Atom(v) => {
                    bytes.push(0);
                    bytes.extend_from_slice(&v.to_le_bytes());
                }
                NounToken::Pair => bytes.push(1),
            }
        }
        for values in [&self.public_input, &self.public_output] {
            bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
            for v in values {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&self.cycles.to_le_bytes());
        bytes.extend_from_slice(&self.budget.to_le_bytes());
        bytes
    }

    pub fn encode_program(noun: &ExecutionNoun) -> Result<Vec<NounToken>, String> {
        let mut tokens = Vec::new();
        let mut pending = vec![(noun, 0)];
        while let Some((node, depth)) = pending.pop() {
            if depth > MAX_DEPTH || tokens.len() >= MAX_PROGRAM_NODES {
                return Err("program size/depth limit".into());
            }
            match node {
                ExecutionNoun::Atom(v) => {
                    if *v >= nebu::field::P {
                        return Err("noncanonical program atom".into());
                    }
                    tokens.push(NounToken::Atom(*v));
                }
                ExecutionNoun::Pair(a, b) => {
                    tokens.push(NounToken::Pair);
                    pending.push((b, depth + 1));
                    pending.push((a, depth + 1));
                }
            }
        }
        Ok(tokens)
    }
}

/// Input values are public. Secret-input proving is deliberately a separate,
/// unavailable protocol until witness-hiding constraints/PCS are reviewed.
pub fn prove_execution(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
) -> Result<(ExecutionStatement, DirectProof), String> {
    let mut statement = ExecutionStatement {
        program: ExecutionStatement::encode_program(program)?,
        public_input: input.to_vec(),
        public_output: vec![],
        cycles: 0,
        budget,
    };
    let relation = statement.relation()?;
    let witness = relation
        .witness(&statement.inputs())
        .map_err(|e| format!("execution witness: {e:?}"))?;
    statement.public_output = relation
        .output_indices
        .iter()
        .map(|&i| witness.z[i].as_u64())
        .collect();
    statement.cycles = witness.z[relation.cost_index].as_u64();
    if statement.cycles > budget {
        return Err("execution cost exceeds budget".into());
    }
    let public = statement.bindings(&relation)?;
    let proof = proof::prove(
        &relation.instance,
        &witness,
        &statement.transcript_bytes(),
        &public,
    )
    .map_err(|e| e.to_string())?;
    Ok((statement, proof))
}

/// Derives the full relation and verifies the claimed public values. This does
/// not run nox, construct a witness, or accept a supplied execution trace.
pub fn verify_execution(statement: &ExecutionStatement, proof: &DirectProof) -> Result<(), String> {
    let relation = statement.relation()?;
    proof::verify(
        &relation.instance,
        proof,
        &statement.transcript_bytes(),
        &statement.bindings(&relation)?,
    )
    .map_err(|e| e.to_string())
}
