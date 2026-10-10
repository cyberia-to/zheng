//! Private queries selected inside the CCS from authenticated public state tables.
//!
//! Every entry point takes the reads' `StateEvidence` and authenticates it
//! itself under the statement's own `root` (`StateEvidence::private_tables`:
//! the leaves fold to the root, every table matches its leaf, all ten
//! public namespaces present) before the tables become relation constants.
//! No caller authenticates anything on zheng's behalf.
use super::private::PreparedExecution;
use super::relation::{
    ExecutionRelation, PublicStateTables, SubjectShape, compile_relation_with_state,
};
use super::state_evidence::StateEvidence;
use super::veil::{self, VeilProof};
use super::zk::{self, PrivateProof};
use super::{ExecutionNoun, ExecutionStatement, state::StateStatement};
use nebu::Goldilocks as F;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateStateStatement {
    pub execution: ExecutionStatement,
    pub root: [u64; 4],
    pub root_in_subject: bool,
}
impl PrivateStateStatement {
    fn state_statement(&self) -> StateStatement {
        StateStatement {
            execution: self.execution.clone(),
            state_root: self.root,
            root_in_subject: self.root_in_subject,
            reads: vec![],
        }
    }
    fn relation(&self, tables: &PublicStateTables) -> Result<ExecutionRelation, String> {
        self.execution.validate_bounds()?;
        if self.root.iter().any(|&v| v >= nebu::field::P) || tables.root() != self.root {
            return Err("private state root mismatch".into());
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
        let relation = compile_relation_with_state(&self.execution.program_noun()?, &shape, tables)
            .map_err(|e| format!("unsupported private state relation: {e:?}"))?;
        Ok(relation)
    }
    /// Authenticate `evidence` under this statement's root and derive the
    /// relation and public coordinates from it.
    pub fn prepare(&self, evidence: &StateEvidence) -> Result<PreparedExecution, String> {
        let tables = evidence.private_tables(self.root)?;
        self.prepare_tables(&tables)
    }
    fn prepare_tables(&self, tables: &PublicStateTables) -> Result<PreparedExecution, String> {
        let relation = self.relation(tables)?;
        let state = self.state_statement();
        let public_coordinates = self
            .execution
            .bindings_with_inputs(&relation, &state.inputs())?
            .into_iter()
            .map(|(i, v)| (i, v.as_u64()))
            .collect();
        Ok(PreparedExecution {
            relation,
            public_coordinates,
        })
    }
}
impl PrivateStateStatement {
    /// Verify a veil proof made under `statement` bytes, after
    /// authenticating `evidence` under this statement's root.
    pub fn verify_veil(
        &self,
        evidence: &StateEvidence,
        proof: &VeilProof,
        statement: &[u8],
    ) -> Result<(), String> {
        let prepared = self.prepare(evidence)?;
        veil::verify_relation(&prepared.relation.instance, proof, statement, &coordinates(&prepared))
    }
    /// Verify a MITH proof made under `statement` bytes, after
    /// authenticating `evidence` under this statement's root.
    pub fn verify_mith(
        &self,
        evidence: &StateEvidence,
        proof: &PrivateProof,
        statement: &[u8],
    ) -> Result<(), String> {
        let prepared = self.prepare(evidence)?;
        zk::verify(&prepared.relation.instance, proof, statement, &coordinates(&prepared))
            .map_err(|e| e.to_string())
    }
}

fn coordinates(prepared: &PreparedExecution) -> Vec<(usize, F)> {
    prepared.public_coordinates.iter().map(|&(i, v)| (i, F::new(v))).collect()
}

/// All ten public dimensions are fixed by the verifier before witness generation.
/// Actual query coordinates and returned values remain private CCS columns.
/// The statement's root is the root `evidence` authenticates.
pub fn prepare_execution(
    program: &ExecutionNoun,
    input: &[u64],
    secrets: &[u64],
    budget: u64,
    root_in_subject: bool,
    evidence: &StateEvidence,
) -> Result<(PrivateStateStatement, PreparedExecution, Vec<u64>), String> {
    let tables = evidence.private_tables(evidence.root()?)?;
    let tables = &tables;
    if secrets.len() > 4096 || secrets.iter().any(|&v| v >= nebu::field::P) {
        return Err("invalid private witness stream".into());
    }
    let mut statement = PrivateStateStatement {
        execution: ExecutionStatement {
            program: ExecutionStatement::encode_program(program)?,
            public_input: input.to_vec(),
            public_output: vec![],
            cycles: 0,
            budget,
        },
        root: tables.root.map(|v| v.as_u64()),
        root_in_subject,
    };
    let relation = statement.relation(tables)?;
    let state = statement.state_statement();
    let secrets = secrets.iter().map(|&v| F::new(v)).collect::<Vec<_>>();
    let witness = relation
        .witness_with_provider(&state.inputs(), &secrets, &mut |root, ns, key| {
            if root != tables.root {
                return None;
            }
            tables
                .dimensions
                .get(usize::try_from(ns.as_u64()).ok()?)?
                .get(usize::try_from(key.as_u64()).ok()?)
                .copied()
        })
        .map_err(|_| "private state witness failed")?;
    if !relation.instance.is_satisfied_by(&witness) {
        return Err("private state constraints failed".into());
    }
    statement.execution.public_output = relation
        .output_indices
        .iter()
        .map(|&i| witness.z[i].as_u64())
        .collect();
    statement.execution.cycles = witness.z[relation.cost_index].as_u64();
    let prepared = statement.prepare_tables(tables)?;
    Ok((
        statement,
        prepared,
        witness.z.iter().map(|v| v.as_u64()).collect(),
    ))
}
