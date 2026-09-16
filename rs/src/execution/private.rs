//! Private witness preparation, independent of the cryptographic proof backend.
use super::relation::ExecutionRelation;
use super::{ExecutionNoun, ExecutionStatement};
use nebu::Goldilocks as F;

/// Contains public values only. Witness length and values are not serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateStatement {
    pub execution: ExecutionStatement,
}

/// Public verifier data derived solely from the statement's canonical program.
pub struct PreparedExecution {
    pub relation: ExecutionRelation,
    pub public_coordinates: Vec<(usize, u64)>,
}

impl PrivateStatement {
    pub fn prepare(&self) -> Result<PreparedExecution, String> {
        let relation = self.execution.relation()?;
        let public_coordinates = self
            .execution
            .bindings(&relation)?
            .into_iter()
            .map(|(i, v)| (i, v.as_u64()))
            .collect();
        Ok(PreparedExecution {
            relation,
            public_coordinates,
        })
    }
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut bytes = b"zheng-nox-private-ccs-execution-v1".to_vec();
        bytes.extend(self.execution.transcript_bytes());
        bytes
    }
}

/// Compute private columns on the prover; callers must prove the returned
/// verifier-derived relation and bind the complete public statement.
pub fn prepare_execution(
    program: &ExecutionNoun,
    input: &[u64],
    secrets: &[u64],
    budget: u64,
) -> Result<(PrivateStatement, PreparedExecution, Vec<u64>), String> {
    if secrets.len() > 4096 || secrets.iter().any(|&v| v >= nebu::field::P) {
        return Err("invalid private input bounds or field encoding".into());
    }
    let mut execution = ExecutionStatement {
        program: ExecutionStatement::encode_program(program)?,
        public_input: input.to_vec(),
        public_output: vec![],
        cycles: 0,
        budget,
    };
    let relation = execution.relation()?;
    let secrets = secrets.iter().map(|&v| F::new(v)).collect::<Vec<_>>();
    let witness = relation
        .witness_with_secrets(&execution.inputs(), &secrets)
        .map_err(|_| "private execution witness stream does not match the program")?;
    if !relation.instance.is_satisfied_by(&witness) {
        return Err("private execution constraints failed".into());
    }
    execution.public_output = relation
        .output_indices
        .iter()
        .map(|&i| witness.z[i].as_u64())
        .collect();
    execution.cycles = witness.z[relation.cost_index].as_u64();
    let statement = PrivateStatement { execution };
    let prepared = statement.prepare()?;
    Ok((
        statement,
        prepared,
        witness.z.iter().map(|v| v.as_u64()).collect(),
    ))
}
