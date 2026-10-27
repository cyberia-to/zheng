//! A held proving key for veil-W, as veil's (`veil::key`): the compiled
//! relation and its verifying key, the masked relation in the compact
//! layout, the relabelled masked relation, the WHIR parameters and the
//! slot layout. Each proof still draws fresh coins; a keyed proof equals
//! the unkeyed one under equal coins (`tests`).

use lens::WhirParams;
use nebu::Goldilocks;

use super::super::coins::Coins;
use super::super::protocol::Setup;
use super::super::with_constant;
use super::layout::Slots;
use super::{SmallProof, choose, protocol};
use crate::execution::private::PrivateStatement;
use crate::execution::{ExecutionNoun, ExecutionStatement, VerifyingKey};
use crate::types::CCSInstance;

/// veil-W's prover state for one program and input count.
pub struct ProvingKey {
    vk: VerifyingKey,
    pinned: Vec<usize>,
    setup: Setup,
    relabelled: CCSInstance,
    params: WhirParams,
    slots: Slots,
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
        let pins = with_constant(&skeleton.bindings(&relation)?);
        let vk = VerifyingKey::new(skeleton.program_key(), relation);
        let setup = Setup::compact(&vk.relation().instance, &pins)?;
        let (params, slots) = choose(&setup)?;
        super::admit(&params, &setup)?;
        let relabelled = setup.layout.instance(&setup.instance);
        let pinned = pins.iter().map(|&(i, _)| i).collect();
        Ok(Self { vk, pinned, setup, relabelled, params, slots })
    }

    /// The verifying key (pass it to [`super::verify_with`]).
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// [`super::prove`] with a held key and fresh OS coins.
pub fn prove_with_key(
    key: &ProvingKey,
    program: &ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
) -> Result<(PrivateStatement, SmallProof), String> {
    prove_keyed(key, program, input, secret, budget, &Coins::os()?)
}

pub(crate) fn prove_keyed(
    key: &ProvingKey,
    program: &ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
    coins: &Coins,
) -> Result<(PrivateStatement, SmallProof), String> {
    if secret.len() > 4096 || secret.iter().any(|&v| v >= nebu::field::P) {
        return Err("invalid private input bounds or field encoding".into());
    }
    let mut execution = ExecutionStatement {
        program: ExecutionStatement::encode_program(program)?,
        public_input: input.to_vec(),
        public_output: vec![],
        cycles: 0,
        budget,
    };
    if execution.program_key() != key.vk.program_key() {
        return Err("proving key was derived for another program or input count".into());
    }
    let relation = key.vk.relation();
    let secrets: Vec<Goldilocks> = secret.iter().map(|&v| Goldilocks::new(v)).collect();
    let witness = relation
        .witness_with_secrets(&execution.inputs(), &secrets)
        .map_err(|_| "private execution witness stream does not match the program")?;
    if !relation.instance.is_satisfied_by(&witness) {
        return Err("private execution constraints failed".into());
    }
    execution.public_output = relation.output_indices.iter().map(|&i| witness.z[i].as_u64()).collect();
    execution.cycles = witness.z[relation.cost_index].as_u64();
    execution.validate_bounds()?;
    let pins = with_constant(&execution.bindings(relation)?);
    if pins.len() != key.pinned.len() || pins.iter().zip(&key.pinned).any(|(&(i, _), &j)| i != j) {
        return Err("veil-W: pinned coordinates differ from the key's".into());
    }
    if pins.iter().any(|&(i, v)| witness.z[i] != v) {
        return Err("veil-W: witness disagrees with the statement".into());
    }
    let statement = PrivateStatement { execution };
    let bytes = crate::execution::succinct::keyed_statement(&key.vk, &statement.transcript_bytes());
    let s = &key.setup;
    let z = s.ext.witness(&witness.z, s.instance.num_cols, coins);
    let mut zp = vec![Goldilocks::ZERO; key.relabelled.num_cols];
    for (col, slot) in s.layout.map.iter().enumerate() {
        if let Some(x) = slot {
            zp[*x] = z[col];
        }
    }
    let parts = protocol::prove(&key.params, s, &key.slots, &key.relabelled, &zp, &bytes, coins)?;
    Ok((statement, SmallProof { bytes: parts.to_bytes() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::veil::tests::square_secret;

    #[test]
    fn a_held_key_makes_the_unkeyed_proof_and_refuses_other_programs() {
        let program = square_secret();
        let key = ProvingKey::new(&program, 0).unwrap();
        for x in [3u64, 12] {
            let seed = [x as u8; 32];
            let (s1, p1) = prove_keyed(&key, &program, &[], &[x], 1000, &Coins::seeded(seed)).unwrap();
            let (s2, p2) = super::super::prove_with_coins(&program, &[], &[x], 1000, &Coins::seeded(seed)).unwrap();
            assert_eq!((&s1, &p1), (&s2, &p2));
            super::super::verify_with(&s1, &p1, Some(key.verifying_key())).unwrap();
        }
        assert!(prove_with_key(&key, &program, &[1], &[3], 1000).is_err());
        let other = ExecutionNoun::Pair(Box::new(ExecutionNoun::Atom(0)), Box::new(ExecutionNoun::Atom(2)));
        assert!(prove_with_key(&key, &other, &[], &[3], 1000).is_err());
    }
}
