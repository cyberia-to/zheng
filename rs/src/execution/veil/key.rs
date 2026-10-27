//! A proving key for the zk profile: what a prover derives once per
//! program and input count and reuses across proofs — the compiled
//! relation and its verifying key, the masked relation (`pad`), its column
//! layout and the relabelled masked relation. A device that proves the
//! same private statement type repeatedly (P1 authorship, membership)
//! holds one; each proof still draws fresh coins, so proofs differ, and a
//! proof made with a key is one `prove_bound` could have made (equal bytes
//! under equal coins; `tests`).

use nebu::Goldilocks;

use super::coins::Coins;
use super::hiding::HidingParams;
use super::protocol::{self, Setup};
use super::{VeilProof, with_constant};
use crate::execution::private::PrivateStatement;
use crate::execution::{ExecutionNoun, ExecutionStatement, VerifyingKey};
use crate::types::CCSInstance;

/// The zk profile's prover state for one program and input count.
pub struct ProvingKey {
    vk: VerifyingKey,
    /// pinned columns, `(0, ·)` first
    pinned: Vec<usize>,
    setup: Setup,
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
        let pins = with_constant(&skeleton.bindings(&relation)?);
        let vk = VerifyingKey::new(skeleton.program_key(), relation);
        let setup = Setup::new(&vk.relation().instance, &pins)?;
        let relabelled = setup.layout.instance(&setup.instance);
        let pinned = pins.iter().map(|&(i, _)| i).collect();
        Ok(Self {
            vk,
            pinned,
            setup,
            relabelled,
        })
    }

    /// The verifying key this proving key carries (pass it to
    /// `veil::verify_with`).
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// `veil::prove` with a held key.
pub fn prove_with_key(
    key: &ProvingKey,
    program: &ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
) -> Result<(PrivateStatement, VeilProof), String> {
    prove_bound_with_key(
        key,
        program,
        input,
        secret,
        budget,
        &PrivateStatement::transcript_bytes,
    )
}

/// `veil::prove_bound` with a held key.
pub fn prove_bound_with_key(
    key: &ProvingKey,
    program: &ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
    bind: &dyn Fn(&PrivateStatement) -> Vec<u8>,
) -> Result<(PrivateStatement, VeilProof), String> {
    prove_keyed(key, program, input, secret, budget, bind, &Coins::os()?)
}

pub(crate) fn prove_keyed(
    key: &ProvingKey,
    program: &ExecutionNoun,
    input: &[u64],
    secret: &[u64],
    budget: u64,
    bind: &dyn Fn(&PrivateStatement) -> Vec<u8>,
    coins: &Coins,
) -> Result<(PrivateStatement, VeilProof), String> {
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
    execution.public_output = relation
        .output_indices
        .iter()
        .map(|&i| witness.z[i].as_u64())
        .collect();
    execution.cycles = witness.z[relation.cost_index].as_u64();
    execution.validate_bounds()?;
    let pins = with_constant(&execution.bindings(relation)?);
    if pins.len() != key.pinned.len() || pins.iter().zip(&key.pinned).any(|(&(i, _), &j)| i != j) {
        return Err("veil: pinned coordinates differ from the key's".into());
    }
    if pins.iter().any(|&(i, v)| witness.z[i] != v) {
        return Err("veil: witness disagrees with the statement".into());
    }
    let statement = PrivateStatement { execution };
    let bytes = crate::execution::succinct::keyed_statement(&key.vk, &bind(&statement));
    let parsed = protocol::prove_prepared(
        &HidingParams::default(),
        &key.setup,
        &key.relabelled,
        &witness.z,
        &bytes,
        coins,
    )?;
    Ok((
        statement,
        VeilProof {
            bytes: parsed.to_bytes(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::private::prepare_execution;
    use crate::execution::veil::{prove_relation_with, verify_with};
    use crate::types::CCSWitness;

    #[test]
    fn a_held_key_makes_the_proof_prove_bound_makes_and_refuses_other_programs() {
        let program = super::super::tests::square_secret();
        let key = ProvingKey::new(&program, 0).unwrap();
        for x in [3u64, 12, nebu::field::P - 12] {
            let seed = [x as u8; 32];
            let (s1, p1) = prove_keyed(
                &key,
                &program,
                &[],
                &[x],
                1000,
                &PrivateStatement::transcript_bytes,
                &Coins::seeded(seed),
            )
            .unwrap();
            // the unkeyed path under the same coins
            let (s2, prepared, z) = prepare_execution(&program, &[], &[x], 1000).unwrap();
            assert_eq!(s1, s2);
            let vk = VerifyingKey::new(s2.execution.program_key(), prepared.relation);
            let public: Vec<_> = prepared
                .public_coordinates
                .iter()
                .map(|&(i, v)| (i, Goldilocks::new(v)))
                .collect();
            let w = CCSWitness {
                z: z.into_iter().map(Goldilocks::new).collect(),
            };
            let bytes = crate::execution::succinct::keyed_statement(&vk, &s2.transcript_bytes());
            let p2 = prove_relation_with(
                &HidingParams::default(),
                &vk.relation().instance,
                &w,
                &bytes,
                &public,
                &Coins::seeded(seed),
            )
            .unwrap();
            assert_eq!(p1, p2);
            verify_with(&s1, &p1, Some(key.verifying_key())).unwrap();
            let fresh = prove_with_key(&key, &program, &[], &[x], 1000).unwrap();
            verify_with(&fresh.0, &fresh.1, None).unwrap();
            assert_ne!(fresh.1, p1, "fresh coins");
        }
        assert!(prove_with_key(&key, &program, &[1], &[3], 1000).is_err());
        let other = crate::execution::ExecutionNoun::Pair(
            Box::new(crate::execution::ExecutionNoun::Atom(0)),
            Box::new(crate::execution::ExecutionNoun::Atom(2)),
        );
        assert!(prove_with_key(&key, &other, &[], &[3], 1000).is_err());
    }
}
