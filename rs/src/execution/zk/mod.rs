//! Native private CCS proofs. See specs/native-private-ccs.md for the precise
//! relation, arithmetic MPC-in-the-head protocol and security assumptions.
mod circuit;
#[cfg(test)]
mod tests;
mod views;
mod wire;

use crate::types::{CCSInstance, CCSWitness};
use circuit::Circuit;
use nebu::Goldilocks as F;
use views::{FirstMessage, Seed, View};

pub const FORMAT: &str = "zheng-ccs-mith-goldilocks-v1";
pub const REPETITIONS: usize = 219;
pub const MAX_BYTES: usize = 256 * 1024 * 1024;

/// Bounded, fixed-width wire payload. Private input values are secret-shared;
/// proof bytes contain only the two opened views of each independent repetition.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PrivateProof {
    #[cfg_attr(feature = "serde", serde(deserialize_with = "wire::deserialize"))]
    bytes: Vec<u8>,
}

impl PrivateProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Admission only: the verifier checks relation-derived sizes and fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrivateError> {
        if bytes.len() > MAX_BYTES || bytes.len() < 20 || !bytes.starts_with(wire::MAGIC) {
            return Err(PrivateError::InvalidProof);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateError {
    InvalidRelation,
    InvalidPublicCoordinates,
    InvalidWitness,
    InvalidProof,
    EntropyUnavailable,
    Limit,
}
impl core::fmt::Display for PrivateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native private CCS proof: {self:?}")
    }
}
impl std::error::Error for PrivateError {}

/// Prove the exact supplied relation and public coordinates, with fresh OS
/// randomness. The execution owner must derive the relation from its statement.
pub fn prove(
    instance: &CCSInstance,
    witness: &CCSWitness,
    statement: &[u8],
    public: &[(usize, F)],
) -> Result<PrivateProof, PrivateError> {
    let circuit = Circuit::new(instance, statement, public)?;
    if !circuit.satisfied(&witness.z) {
        return Err(PrivateError::InvalidWitness);
    }
    let mut seeds = zeroize::Zeroizing::new(vec![[[0u8; 32]; 3]; REPETITIONS]);
    for round in seeds.iter_mut() {
        for seed in round {
            getrandom::fill(seed).map_err(|_| PrivateError::EntropyUnavailable)?;
        }
    }
    Ok(prove_seeded(&circuit, &witness.z, &seeds))
}

fn prove_seeded(circuit: &Circuit, witness: &[F], seeds: &[[Seed; 3]]) -> PrivateProof {
    let mut transcript = views::transcript(circuit);
    // Only entropy and commitments survive between the two passes.
    // Recomputing views bounds peak witness memory independently of repetitions.
    let mut commitments = Vec::with_capacity(REPETITIONS);
    for (r, seeds) in seeds.iter().enumerate() {
        let views = views::simulate(circuit, witness, seeds);
        let message = FirstMessage::new(circuit, r, &views);
        message.absorb(&mut transcript);
        commitments.push(message.commitments);
    }
    let challenges = views::challenges(&transcript);
    let length = 20
        + challenges
            .iter()
            .map(|&e| {
                97 + 8
                    * (circuit.products.len()
                        + circuit.outputs.len()
                        + if e == 0 { 0 } else { circuit.inputs })
            })
            .sum::<usize>();
    let mut bytes = Vec::with_capacity(length);
    wire::header(circuit, &mut bytes);
    for (r, seeds) in seeds.iter().enumerate() {
        let views = views::simulate(circuit, witness, seeds);
        let message = FirstMessage {
            commitments: commitments[r],
            outputs: std::array::from_fn(|i| circuit.outputs(&views[i].wires, i)),
        };
        wire::encode_round(circuit, challenges[r], &message, &views, &mut bytes);
    }
    PrivateProof { bytes }
}

/// Verify without obtaining a witness or invoking nox. Relations, public values
/// and dimensions are caller-derived; the proof can select none of them.
pub fn verify(
    instance: &CCSInstance,
    proof: &PrivateProof,
    statement: &[u8],
    public: &[(usize, F)],
) -> Result<(), PrivateError> {
    if proof.bytes.len() > MAX_BYTES {
        return Err(PrivateError::InvalidProof);
    }
    let circuit = Circuit::new(instance, statement, public)?;
    let mut reader = wire::Reader::new(&proof.bytes, &circuit)?;
    let mut transcript = views::transcript(&circuit);
    let mut declared = [0u8; REPETITIONS];
    for (r, challenge) in declared.iter_mut().enumerate() {
        *challenge = reader.take(1)?[0];
        if *challenge > 2 {
            return Err(PrivateError::InvalidProof);
        }
        let e = *challenge as usize;
        let neighbor = (e + 1) % 3;
        let hidden = (e + 2) % 3;
        let hidden_commitment = reader.seed()?;
        let hidden_output = reader.fields(circuit.outputs.len())?;
        let seeds = [reader.seed()?, reader.seed()?];
        let mut inputs = [Vec::new(), Vec::new()];
        for i in 0..2 {
            let party = (e + i) % 3;
            inputs[i] = if party == 2 {
                reader.fields(circuit.inputs)?
            } else {
                views::input_share(&seeds[i], circuit.inputs)
            };
        }
        inputs[1].extend(reader.fields(circuit.products.len())?);
        let [first, second] = inputs;
        let mut opened = [
            View {
                seed: seeds[0],
                wires: first,
            },
            View {
                seed: seeds[1],
                wires: second,
            },
        ];
        views::replay(&circuit, e, &mut opened);
        let mut message = FirstMessage {
            commitments: [[0; 32]; 3],
            outputs: std::array::from_fn(|_| Vec::new()),
        };
        message.commitments[hidden] = hidden_commitment;
        message.outputs[hidden] = hidden_output;
        for (i, party) in [e, neighbor].into_iter().enumerate() {
            message.commitments[party] = views::commitment(&circuit, r, party, &opened[i]);
            message.outputs[party] = circuit.outputs(&opened[i].wires, party);
        }
        if !message.is_zero() {
            return Err(PrivateError::InvalidProof);
        }
        message.absorb(&mut transcript);
    }
    if !reader.complete() || views::challenges(&transcript) != declared {
        return Err(PrivateError::InvalidProof);
    }
    Ok(())
}
