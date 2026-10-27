//! Public authenticated-state execution: lookup coordinates pinned in a
//! verifier-derived CCS. Profile v3 (`certify_state_execution`,
//! `StateStatement::verify_certificate`) checks a certificate exactly;
//! profile v1 (`prove_state_execution`, `StateStatement::verify_v1`) is
//! retired and read for one release.
//!
//! Every verifier takes the [`StateEvidence`] of the reads and
//! authenticates it against the statement's own `state_root` before any
//! read is pinned: no caller authenticates anything on zheng's behalf.
//!
//! The statement carries no caller context. Under the public profiles the
//! witness is disclosed, so anyone holding a certificate can re-certify the
//! same execution under any label: no relation can bind one. The retired v1
//! transcript did absorb a 32-byte context; `verify_v1` takes it as an
//! argument so that old proofs keep verifying.
use super::relation::{ExecutionRelation, SubjectShape, compile_relation};
use super::state_evidence::{AuthenticatedState, StateEvidence};
use super::{Certificate, DirectProof, ExecutionNoun, ExecutionStatement, certificate, proof};
use crate::types::CCSWitness;
use nebu::Goldilocks as F;
use std::collections::BTreeMap;

/// A verifying key borrowed from the caller's cache or derived in place.
type Keyed<'a> = std::borrow::Cow<'a, super::VerifyingKey>;

/// Bound on the reads a state statement may carry.
pub const MAX_READS: usize = 4096;

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
    /// Compiler state ABI places the root in the subject head. Raw formulas
    /// may instead construct the root explicitly inside their program.
    pub root_in_subject: bool,
    #[cfg_attr(feature = "serde", serde(deserialize_with = "reads_wire"))]
    pub reads: Vec<PublicLookup>,
}
#[cfg(feature = "serde")]
fn reads_wire<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<PublicLookup>, D::Error> {
    super::statement_wire::bounded::<D, PublicLookup, MAX_READS>(d)
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
    fn validate(&self) -> Result<(), String> {
        self.execution.validate_bounds()?;
        if self.state_root.iter().any(|&v| v >= nebu::field::P) || self.reads.len() > MAX_READS {
            return Err("invalid state execution bounds".into());
        }
        Ok(())
    }
    pub(crate) fn relation(&self) -> Result<ExecutionRelation, String> {
        self.validate()?;
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
    /// What the relation depends on, hashed: see [`super::vk`].
    pub fn program_key(&self) -> [u8; 32] {
        super::vk::program_key(
            &self.execution.program,
            self.execution.public_input.len(),
            super::vk::StatementKind::State {
                root_in_subject: self.root_in_subject,
            },
        )
    }

    /// The statement bytes every transcript-bearing profile absorbs.
    pub fn transcript_bytes(&self) -> Vec<u8> {
        self.domain_bytes(b"zheng-nox-public-state-execution-v2", None)
    }
    /// The retired v1 statement bytes, with the caller context v1 absorbed.
    pub fn transcript_bytes_v1(&self, context: &[u8; 32]) -> Vec<u8> {
        self.domain_bytes(b"zheng-nox-public-state-execution-v1", Some(context))
    }
    fn domain_bytes(&self, domain: &[u8], context: Option<&[u8; 32]>) -> Vec<u8> {
        let mut bytes = domain.to_vec();
        bytes.extend(self.execution.transcript_bytes());
        if let Some(context) = context {
            bytes.extend(context);
        }
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
    pub(crate) fn bindings(
        &self,
        relation: &ExecutionRelation,
        state: &AuthenticatedState<'_>,
    ) -> Result<Vec<(usize, F)>, String> {
        if state.root() != self.state_root {
            return Err("state evidence authenticated under another root".into());
        }
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
                || state.cell(read.namespace, read.key) != Some(read.value)
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
    /// The relation and pinned coordinates after authenticating `evidence`
    /// under this statement's root and every active read against it.
    pub(crate) fn authenticated_bindings(
        &self,
        evidence: &StateEvidence,
    ) -> Result<(ExecutionRelation, Vec<(usize, F)>), String> {
        let state = evidence.authenticate(self.state_root)?;
        let relation = self.relation()?;
        let public = self.bindings(&relation, &state)?;
        Ok((relation, public))
    }
    /// The verifying key (from `vk` when derived for this statement, else
    /// compiled) and the pinned coordinates after authentication.
    pub(crate) fn keyed_bindings<'a>(
        &self,
        evidence: &StateEvidence,
        vk: Option<&'a super::VerifyingKey>,
    ) -> Result<(Keyed<'a>, Vec<(usize, F)>), String> {
        let state = evidence.authenticate(self.state_root)?;
        let key = match vk {
            Some(vk) => {
                self.validate()?;
                std::borrow::Cow::Borrowed(vk.check(self.program_key())?)
            }
            None => std::borrow::Cow::Owned(super::VerifyingKey::for_state(self)?),
        };
        let public = self.bindings(key.relation(), &state)?;
        Ok((key, public))
    }
    /// Profile v3: authenticate `evidence` under `state_root`, every active
    /// read against it, then check every row exactly.
    pub fn verify_certificate(
        &self,
        certificate: &Certificate,
        evidence: &StateEvidence,
    ) -> Result<(), String> {
        let (relation, public) = self.authenticated_bindings(evidence)?;
        certificate::verify(&relation.instance, certificate, &public).map_err(|e| e.to_string())
    }
    /// [`Self::verify_certificate`] with a cached key derived for this
    /// statement's program key (any other key is rejected).
    pub fn verify_certificate_with(
        &self,
        certificate: &Certificate,
        evidence: &StateEvidence,
        vk: &super::VerifyingKey,
    ) -> Result<(), String> {
        let (key, public) = self.keyed_bindings(evidence, Some(vk))?;
        certificate::verify(&key.relation().instance, certificate, &public)
            .map_err(|e| e.to_string())
    }
    /// Profile v1 (retired, read for one release) under the context its
    /// transcript absorbed.
    pub fn verify_v1(
        &self,
        context: &[u8; 32],
        proof: &DirectProof,
        evidence: &StateEvidence,
    ) -> Result<(), String> {
        let (relation, public) = self.authenticated_bindings(evidence)?;
        proof::verify(&relation.instance, proof, &self.transcript_bytes_v1(context), &public)
            .map_err(|e| e.to_string())
    }
}
/// The statement, relation, witness and pinned coordinates of one honest
/// state execution; shared by the v1 prover, the v3 certifier and the
/// succinct profile.
#[allow(clippy::type_complexity)]
pub(super) fn prepare(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    root_in_subject: bool,
    evidence: &StateEvidence,
) -> Result<(StateStatement, ExecutionRelation, CCSWitness, Vec<(usize, F)>), String> {
    let state_root = evidence.root()?;
    let state = evidence.authenticate(state_root)?;
    let mut statement = StateStatement {
        execution: ExecutionStatement {
            program: ExecutionStatement::encode_program(program)?,
            public_input: input.to_vec(),
            public_output: vec![],
            cycles: 0,
            budget,
        },
        state_root,
        root_in_subject,
        reads: vec![],
    };
    let relation = statement.relation()?;
    let witness = relation
        .witness_with_provider(&statement.inputs(), &[], &mut |root, ns, key| {
            if root.map(|v| v.as_u64()) != state_root {
                return None;
            }
            state.cell(ns.as_u64(), key.as_u64()).map(F::new)
        })
        .map_err(|e| format!("state execution witness: {e:?}"))?;
    let value = |i: usize| witness.z[i].as_u64();
    statement.execution.public_output = relation.output_indices.iter().map(|&i| value(i)).collect();
    statement.execution.cycles = value(relation.cost_index);
    if statement.execution.cycles > budget {
        return Err("execution cost exceeds budget".into());
    }
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
    let public = statement.bindings(&relation, &state)?;
    Ok((statement, relation, witness, public))
}

/// State profile v1 (Spartan + PublicTensor). Public only: the direct proof
/// discloses all columns. Retained to produce and read `JOYST001` for one
/// release; new artifacts use [`certify_state_execution`]. `context` enters
/// the v1 transcript only.
pub fn prove_state_execution(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    root_in_subject: bool,
    context: &[u8; 32],
    evidence: &StateEvidence,
) -> Result<(StateStatement, DirectProof), String> {
    let (statement, relation, witness, public) =
        prepare(program, input, budget, root_in_subject, evidence)?;
    let proof = proof::prove(
        &relation.instance,
        &witness,
        &statement.transcript_bytes_v1(context),
        &public,
    )
    .map_err(|e| e.to_string())?;
    Ok((statement, proof))
}

/// State profile v3: the statement (with every read) plus the free witness
/// positions. The verifier pins z[0] = 1, the inputs (and the root when it
/// sits in the subject), the outputs, the cost and every lookup coordinate
/// — active flag, root limbs, namespace, key, value — after authenticating
/// the evidence under the statement's root and each active read against
/// it, then checks every CCS row exactly. No commitment, sumcheck or
/// challenge. The statement's root is the root `evidence` authenticates.
pub fn certify_state_execution(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    root_in_subject: bool,
    evidence: &StateEvidence,
) -> Result<(StateStatement, Certificate), String> {
    let (statement, relation, witness, public) =
        prepare(program, input, budget, root_in_subject, evidence)?;
    let certificate =
        certificate::certify(&relation.instance, &witness, &public).map_err(|e| e.to_string())?;
    Ok((statement, certificate))
}
