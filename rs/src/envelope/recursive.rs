//! Profile 5 (recursive) body: a nox run of any length proven by
//! incrementally verifiable computation (`recursion::ivc`) — the last
//! step's proof, its accumulation step and one decider; constant in the
//! number of steps.
//!
//! ```text
//! format     u8       RECURSIVE_FORMAT (the IVC wire's version)
//! params     8 B      WHIR header — one of the admitted parameter sets
//! statement           program tokens, inputs, output tokens, cycles,
//!                     budget (exactly as profile 4)
//! proof      varint n, then n bytes: `IvcProof::to_bytes` — fixed-width
//!            little-endian, every limb a canonical Goldilocks value (< p)
//! ```
//!
//! Decoding admits only the parameter sets of [`ADMITTED`] (rate 1/16 or
//! 1/64, folding 4, 24 grinding bits, steps of 2^15 rows), so the verifier
//! derives at most one circuit key per set and caches it for the process
//! (`ivc::key`); a hostile header cannot make it derive another. The proof
//! must fill its length exactly and the length must fill the envelope.

use lens::WhirParams;

use super::codec::{Reader, Writer};
use super::machine::{read_statement, statement};
use super::{Envelope, EnvelopeError as E};
use crate::execution::ExecutionNoun;
use crate::execution::state_evidence::StateEvidence;
use crate::machine::{self, MachineStatement};
use crate::recursion::ivc::{self, IvcProof};

/// Version of the IVC proof wire inside a profile-5 body.
pub const RECURSIVE_FORMAT: u8 = 1;
/// The step size of every admitted parameter set (log2 rows).
pub const STEP_LOG_ROWS: u32 = 15;
/// Upper bound on the IVC proof bytes (measured 233–285 KB).
pub const MAX_PROOF_BYTES: usize = 1 << 20;

/// The parameter sets a profile-5 envelope may name: `(log_inv_rate,
/// step log rows)` over folding 4 and 24 grinding bits. Every ledger row
/// of each is ≥ 128 bits (`specs/soundness.md` § recursion).
pub const ADMITTED: [(u8, u32); 2] = [(4, STEP_LOG_ROWS), (6, STEP_LOG_ROWS)];

/// The shipped parameters: rate 1/16 (`audit/recursion-2026-10.md` §2).
pub fn params() -> WhirParams {
    params_at(4)
}

fn params_at(log_inv_rate: u8) -> WhirParams {
    let mut w = crate::execution::succinct::params_for(20);
    w.log_inv_rate = log_inv_rate;
    w.pow_bits = 24;
    w
}

/// Whether `(whir, log_rows)` is an admitted parameter set.
pub fn admitted(whir: &WhirParams, log_rows: u32) -> bool {
    ADMITTED
        .iter()
        .any(|&(rate, n)| n == log_rows && params_at(rate).header() == whir.header())
}

/// The circuit key of an admitted set, derived once per process.
pub fn key(whir: &WhirParams, log_rows: u32) -> Result<std::sync::Arc<ivc::Key>, String> {
    if !admitted(whir, log_rows) {
        return Err("recursive envelope: parameters not admitted".into());
    }
    ivc::key(whir, log_rows as usize)
}

/// Run `program` and prove it recursively under `whir` (an admitted set).
pub fn prove(
    program: &ExecutionNoun,
    input: &[u64],
    budget: u64,
    whir: &WhirParams,
) -> Result<Envelope, String> {
    key(whir, STEP_LOG_ROWS)?;
    let run = machine::execute_exact(program, input, budget, STEP_LOG_ROWS)
        .map_err(|e| format!("machine: {e:?}"))?;
    let proof = ivc::prove_run(&run, whir)?;
    Ok(Envelope::Recursive {
        params: *whir,
        statement: run.statement,
        proof: Box::new(proof),
    })
}

/// Verify under the cached key of the proof's parameter set. A statement
/// that reads state needs `state`: its reads are authenticated against it
/// first, as in profile 4.
pub(super) fn verify(
    whir: &WhirParams,
    st: &MachineStatement,
    proof: &IvcProof,
    state: Option<&StateEvidence>,
) -> Result<(), String> {
    machine::authenticate_state(st, state)?;
    key(whir, proof.log_rows)?;
    ivc::verify(st, proof, whir)
}

/// The proof's wire bytes (the envelope's last field).
pub fn proof_bytes(whir: &WhirParams, proof: &IvcProof) -> Result<Vec<u8>, String> {
    Ok(proof.to_bytes(&*key(whir, proof.log_rows)?))
}

/// Encoding derives (or fetches) the key of the envelope's parameters; it
/// panics only on parameters no key exists for (`Params::new` refuses
/// them), which no prover produces. Decoding then admits only [`ADMITTED`].
pub(super) fn encode(params: &WhirParams, st: &MachineStatement, proof: &IvcProof, w: &mut Writer) {
    let key = ivc::key(params, proof.log_rows as usize).expect("a recursion key for the envelope's parameters");
    let bytes = proof.to_bytes(&key);
    w.raw(&[RECURSIVE_FORMAT]);
    w.raw(&params.header());
    statement(st, w);
    w.len(bytes.len());
    w.raw(&bytes);
}

pub(super) fn decode(r: &mut Reader) -> Result<Envelope, E> {
    if r.byte()? != RECURSIVE_FORMAT {
        return Err(E::NonCanonical);
    }
    let header = r.raw(8)?;
    let params = ADMITTED
        .iter()
        .map(|&(rate, _)| params_at(rate))
        .find(|p| p.header()[..] == *header)
        .ok_or(E::NonCanonical)?;
    let statement = read_statement(r)?;
    let n = r.len(MAX_PROOF_BYTES, 1)?;
    let bytes = r.raw(n)?;
    // the header's step size must be admitted before any key is derived
    let log_rows = u32::from(*bytes.first().ok_or(E::Truncated)?);
    if !admitted(&params, log_rows) {
        return Err(E::NonCanonical);
    }
    let proof = IvcProof::from_bytes(bytes, |lr| key(&params, lr)).map_err(|_| E::NonCanonical)?;
    Ok(Envelope::Recursive {
        params,
        statement,
        proof: Box::new(proof),
    })
}
