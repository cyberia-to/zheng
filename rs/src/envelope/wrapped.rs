//! Profile 6 (wrapped) body: a nox run of any length proven by IVC
//! (`recursion::ivc`), the IVC final verifier proved by wrap levels
//! (`recursion::wrap`) — the final proof: the recursive proof's header,
//! the deferred nox-public claim and one final-mode wrap proof; constant
//! in the steps and ≤ 64 KB.
//!
//! ```text
//! format     u8       WRAPPED_FORMAT (the final proof wire's version)
//! ivc        8 B      the recursive proof's WHIR header
//! levels     u8 L, then L × (8 B WHIR header, u8 mode: 0 inner, 1 final)
//! statement  32 B     the program's digest, then inputs, output tokens,
//!                     cycles, budget, state (exactly as profiles 4 and 5)
//! proof      varint n, then n bytes: `FinalProof::to_bytes` — fixed-width
//!            little-endian, every limb a canonical Goldilocks value (< p)
//! ```
//!
//! Decoding admits only the chain of [`chain`] (`wrap::SHIPPED`: IVC at
//! rate 1/8 (`ivc::SHIPPED_RATE`, 4-ary trees) with `ivc::SHIPPED_POW` =
//! 16 grinding bits over steps of 2^15 rows; wrap levels 1/16 inner with 16 grinding bits, 1/128 inner
//! with 22 (its key over the base field), 1/512 final with 26) and only that step size in the proof's
//! header, so a verifier needs exactly one final key
//! and one IVC key; a hostile header cannot make it derive another. The
//! proof must fill its length exactly and the length must fill the
//! envelope.
//!
//! Keys: the prover derives the whole chain — the inner levels commit
//! their keys (minutes, tens of GB). The verifier needs the IVC key and the
//! final level's key only, cached per process: it derives the levels
//! without committing the inner keys, their roots pinned in
//! [`INNER_ROOTS`] (seconds), or [`super::keys`] installs both keys from a
//! bundle whose digest zheng pins (milliseconds). The prover checks the
//! roots it commits against the pins, so a stale pin fails at the first
//! proof, never silently.

use std::sync::{Arc, Mutex, OnceLock};

use lens::WhirParams;
use nebu::Goldilocks;

use super::codec::{Reader, Writer};
use super::machine::{read_statement, statement};
use super::recursive::{self, STEP_LOG_ROWS};
use super::{Envelope, EnvelopeError as E};
use crate::execution::ExecutionNoun;
use crate::execution::state_evidence::StateEvidence;
use crate::machine::{self, MachinePublic, MachineStatement};
use crate::recursion::ivc;
use crate::recursion::word::Digest;
use crate::recursion::wrap::{self, FinalProof, Inner, Mode, WrapKey, WrapParams};

/// Version of the profile-6 body (2: the program bound by its digest; 3:
/// the chain `wrap::SHIPPED`, IVC at 16 grinding bits, the final level's
/// message digests; 4: the final level at 26 grinding bits — its proof
/// ≤ 64,213 B over every transcript; 5: the inner levels' keys over the
/// base field, the second level at 1/128 with 22 grinding bits; 6: the
/// IVC at rate 1/8 under 4-ary trees).
pub const WRAPPED_FORMAT: u8 = 6;
/// Upper bound on the final proof bytes: 64 KiB, by construction — the
/// admitted final key's `wrap::max_proof_bytes` (64,213 B, over every
/// transcript) is ≤ this, checked when the key is built.
pub const MAX_PROOF_BYTES: usize = wrap::MAX_FINAL_BYTES;
/// Wrap levels of the admitted chain.
pub const LEVELS: usize = 3;

/// The admitted chain: the IVC parameters and the wrap levels, innermost
/// first (`wrap::SHIPPED`; `audit/wrap-fastverify-2026-10.md`: every
/// ledger row ≥ 128 bits).
pub fn chain() -> (WhirParams, [WrapParams; LEVELS]) {
    let mut ivc = recursive::params();
    ivc.log_inv_rate = ivc::SHIPPED_RATE;
    ivc.pow_bits = ivc::SHIPPED_POW;
    let level = |rate: u8, pow: u8, mode: Mode| {
        let mut whir = ivc;
        whir.log_inv_rate = rate;
        whir.pow_bits = pow;
        WrapParams { whir, n: 0, mode }
    };
    (ivc, [level(4, 16, Mode::Inner), level(7, 22, Mode::Inner), level(9, 26, Mode::Final)])
}

/// The chain as it travels: IVC header, level count, per level header and
/// mode.
pub fn chain_bytes() -> Vec<u8> {
    let (ivc, levels) = chain();
    let mut out = ivc.header().to_vec();
    out.push(LEVELS as u8);
    for l in levels {
        out.extend_from_slice(&l.whir.header());
        out.push(u8::from(l.mode == Mode::Final));
    }
    out
}

/// The key roots of the inner levels (levels 0 and 1), as committed by
/// the prover's derivation (`examples/wrap_keys`; checked by the prover
/// and by `tests/keys.rs`).
pub const INNER_ROOTS: [[u64; 4]; LEVELS - 1] = [
    [7041767904392082286, 11448638483575815095, 12825339660069193712, 8967305912144799596],
    [1226187435390808964, 11124567655421662191, 11199638616521209351, 13287911327096972304],
];

fn pinned_root(i: usize) -> Digest {
    INNER_ROOTS[i].map(Goldilocks::new)
}

fn final_slot() -> &'static Mutex<Option<Arc<WrapKey>>> {
    static K: OnceLock<Mutex<Option<Arc<WrapKey>>>> = OnceLock::new();
    K.get_or_init(|| Mutex::new(None))
}

/// The whole chain's keys, derived once per process (the prover's).
pub fn chain_keys() -> Result<Arc<Vec<Arc<WrapKey>>>, String> {
    static C: OnceLock<Mutex<Option<Arc<Vec<Arc<WrapKey>>>>>> = OnceLock::new();
    let slot = C.get_or_init(|| Mutex::new(None));
    let mut g = slot.lock().expect("wrap keys");
    if let Some(c) = g.as_ref() {
        return Ok(c.clone());
    }
    let (ivc, levels) = chain();
    let ikey = ivc::key(&ivc, STEP_LOG_ROWS as usize)?;
    let mut keys: Vec<Arc<WrapKey>> = Vec::with_capacity(LEVELS);
    for p in levels {
        let k = match keys.last() {
            None => wrap::derive_key_ivc(p, &ikey)?,
            Some(prev) => wrap::derive_key_wrap(p, prev)?,
        };
        keys.push(Arc::new(k));
    }
    let roots: Vec<[u64; 4]> = keys[..LEVELS - 1].iter().map(|k| k.key_root.expect("an inner level").map(|v| v.as_u64())).collect();
    if roots != INNER_ROOTS {
        return Err(format!("wrapped: the inner levels' key roots {roots:?} are not the pinned ones (envelope::wrapped::INNER_ROOTS is stale)"));
    }
    let c = Arc::new(keys);
    let last = c.last().expect("a level").clone();
    final_slot().lock().expect("final key").get_or_insert(last);
    *g = Some(c.clone());
    Ok(c)
}

/// Whether the final key is in the process cache (installed or derived).
pub fn final_key_cached() -> bool {
    final_slot().lock().expect("final key").is_some()
}

/// The recursive proof every admitted key is bound to (`WrapKey::ivc`):
/// the chain's IVC parameters and the step size.
pub fn admitted_ivc() -> (WhirParams, usize) {
    (chain().0, STEP_LOG_ROWS as usize)
}

fn check_bound(k: &WrapKey) -> Result<(), String> {
    let last = chain().1[LEVELS - 1];
    if k.ivc != admitted_ivc() || k.params.whir != last.whir || k.params.mode != last.mode {
        return Err("wrapped: the final key is not the admitted chain's".into());
    }
    // its proofs fit the envelope over every transcript
    if wrap::max_proof_bytes(k) > MAX_PROOF_BYTES {
        return Err("wrapped: the final key's proofs can exceed 64 KiB".into());
    }
    Ok(())
}

/// Install the final key (rebuilt from a pinned layout: `keys`).
pub(super) fn install_final(k: WrapKey) -> Result<(), String> {
    check_bound(&k)?;
    final_slot().lock().expect("final key").get_or_insert(Arc::new(k));
    Ok(())
}

/// The final level's key: cached, else derived over the inner levels'
/// pinned roots (their keys are never committed).
pub fn final_key() -> Result<Arc<WrapKey>, String> {
    let mut slot = final_slot().lock().expect("final key");
    if let Some(k) = slot.as_ref() {
        return Ok(k.clone());
    }
    let (ivc_whir, [l0, l1, l2]) = chain();
    let ikey = recursive::pinned_key(&ivc_whir, ivc::key(&ivc_whir, STEP_LOG_ROWS as usize)?)?;
    let k0 = wrap::derive_key_ivc_at(l0, &ikey, pinned_root(0))?;
    let k1 = wrap::derive_key_wrap_at(l1, &k0, pinned_root(1))?;
    let k = Arc::new(wrap::derive_key_wrap(l2, &k1)?);
    check_bound(&k)?;
    *slot = Some(k.clone());
    Ok(k)
}

/// Run `program`, prove it by IVC under the chain's IVC parameters, then
/// wrap the recursive proof through every level.
pub fn prove(program: &ExecutionNoun, input: &[u64], budget: u64) -> Result<Envelope, String> {
    let (ivc_whir, _) = chain();
    let run = machine::execute_exact(program, input, budget, STEP_LOG_ROWS).map_err(|e| format!("machine: {e:?}"))?;
    let proof = ivc::prove_run(&run, &ivc_whir)?;
    wrap_recursive(&run.statement, &proof)
}

/// Wrap a recursive proof (made under the chain's IVC parameters) of `st`.
pub fn wrap_recursive(st: &MachineStatement, proof: &ivc::IvcProof) -> Result<Envelope, String> {
    let (ivc_whir, _) = chain();
    let keys = chain_keys()?;
    let ikey = ivc::key(&ivc_whir, STEP_LOG_ROWS as usize)?;
    let prep = ivc::prepare(st, &ivc_whir, proof.log_rows, proof.start, proof.segments, proof.chain)?;
    let pn = ivc::verify_claim(&prep, proof)?;
    let mut last: Option<wrap::WrapProof> = None;
    for (i, k) in keys.iter().enumerate() {
        let inner = match &last {
            None => Inner::Ivc { key: &ikey, proof },
            Some(w) => Inner::Wrap { key: &keys[i - 1], proof: w },
        };
        let (w, _) = wrap::prove(k, &inner, &prep.publics, &pn)?;
        last = Some(w);
    }
    let fp = FinalProof {
        log_rows: proof.log_rows,
        start: proof.start,
        segments: proof.segments,
        chain: proof.chain,
        pn,
        wrap: last.expect("a level"),
    };
    Ok(Envelope::Wrapped {
        statement: st.public(),
        proof: Box::new(fp),
    })
}

/// Verify under the cached keys. A statement that reads state needs
/// `state`: its reads are authenticated against it first.
pub(super) fn verify(st: &MachineStatement, fp: &FinalProof, state: Option<&StateEvidence>) -> Result<(), String> {
    machine::authenticate_state(st, state)?;
    // the header names the recursive proof the admitted key is bound to,
    // checked before any key work
    if fp.log_rows as usize != admitted_ivc().1 {
        return Err("wrapped envelope: step size not admitted".into());
    }
    let k = final_key()?;
    check_bound(&k)?;
    wrap::verify_statement(st, &admitted_ivc().0, &k, fp)
}

/// The proof's wire bytes (the envelope's last field).
pub fn proof_bytes(fp: &FinalProof) -> Result<Vec<u8>, String> {
    Ok(fp.to_bytes(&*final_key()?))
}

/// Encoding fetches (or derives) the final key; the envelope names the
/// admitted chain.
pub(super) fn encode(st: &MachinePublic, fp: &FinalProof, w: &mut Writer) {
    let bytes = proof_bytes(fp).expect("the wrapped chain's final key");
    w.raw(&[WRAPPED_FORMAT]);
    w.raw(&chain_bytes());
    statement(st, w);
    w.len(bytes.len());
    w.raw(&bytes);
}

pub(super) fn decode(r: &mut Reader, expect: Option<&[u8; 32]>) -> Result<Envelope, E> {
    if r.byte()? != WRAPPED_FORMAT {
        return Err(E::NonCanonical);
    }
    let want = chain_bytes();
    if r.raw(want.len())? != want.as_slice() {
        return Err(E::NonCanonical);
    }
    let statement = read_statement(r, expect)?;
    let n = r.len(MAX_PROOF_BYTES, 1)?;
    let bytes = r.raw(n)?;
    // the proof's step size must be the admitted key's (`WrapKey::ivc`)
    // before any key is built
    if usize::from(*bytes.first().ok_or(E::Truncated)?) != admitted_ivc().1 {
        return Err(E::NonCanonical);
    }
    let key = final_key().map_err(|_| E::NonCanonical)?;
    let proof = FinalProof::from_bytes(bytes, &key).map_err(|_| E::NonCanonical)?;
    Ok(Envelope::Wrapped {
        statement,
        proof: Box::new(proof),
    })
}
