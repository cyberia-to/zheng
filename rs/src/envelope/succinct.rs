//! Profile 1 (succinct) body.
//!
//! ```text
//! pcs        u8                 1 WHIR · 2 TensorRs
//! params     PCS header bytes   8 (WHIR) · 6 (TensorRs)
//! kind       u8                 0 execution · 1 state
//! statement                     the execution statement, or the state
//!                               statement exactly as in profile 3
//! root       32 B               four canonical limbs
//! evals      varint t,  t × Fp3            M̃_i(ρ_x)
//! outer      varint R, varint c, R × c × Fp3   rounds without c_1
//! inner      varint R', R' × 2 × Fp3           rounds without c_1
//! value      Fp3                           w̃(r')
//! opening    the rest: the PCS proof after its parameter header
//! ```
//!
//! An Fp3 element is three canonical little-endian u64 limbs (8 bytes each,
//! each `< p`): challenge-field elements are uniform, so a varint would be
//! longer. Shapes are checked against the relation by the verifier, not
//! here; here only bounds and canonical encodings are checked.

use lens::{Commitment, PcsError, TensorRs, Whir};
use nebu::Fp3;
use nebu::field::P;

use super::body::{execution, read_execution, read_state, state};
use super::codec::{Reader, Writer};
use super::{Envelope, EnvelopeError as E};
use crate::execution::state::StateStatement;
use crate::execution::state_evidence::StateEvidence;
use crate::execution::succinct::{SuccinctPcs, SuccinctProof};
use crate::execution::ExecutionStatement;
use crate::spartan::reduce::CompressedRounds;

const MAX_MATRICES: usize = 16;
const MAX_ROUNDS: usize = 40;
const MAX_COEFFS: usize = 16;

/// The statement a succinct proof is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuccinctStatement {
    Execution(ExecutionStatement),
    State(StateStatement),
}

/// A succinct proof under one of the schemes the wire can name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnySuccinct {
    Whir(Box<SuccinctProof<Whir>>),
    Tensor(Box<SuccinctProof<TensorRs>>),
}

impl AnySuccinct {
    /// The wire id of the scheme.
    pub fn pcs_id(&self) -> u8 {
        match self {
            Self::Whir(_) => <Whir as SuccinctPcs>::ID,
            Self::Tensor(_) => <TensorRs as SuccinctPcs>::ID,
        }
    }
}

impl From<SuccinctProof<Whir>> for AnySuccinct {
    fn from(p: SuccinctProof<Whir>) -> Self {
        Self::Whir(Box::new(p))
    }
}

impl From<SuccinctProof<TensorRs>> for AnySuccinct {
    fn from(p: SuccinctProof<TensorRs>) -> Self {
        Self::Tensor(Box::new(p))
    }
}

fn ext(w: &mut Writer, x: Fp3) {
    for limb in [x.c0, x.c1, x.c2] {
        w.raw(&limb.as_u64().to_le_bytes());
    }
}

fn read_ext(r: &mut Reader) -> Result<Fp3, E> {
    let mut limb = || -> Result<nebu::Goldilocks, E> {
        let b: [u8; 8] = r.raw(8)?.try_into().expect("8 bytes");
        let v = u64::from_le_bytes(b);
        if v >= P {
            return Err(E::NonCanonical);
        }
        Ok(nebu::Goldilocks::new(v))
    };
    Ok(Fp3::new(limb()?, limb()?, limb()?))
}

fn rounds(w: &mut Writer, c: &CompressedRounds<Fp3>, fixed: Option<usize>) {
    w.len(c.rounds.len());
    let width = c.rounds.first().map_or(0, Vec::len);
    if fixed.is_none() {
        w.len(width);
    }
    for round in &c.rounds {
        debug_assert_eq!(round.len(), width);
        for &x in round {
            ext(w, x);
        }
    }
}

fn read_rounds(r: &mut Reader, fixed: Option<usize>) -> Result<CompressedRounds<Fp3>, E> {
    let n = r.len(MAX_ROUNDS, 1)?;
    let width = match fixed {
        Some(c) => c,
        None => r.len(MAX_COEFFS, 0)?,
    };
    // one encoding: an empty list has width 0, a non-empty one width ≥ 1
    if (n == 0) != (width == 0) && fixed.is_none() {
        return Err(E::NonCanonical);
    }
    if n.saturating_mul(width).saturating_mul(24) > r.remaining() {
        return Err(E::Truncated);
    }
    let rounds = (0..n)
        .map(|_| (0..width).map(|_| read_ext(r)).collect())
        .collect::<Result<_, _>>()?;
    Ok(CompressedRounds { rounds })
}

fn proof<Pc: SuccinctPcs>(p: &SuccinctProof<Pc>, w: &mut Writer) {
    w.raw(p.root.as_bytes());
    w.len(p.matrix_evals.len());
    for &x in &p.matrix_evals {
        ext(w, x);
    }
    rounds(w, &p.outer, None);
    rounds(w, &p.inner, Some(2));
    ext(w, p.witness_eval);
    w.raw(&Pc::proof_body(&p.opening));
}

fn read_proof<Pc: SuccinctPcs>(
    params: Pc::Params,
    r: &mut Reader,
) -> Result<SuccinctProof<Pc>, E> {
    let root = r.raw(32)?;
    if root
        .chunks_exact(8)
        .any(|l| u64::from_le_bytes(l.try_into().expect("8 bytes")) >= P)
    {
        return Err(E::NonCanonical);
    }
    let root = Commitment(hemera::Hash::from_bytes(root.try_into().expect("32 bytes")));
    let t = r.len(MAX_MATRICES, 24)?;
    let matrix_evals = (0..t).map(|_| read_ext(r)).collect::<Result<_, _>>()?;
    let outer = read_rounds(r, None)?;
    let inner = read_rounds(r, Some(2))?;
    let witness_eval = read_ext(r)?;
    let body = r.raw(r.remaining())?;
    let opening = Pc::proof_from_body(&params, body).map_err(|_: PcsError| E::NonCanonical)?;
    Ok(SuccinctProof {
        params,
        root,
        matrix_evals,
        outer,
        inner,
        witness_eval,
        opening,
    })
}

/// The proof part of a profile-1 body as it travels: PCS id, parameter
/// header, commitment, Spartan messages and opening (no statement).
pub fn proof_bytes(any: &AnySuccinct) -> Vec<u8> {
    let mut w = Writer::default();
    pcs_header(any, &mut w);
    proof_part(any, &mut w);
    w.bytes
}

fn pcs_header(any: &AnySuccinct, w: &mut Writer) {
    w.raw(&[any.pcs_id()]);
    match any {
        AnySuccinct::Whir(p) => w.raw(&Whir::header(&p.params)),
        AnySuccinct::Tensor(p) => w.raw(&TensorRs::header(&p.params)),
    }
}

fn proof_part(any: &AnySuccinct, w: &mut Writer) {
    match any {
        AnySuccinct::Whir(p) => proof(p, w),
        AnySuccinct::Tensor(p) => proof(p, w),
    }
}

pub(super) fn encode(statement: &SuccinctStatement, any: &AnySuccinct, w: &mut Writer) {
    pcs_header(any, w);
    match statement {
        SuccinctStatement::Execution(s) => {
            w.raw(&[0]);
            execution(s, w);
        }
        SuccinctStatement::State(s) => {
            w.raw(&[1]);
            state(s, w);
        }
    }
    proof_part(any, w);
}

fn header<Pc: SuccinctPcs>(r: &mut Reader) -> Result<Pc::Params, E> {
    Pc::params_from_header(r.raw(Pc::HEADER)?).map_err(|_| E::NonCanonical)
}

enum Params {
    Whir(<Whir as lens::MultilinearPcs>::Params),
    Tensor(<TensorRs as lens::MultilinearPcs>::Params),
}

pub(super) fn decode(r: &mut Reader) -> Result<Envelope, E> {
    let params = match r.byte()? {
        1 => Params::Whir(header::<Whir>(r)?),
        2 => Params::Tensor(header::<TensorRs>(r)?),
        _ => return Err(E::NonCanonical),
    };
    let statement = match r.byte()? {
        0 => SuccinctStatement::Execution(read_execution(r)?),
        1 => SuccinctStatement::State(read_state(r)?),
        _ => return Err(E::NonCanonical),
    };
    let proof = match params {
        Params::Whir(p) => AnySuccinct::Whir(Box::new(read_proof::<Whir>(p, r)?)),
        Params::Tensor(p) => AnySuccinct::Tensor(Box::new(read_proof::<TensorRs>(p, r)?)),
    };
    Ok(Envelope::Succinct { statement, proof })
}

/// Verify a decoded succinct envelope.
pub(super) fn verify(
    statement: &SuccinctStatement,
    any: &AnySuccinct,
    state: Option<&StateEvidence>,
) -> Result<(), String> {
    use crate::execution::succinct as s;
    let evidence = || state.ok_or_else(|| "succinct state proof: no state evidence".to_string());
    match (statement, any) {
        (SuccinctStatement::Execution(st), AnySuccinct::Whir(p)) => s::verify(st, p),
        (SuccinctStatement::Execution(st), AnySuccinct::Tensor(p)) => s::verify(st, p),
        (SuccinctStatement::State(st), AnySuccinct::Whir(p)) => s::verify_state(st, p, evidence()?),
        (SuccinctStatement::State(st), AnySuccinct::Tensor(p)) => {
            s::verify_state(st, p, evidence()?)
        }
    }
}
