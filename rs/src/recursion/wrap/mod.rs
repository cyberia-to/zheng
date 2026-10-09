//! Wrap steps: a verifier proved as one non-accumulating proof of the
//! recursion circuit alone (`specs/recursion.md` § wrap).
//!
//! A wrap proof shows that the circuit ran a verifier — the IVC final
//! verifier ([`super::finalv`]) or the verifier of another wrap proof — on
//! a proof it holds as witness, and output the digest of the public values
//! that verifier binds:
//!
//! ```text
//! X = H_PUBLIC(ctx, chain, segments, run challenges, statement constants,
//!              the deferred nox-public claim (point, value))
//! ```
//!
//! The relation: the circuit's AIR over `2^n` rows, three-or-fewer
//! committed words — `W1` (circuit phase 1), `W2` (phase 2, after the
//! memory challenges), and in [`KeyMode::Committed`] the circuit's key as
//! two fixed words — `live = 1` on every row, the public input `X` at the
//! output row. The proof:
//!
//! ```text
//! transcript  tag WRAP: X; W1 root, OOD; (α_V, β_V); W2 root, OOD;
//!             τ, μ; zerocheck (degree 9); every W1, W2 column at ρ and
//!             its successor; the key columns at ρ (committed mode);
//!             γ_k; the shift reduction of W1, W2 to one point; the key
//!             claim split over its two words; one batched field-native
//!             WHIR opening of every word
//! ```
//!
//! The verifier evaluates the circuit's constraints at the point through
//! their recorded graph (`expr`), so it runs natively and as a circuit:
//! a wrap of a wrap verifies the inner wrap in the recursion circuit. In
//! [`KeyMode::Native`] the verifier evaluates the key's columns itself
//! (`O(nonzero key entries)`), which saves the key words' openings — the
//! outermost proof's mode (a native verifier only).

mod program;
mod prove;
mod verify;
pub mod wire;

#[cfg(test)]
mod tests;

pub use program::{Inner, derive_key_ivc, derive_key_wrap, public_digest, public_digest_native};
pub use prove::prove;
pub use verify::{check_shape, verify};

use lens::WhirParams;
use nebu::Fp3;

use super::circuit::air::{CircuitAir, Row, Sink};
use super::circuit::layout::{LIVE, PIN, V1, V2, pre};
use super::circuit::trace::Pre;
use super::decide::KeyWords;
use super::state::ClaimV;
use super::whir;
use super::word::Digest;
use crate::air::num::{Graph, Num, record};
use crate::air::{Air, Public, Shape, Vals};

/// Committed columns (phase 1 ‖ phase 2).
pub const COLS: usize = V1 + V2;
/// Columns of a committed word.
pub const WORD: usize = 64;
/// Column variables of a word.
pub const CBITS: usize = 6;

/// How the verifier gets the key's columns at the zerocheck point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMode {
    /// Two fixed committed words, opened with the trace words (any
    /// interpreter, the circuit included).
    Committed,
    /// Evaluated by the verifier from the key (a native verifier only).
    Native,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WrapParams {
    pub whir: WhirParams,
    /// `log2` of the rows.
    pub n: usize,
    pub key: KeyMode,
}

/// Everything a wrap level's prover and verifier derive from its
/// parameters and the verifier it proves.
pub struct WrapKey {
    pub params: WrapParams,
    pub pre: Pre,
    pub sparse: Vec<Vec<(u32, Fp3)>>,
    /// The key words ([`KeyMode::Committed`]).
    pub kw: Option<KeyWords>,
    pub key_ext: bool,
    pub cfg: whir::Config,
    /// OOD samples binding each trace word.
    pub fresh: usize,
    pub out_row: usize,
    /// `Σ_k μ^k C_k` of the circuit's constraints and `live = 1`, over the
    /// point, the memory challenges and `μ`.
    pub g: Graph,
    pub constraints: usize,
    /// Coordinates of the deferred nox-public claim's point.
    pub pn: usize,
    /// Rows the circuit uses (of `2^n`).
    pub rows: usize,
}

impl WrapKey {
    pub fn inputs(&self) -> usize {
        if self.kw.is_some() { 4 } else { 2 }
    }
    /// Symbol fields of the opened words.
    pub fn exts(&self) -> Vec<bool> {
        let mut v = vec![false, false];
        if self.kw.is_some() {
            v.extend([self.key_ext; 2]);
        }
        v
    }
    pub fn vars(&self) -> usize {
        self.params.n + CBITS
    }
}

/// A wrap proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapProof {
    pub roots: [Digest; 2],
    pub ood: [Vec<Fp3>; 2],
    pub zerocheck: Vec<Vec<Fp3>>,
    pub local: Vec<Fp3>,
    pub next: Vec<Fp3>,
    /// The key's columns at `ρ` (committed mode; empty otherwise).
    pub key: Vec<Fp3>,
    pub shift: Vec<Fp3>,
    pub vals: [Fp3; 2],
    /// The key claim over its two words (committed mode; empty otherwise).
    pub kv: Vec<Fp3>,
    pub whir: whir::Proof,
}

/// The outermost proof: the deferred nox-public claim and the wrap proof
/// whose public input binds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalProof {
    pub pn: ClaimV<Fp3>,
    pub wrap: WrapProof,
}

/// The constraint degree of the circuit.
pub const DEGREE: usize = 8;

/// The circuit's AIR alone, `live = 1` appended, for the zerocheck prover:
/// local = W1 ‖ W2, publics = key ‖ public-input columns.
pub struct View<'a>(pub &'a CircuitAir);

impl View<'_> {
    pub fn eval_with<T: Num>(&self, local: &[T], next: &[T], pubs: &[T], alpha: T, beta: T, out: &mut [T]) {
        let row = Row {
            l1: &local[..V1],
            l2: &local[V1..COLS],
            n1: &next[..V1],
            n2: &next[V1..COLS],
            p: &pubs[..pre::COUNT],
            pin: &pubs[pre::COUNT..],
            alpha,
            beta,
        };
        let k = self.0.constraints();
        let mut s = Sink { buf: &mut out[..k], i: 0 };
        self.0.eval(&row, &mut s);
        out[k] = local[LIVE] - T::ONE;
    }
}

impl Air for View<'_> {
    fn shape(&self) -> Shape {
        Shape { w1: COLS, w2: 0, challenges: 2, constraints: self.0.constraints() + 1, degree: DEGREE }
    }
    fn publics(&self) -> &[Public] {
        &[]
    }
    fn eval(&self, v: &Vals<'_>, ch: &[Fp3], out: &mut [Fp3]) {
        self.eval_with(v.local, v.next, v.publics, ch[0], ch[1], out);
    }
}

/// Inputs of the constraint graph: local, next, key, public input, α_V,
/// β_V, μ.
pub const G_INPUTS: usize = 2 * COLS + pre::COUNT + PIN + 3;

/// Record `Σ_k μ^k C_k` (constraints of the circuit and `live = 1`).
pub fn g_graph(air: &CircuitAir) -> (Graph, usize) {
    let k = air.constraints() + 1;
    let g = record(G_INPUTS, |i| {
        let (local, rest) = i.split_at(COLS);
        let (next, rest) = rest.split_at(COLS);
        let (pubs, rest) = rest.split_at(pre::COUNT + PIN);
        let (alpha, beta, mu) = (rest[0], rest[1], rest[2]);
        let mut out = vec![crate::air::num::Sym::ZERO; k];
        View(air).eval_with(local, next, pubs, alpha, beta, &mut out);
        let mut acc = crate::air::num::Sym::ZERO;
        let mut m = crate::air::num::Sym::ONE;
        for c in out {
            acc += m * c;
            m *= mu;
        }
        vec![acc]
    });
    (g, k)
}

/// Verify the outermost proof natively against a prepared statement: the
/// deferred nox-public claim against the statement's columns, then the
/// wrap proof under the public input the statement and that claim hash
/// to.
pub fn verify_final(prep: &super::ivc::Prepared, k: &WrapKey, fp: &FinalProof) -> Result<(), String> {
    use super::ops::{Native, Ops};
    if fp.pn.point.len() != k.pn {
        return Err("wrap: nox-public claim shape".into());
    }
    check_shape(k, &fp.wrap)?;
    if super::prove::pbar_nox(&prep.global, &fp.pn.point, prep.key.params.n) != fp.pn.value {
        return Err("wrap: deferred nox publics".into());
    }
    let x = program::public_digest_native(&prep.publics, &fp.pn)?;
    let mut o = Native::batched();
    let xv = x.map(|v| o.constant(Fp3::from_base(v)));
    verify(&mut o, k, xv, &fp.wrap);
    o.finish()
}

/// Verify a wrap proof natively under public input `x`.
pub fn verify_native(k: &WrapKey, x: Digest, pf: &WrapProof) -> Result<(), String> {
    use super::ops::{Native, Ops};
    check_shape(k, pf)?;
    let mut o = Native::batched();
    let xv = x.map(|v| o.constant(Fp3::from_base(v)));
    verify(&mut o, k, xv, pf);
    o.finish()
}
