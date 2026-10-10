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
//! Two modes:
//!
//! - [`Mode::Inner`] (a proof another wrap verifies): the circuit's AIR
//!   over `2^n` rows with committed words `W1` (circuit phase 1), `W2`
//!   (phase 2: the memory argument, after the memory challenges) and the
//!   circuit's key as two fixed words; any interpreter verifies it, the
//!   circuit included;
//! - [`Mode::Final`] (the outermost proof, verified natively): one
//!   committed word `W1`; the memory argument is replaced by its linear
//!   form — every read slot's value equals its write slot's, batched with
//!   powers of `λ` into `⟨u_λ, W1⟩ = 0` over the whole word, one sumcheck
//!   — and the key's columns are evaluated by the verifier (`u_λ` and the
//!   key are fixed by the circuit's layout: `O(reads + key entries)`
//!   field operations, no opening).
//!
//! Both: `live = 1` on every row, the public input `X` at the output row.
//!
//! ```text
//! transcript  tag WRAP: X; W1 root, OOD; inner: (α_V, β_V), W2 root,
//!             OOD | final: λ; τ, μ; zerocheck (degree 9); the committed
//!             columns at ρ and its successor; inner: the key columns at
//!             ρ, γ_k; the shift reduction to one point per word; inner:
//!             the key claim split over its two words | final: the wiring
//!             sumcheck; one batched field-native WHIR opening
//! ```
//!
//! The verifier evaluates the circuit's constraints at the point through
//! their recorded graph (`expr`), so it runs natively and as a circuit.

mod program;
mod prove;
mod verify;
mod vk;
mod wiring;

pub use wiring::{Coef, Wiring};
pub mod wire;

#[cfg(test)]
mod review;
#[cfg(test)]
mod tests;

pub use program::{Inner, derive_key_ivc, derive_key_wrap, derive_shape, derive_shape_ivc, public_digest, public_digest_native};
pub use prove::prove;
pub use verify::{check_shape, threads as verifier_threads, verify};

use lens::WhirParams;
use nebu::Fp3;

use super::circuit::air::{CircuitAir, Row, Sink};
use super::circuit::layout::{LIVE, PIN, V1, V2, pre};
use super::circuit::trace::Pre;
use super::state::ClaimV;
use super::whir;
use super::word::Digest;
use crate::air::num::{Graph, Num, record};
use crate::air::{Air, Public, Shape, Vals};

/// The shipped chain of levels over the IVC proof, innermost first, as
/// the benches spell it (`<log inv rate><i|f>[:<grinding bits>]`): inner
/// 1/16 grinding 16 bits (2^16 rows), inner 1/256 grinding 24 (2^15),
/// final 1/512 grinding 24 (2^14) — `audit/wrap-fastverify-2026-10.md`.
pub const SHIPPED: &str = "4i:16,8i,9f:24";

/// Committed columns (phase 1 ‖ phase 2).
pub const COLS: usize = V1 + V2;
/// Columns of a committed word.
pub const WORD: usize = 64;
/// Column variables of a word.
pub const CBITS: usize = 6;

/// A wrap level's relation (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Memory argument, committed key: verifiable by the circuit.
    Inner,
    /// Linear wiring, the key evaluated by the verifier: one committed
    /// word, a native verifier only.
    Final,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WrapParams {
    pub whir: WhirParams,
    /// `log2` of the rows.
    pub n: usize,
    pub mode: Mode,
}

/// Everything a wrap level's prover and verifier derive from its
/// parameters and the verifier it proves.
pub struct WrapKey {
    pub params: WrapParams,
    pub pre: Pre,
    pub sparse: Vec<Vec<(u32, Fp3)>>,
    /// The root of the key's words (inner mode).
    pub key_root: Option<Digest>,
    /// The key's words, committed once (inner mode, a derived key; a
    /// key loaded from bytes has none and its prover recommits them).
    pub kw: Option<super::decide::KeyWords>,
    /// The linear wiring (final mode).
    pub wiring: Option<Wiring>,
    pub key_ext: bool,
    pub cfg: whir::Config,
    /// OOD samples binding each trace word.
    pub fresh: usize,
    pub out_row: usize,
    /// `Σ_k μ^k C_k` of the circuit's constraints and `live = 1`, over the
    /// point, the memory challenges and `μ`.
    pub g: Graph,
    pub constraints: usize,
    /// `g` compiled for native evaluation.
    pub gc: crate::air::num::Compiled,
    /// The committed columns whose successor values the constraints read
    /// (final mode sends only these; inner mode every column).
    pub next_cols: Vec<usize>,
    /// The key columns the constraints read (the final verifier evaluates
    /// only these; the others never enter `G`).
    pub key_cols: Vec<bool>,
    /// Coordinates of the deferred nox-public claim's point.
    pub pn: usize,
    /// The recursive proof the chain of levels starts from: its WHIR
    /// parameters and step size (`log2` rows). The outermost proof's
    /// header must name them.
    pub ivc: (WhirParams, usize),
    /// Rows the circuit uses (of `2^n`), and its census: gates,
    /// decompositions, permutation blocks.
    pub rows: usize,
    pub census: [usize; 3],
}

impl WrapKey {
    pub fn inner(&self) -> bool {
        self.params.mode == Mode::Inner
    }
    /// Committed trace words (1 or 2) and their columns.
    pub fn trace_words(&self) -> usize {
        if self.inner() { 2 } else { 1 }
    }
    pub fn cols(&self) -> usize {
        if self.inner() { COLS } else { V1 }
    }
    pub fn inputs(&self) -> usize {
        if self.inner() { 4 } else { 1 }
    }
    /// Symbol fields of the opened words.
    /// Symbol fields of the opened trees (round 0).
    pub fn exts(&self) -> Vec<bool> {
        if self.inner() { vec![false, false, self.key_ext] } else { vec![false] }
    }
    /// Trees of an inner level are 4-ary (half the permutations a path
    /// costs the circuit that verifies it); the final level's binary
    /// (fewest bytes).
    pub fn arity(&self) -> super::word::Arity {
        if self.inner() { super::word::Arity::Four } else { super::word::Arity::Two }
    }
    pub fn vars(&self) -> usize {
        self.params.n + CBITS
    }
}

/// A wrap proof (final mode: one trace word, the successor values of the
/// columns the constraints read, no key messages, no shift or wiring
/// sumcheck — its claims are the opening's weights).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapProof {
    pub roots: Vec<Digest>,
    pub ood: Vec<Vec<Fp3>>,
    pub zerocheck: Vec<Vec<Fp3>>,
    pub local: Vec<Fp3>,
    pub next: Vec<Fp3>,
    /// The key's columns at `ρ` (committed mode; empty otherwise).
    pub key: Vec<Fp3>,
    pub shift: Vec<Fp3>,
    pub vals: Vec<Fp3>,
    /// The key claim over its two words (inner mode; empty otherwise).
    pub kv: Vec<Fp3>,
    pub whir: whir::Proof,
}

/// The outermost proof: the recursive proof's header (step size, region
/// start, segments, the chain of pre-committed roots), the deferred
/// nox-public claim and the wrap proof whose public input binds them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalProof {
    pub log_rows: u32,
    pub start: u64,
    pub segments: u64,
    pub chain: Digest,
    pub pn: ClaimV<Fp3>,
    pub wrap: WrapProof,
}

/// The constraint degree of the circuit.
pub const DEGREE: usize = 8;

/// The circuit's AIR alone, `live = 1` appended, for the zerocheck prover:
/// local = W1 ‖ W2 (inner) or W1 (final, no memory constraints), publics =
/// key ‖ public-input columns.
pub struct View<'a>(pub &'a CircuitAir, pub Mode);

impl View<'_> {
    pub fn width(&self) -> usize {
        if self.1 == Mode::Inner { COLS } else { V1 }
    }
    pub fn constraints(&self) -> usize {
        1 + if self.1 == Mode::Inner { self.0.constraints() } else { self.0.local_constraints() }
    }
    pub fn eval_with<T: Num>(&self, local: &[T], next: &[T], pubs: &[T], alpha: T, beta: T, out: &mut [T]) {
        let inner = self.1 == Mode::Inner;
        let w = self.width();
        let row = Row {
            l1: &local[..V1],
            l2: &local[V1..w],
            n1: &next[..V1],
            n2: &next[V1..w],
            p: &pubs[..pre::COUNT],
            pin: &pubs[pre::COUNT..],
            alpha,
            beta,
        };
        let k = self.constraints() - 1;
        let mut s = Sink { buf: &mut out[..k], i: 0 };
        if inner {
            self.0.eval(&row, &mut s);
        } else {
            self.0.eval_local(&row, &mut s);
        }
        out[k] = local[LIVE] - T::ONE;
    }
}

impl Air for View<'_> {
    fn shape(&self) -> Shape {
        Shape { w1: self.width(), w2: 0, challenges: 2, constraints: self.constraints(), degree: DEGREE }
    }
    fn publics(&self) -> &[Public] {
        &[]
    }
    fn eval(&self, v: &Vals<'_>, ch: &[Fp3], out: &mut [Fp3]) {
        self.eval_with(v.local, v.next, v.publics, ch[0], ch[1], out);
    }
}

/// Inputs of the constraint graph: local, next (`w` each), key, public
/// input, α_V, β_V, μ.
pub fn g_inputs(w: usize) -> usize {
    2 * w + pre::COUNT + PIN + 3
}

/// The key columns `g` (over committed width `w`) reads.
pub(crate) fn key_used(g: &Graph, w: usize) -> Vec<bool> {
    g.used_inputs()[2 * w..2 * w + pre::COUNT].to_vec()
}

/// Record `Σ_k μ^k C_k` (constraints of the circuit and `live = 1`).
pub fn g_graph(air: &CircuitAir, mode: Mode) -> (Graph, usize) {
    let view = View(air, mode);
    let (k, w) = (view.constraints(), view.width());
    let g = record(g_inputs(w), |i| {
        let (local, rest) = i.split_at(w);
        let (next, rest) = rest.split_at(w);
        let (pubs, rest) = rest.split_at(pre::COUNT + PIN);
        let (alpha, beta, mu) = (rest[0], rest[1], rest[2]);
        let mut out = vec![crate::air::num::Sym::ZERO; k];
        view.eval_with(local, next, pubs, alpha, beta, &mut out);
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
    if prep.header != (fp.log_rows, fp.start, fp.segments, fp.chain) {
        return Err("wrap: header".into());
    }
    // the levels verify one recursive proof's final verifier: its key
    // (WHIR parameters, step size) is the one the statement was prepared
    // under
    if (prep.key.params.whir, prep.key.params.n) != k.ivc {
        return Err("wrap: the key was derived for another recursive proof".into());
    }
    if fp.pn.point.len() != k.pn {
        return Err("wrap: nox-public claim shape".into());
    }
    let lap = super::ivc::timer_pub("    final ");
    check_shape(k, &fp.wrap)?;
    if super::prove::pbar_nox(&prep.global, &fp.pn.point, prep.key.params.n) != fp.pn.value {
        return Err("wrap: deferred nox publics".into());
    }
    lap("nox-public claim");
    let x = program::public_digest_native(&prep.publics, &fp.pn)?;
    lap("public digest");
    let mut o = Native::batched();
    let xv = x.map(|v| o.constant(Fp3::from_base(v)));
    verify(&mut o, k, xv, &fp.wrap);
    lap("wrap verify");
    let r = o.finish();
    lap("merkle batch");
    r
}

/// Verify the outermost proof of `st` (the recursive proof's WHIR
/// parameters `ivc_whir`): prepare the statement under the proof's
/// header, then [`verify_final`].
pub fn verify_statement(st: &crate::machine::MachineStatement, ivc_whir: &lens::WhirParams, k: &WrapKey, fp: &FinalProof) -> Result<(), String> {
    let prep = super::ivc::prepare(st, ivc_whir, fp.log_rows, fp.start, fp.segments, fp.chain)?;
    verify_final(&prep, k, fp)
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

/// Every round-by-round term of a wrap level as `(name, bits)` — its own
/// rounds and its opening's (`specs/soundness.md` § wrap). `reads`: the
/// read slots of the final mode's wiring.
pub fn ledger(params: &WrapParams, cfg: &whir::Config, constraints: usize, reads: usize) -> Vec<(String, f64)> {
    use lens::rspcs::soundness::{ext_field_bits, proximity};
    let k = ext_field_bits();
    let n = params.n;
    let log2 = |x: f64| x.log2();
    let mut out = Vec::new();
    let s0 = cfg.wc.rounds[0];
    let list = proximity(s0.regime, s0.log_inv_rate, s0.log_domain).log_list;
    let fresh = crate::accumulate::fresh_ood(&params.whir, n + CBITS).unwrap_or(0);
    out.push(("fresh-word binding (OOD)".into(), -(2.0 * list - 1.0 + fresh as f64 * ((n + CBITS) as f64 - k))));
    out.push(("zerocheck μ (powers)".into(), k - log2((constraints - 1) as f64)));
    out.push(("zerocheck τ".into(), k - log2(n as f64)));
    out.push(("zerocheck round (degree 9)".into(), k - log2((DEGREE + 2) as f64)));
    match params.mode {
        Mode::Inner => {
            let t = (crate::recursion::circuit::layout::SLOTS << n) as f64;
            out.push(("memory α_V".into(), k - log2(t)));
            out.push(("memory β_V (pairs)".into(), k - 2.0 * log2(t) + 1.0));
            out.push(("shift column batching".into(), k - log2(CBITS as f64)));
            out.push(("shift β, ζ".into(), k - 1.0));
            out.push(("shift round (degree 2)".into(), k - 1.0));
            out.push(("key column batching γ_k".into(), k - log2(7.0)));
            out.push(("key split line".into(), k));
        }
        Mode::Final => {
            out.push(("wiring λ".into(), k - log2(reads.max(2) as f64)));
            out.push(("column batching (local, successor)".into(), k - log2(CBITS as f64)));
        }
    }
    out.extend(cfg.terms());
    out
}
