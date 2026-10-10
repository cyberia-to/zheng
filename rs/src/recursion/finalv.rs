//! The final verifier of a recursive proof, written once over [`Ops`]: the
//! native verifier runs it, and the wrap step proves it as a circuit
//! (`specs/recursion.md` § final verifier).
//!
//! ```text
//! state     absorb the state the last step started from → x = H(state)
//! step      verify the last step from it → the final state
//! final     its context, chain and step count are the statement's, its
//!           first boundary row is the last step's successor (cyclic)
//! G         the deferred constraint claim: the step relation's constraint
//!           polynomial, compiled from its recorded graph with the run's
//!           challenges and the statement constants as inputs
//! decider   the accumulator and the deferred key claim (one opening)
//! out       the deferred nox-public claim (the statement's own columns:
//!           evaluated natively by whoever holds the statement)
//! ```

use nebu::Fp3;

use super::decide::{self, Decider};
use super::ivc::Key;
use super::ops::{Arith, Ops};
use super::state::{self, ClaimV, State};
use super::step::{self, StepProof};
use crate::machine::air::KConst;

/// What a final verification binds besides the proof: computed from the
/// statement by the native verifier, the public input of a wrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publics<V> {
    /// The run's context digest.
    pub ctx: [V; 4],
    /// The chain of pre-committed roots.
    pub chain: [V; 4],
    pub segments: V,
    /// The run's memory challenges.
    pub ch: [V; 2],
    /// The statement constants.
    pub k: KConst<V>,
}

impl<V: Copy> Publics<V> {
    /// Every value with its width (Fp3 or base), in a fixed order.
    pub fn items(&self) -> Vec<(V, bool)> {
        let mut out: Vec<(V, bool)> = self.ctx.iter().chain(&self.chain).map(|&v| (v, false)).collect();
        out.push((self.segments, false));
        out.extend(self.ch.iter().map(|&v| (v, true)));
        out.extend(self.k.to_vec().into_iter().map(|v| (v, false)));
        out
    }
    pub fn from_items(v: &[V]) -> Self {
        Self {
            ctx: [v[0], v[1], v[2], v[3]],
            chain: [v[4], v[5], v[6], v[7]],
            segments: v[8],
            ch: [v[9], v[10]],
            k: KConst::from_slice(&v[11..]),
        }
    }
}

/// Number of public values ([`Publics::items`]).
pub const PUBLICS: usize = 11 + crate::machine::air::KCONSTS;

/// Verify the last step from `state`, the final state against `pubs`, the
/// deferred constraint claim and the decider; returns the deferred
/// nox-public claim.
pub fn run<O: Ops>(o: &mut O, key: &Key, pubs: &Publics<O::V>, state: &State, step: &StepProof, dec: &Decider) -> ClaimV<O::V> {
    let p = &key.params;
    let (st, x) = state::absorb_free(o, &p.dims, state);
    let fin = step::verify(o, p, &st, x, step);
    for i in 0..4 {
        o.assert_eq(fin.ctx[i], pubs.ctx[i], "final: context");
        o.assert_eq(fin.chain[i], pubs.chain[i], "final: chain");
    }
    o.assert_eq(fin.step, pubs.segments, "final: step count");
    for (&a, &b) in fin.b_first.iter().zip(&fin.b_last) {
        o.assert_eq(a, b, "final: cyclic boundary");
    }
    let mut ins = fin.g.point.clone();
    ins.extend_from_slice(&pubs.ch);
    ins.extend(pubs.k.to_vec());
    let g = o.graph(&key.g, &ins)[0];
    o.assert_eq(g, fin.g.value, "final: deferred constraints");
    decide::verify(o, &key.dcfg, &fin.acc, &fin.pv, key.kw_root, key.key_ext, p.n, dec);
    fin.pn
}

/// The publics as constants of an interpreter (the native verifier).
pub fn constants<O: Ops>(o: &mut O, p: &Publics<Fp3>) -> Publics<O::V> {
    let v: Vec<O::V> = p.items().into_iter().map(|(x, _)| o.constant(x)).collect();
    Publics::from_items(&v)
}
