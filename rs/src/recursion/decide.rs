//! The decider of a recursive proof, field-native: one batched WHIR
//! opening ([`super::whir`]) of the last accumulator and of the circuit's
//! key, so the final verifier — natively or inside a wrap circuit — opens
//! words with permutations alone.
//!
//! ```text
//! transcript  tag DECIDE: the accumulator instance (root, (ρ, v0), OOD
//!             claims, spot claims) and the deferred key claim (z ‖ g, v)
//! key claim   P̄_V(z, g) = (1 − g_6)·K̃_lo(z, g_0..6) + g_6·K̃_hi(z, g_0..6)
//!             over the key's two 64-column words; the prover sends
//!             (v_lo, v_hi), the verifier checks the line
//! opening     whir over [accumulator, K_lo, K_hi] with every claim
//! ```
//!
//! The key words are fixed by the parameters (anyone derives them from
//! the circuit layout): exact codewords with roots in the key.

use nebu::Fp3;

use super::acc::{ClaimRef, InstV};
use super::ops::{Arith, Ops};
use super::perm::tag;
use super::sponge::{ProverTranscript, Sponge};
use super::state::{AccV, ClaimV};
use super::whir;
use super::word::{Digest, Word};

/// What the decider sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decider {
    /// `K̃_lo(z, g_0..6)`, `K̃_hi(z, g_0..6)`.
    pub key: [Fp3; 2],
    pub whir: whir::Proof,
}

/// The key's words and their place in the decider.
pub struct KeyWords {
    pub words: [Word; 2],
    pub roots: [Digest; 2],
}

/// Absorb the instance the decider proves (generic over the interpreter).
fn absorb<O: Ops>(o: &mut O, t: &mut Sponge<O>, acc: &AccV<O::V>, pv: &ClaimV<O::V>) {
    t.absorb_all(o, &acc.root);
    t.absorb_all_ext(o, &acc.rho);
    t.absorb_ext(o, acc.v0);
    for &(z, y) in &acc.ood {
        t.absorb_ext(o, z);
        t.absorb_ext(o, y);
    }
    for &(x, y) in &acc.spot {
        t.absorb(o, x);
        t.absorb_ext(o, y);
    }
    t.absorb_all_ext(o, &pv.point);
    t.absorb_ext(o, pv.value);
}

/// The batch's inputs: the accumulator with its claims, the key words
/// with the split key claim.
fn inputs<V: Copy>(acc: &AccV<V>, key_roots: [[V; 4]; 2], key_ext: bool, z: &[V], v: [V; 2]) -> Vec<InstV<V>> {
    let mut out = vec![acc.instance()];
    for (root, val) in key_roots.into_iter().zip(v) {
        out.push(InstV { root, ext: key_ext, claims: vec![ClaimRef::Multi(z.to_vec(), val)] });
    }
    out
}

/// Prove the decider for the final state's accumulator (`table`: the
/// accumulator word) and key claim.
pub fn prove(cfg: &whir::Config, acc_word: &Word, acc: &AccV<Fp3>, pv: &ClaimV<Fp3>, key: &KeyWords, n: usize) -> Result<Decider, String> {
    let mut t = ProverTranscript::new(tag::DECIDE);
    absorb(&mut t.o, &mut t.sp, acc, pv);
    let zg = &pv.point[..n + 6];
    let v = [key.words[0].table(), key.words[1].table()].map(|tb| lens::rspcs::field::ml_eval_ext(&tb, zg));
    t.absorb_ext(v[0]);
    t.absorb_ext(v[1]);
    let vars = acc.rho.len();
    let up = |x: Fp3| lens::rspcs::field::pow_point(x, vars);
    let mut acc_claims = vec![(acc.rho.clone(), acc.v0)];
    acc_claims.extend(acc.ood.iter().map(|&(z, y)| (up(z), y)));
    acc_claims.extend(acc.spot.iter().map(|&(x, y)| (up(x), y)));
    let claims = vec![acc_claims, vec![(zg.to_vec(), v[0])], vec![(zg.to_vec(), v[1])]];
    let whir = whir::prove(cfg, &mut t, &[acc_word, &key.words[0], &key.words[1]], &claims)?;
    Ok(Decider { key: v, whir })
}

/// Verify the decider of `acc` and the key claim `pv` against the key's
/// roots.
#[allow(clippy::too_many_arguments)]
pub fn verify<O: Ops>(o: &mut O, cfg: &whir::Config, acc: &AccV<O::V>, pv: &ClaimV<O::V>, key_roots: [Digest; 2], key_ext: bool, n: usize, pf: &Decider) {
    let mut t = Sponge::new(o, tag::DECIDE);
    absorb(o, &mut t, acc, pv);
    let v = [t.absorb_free_ext(o, pf.key[0]), t.absorb_free_ext(o, pf.key[1])];
    let g6 = pv.point[n + 6];
    let line = o.lerp(g6, v[0], v[1]);
    o.assert_eq(line, pv.value, "decider: the key claim");
    let roots = key_roots.map(|r| r.map(|x| o.constant(Fp3::from_base(x))));
    let ins = inputs(acc, roots, key_ext, &pv.point[..n + 6], v);
    whir::verify(o, cfg, &mut t, &ins, &pf.whir);
}

/// Shape of a decider proof.
pub fn check_shape(cfg: &whir::Config, pf: &Decider) -> Result<(), String> {
    whir::check_shape(cfg, 3, &pf.whir)
}
