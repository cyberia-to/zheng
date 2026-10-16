//! Every value a veil-W proof reveals, by category (what any verifier
//! reads), for zero-knowledge tests: two witnesses of one statement must
//! give identically distributed values in every category.

use lens::rspcs::WhirProof;
use lens::rspcs::wire::Symbols;
use nebu::{Fp3, Goldilocks};

use super::super::protocol::Setup;
use super::super::with_constant;
use super::protocol::Parts;
use super::SmallProof;
use crate::types::CCSInstance;

/// Revealed values by category, each value one canonical `u64` limb.
pub type Revealed = Vec<(&'static str, Vec<u64>)>;

fn limbs(xs: &[Fp3]) -> Vec<u64> {
    xs.iter().flat_map(|x| [x.c0.as_u64(), x.c1.as_u64(), x.c2.as_u64()]).collect()
}

fn digests(hs: &[hemera::Hash]) -> Vec<u64> {
    hs.iter().flat_map(|h| h.as_bytes().chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().expect("8"))).collect::<Vec<_>>()).collect()
}

/// The values of `proof` for a relation and public coordinates.
pub fn revealed_relation(instance: &CCSInstance, public: &[(usize, Goldilocks)], proof: &SmallProof) -> Result<Revealed, String> {
    let s = Setup::new(instance, &with_constant(public))?;
    let p = Parts::from_bytes(proof.as_bytes(), s.shape())?;
    Ok(categories(&p))
}

fn round0(o: &WhirProof) -> &lens::rspcs::whir::Opening {
    o.rounds.first().map_or(&o.final_opening, |r| &r.opening)
}

pub(crate) fn categories(p: &Parts) -> Revealed {
    let o = &p.opening;
    let open0 = round0(o);
    let width = open0.width;
    let k = width - lens::rspcs::whir::zk::EXTRA;
    let Symbols::Base(sym) = &open0.symbols else { unreachable!("base round-0 symbols") };
    let part = |lo: usize, hi: usize| -> Vec<u64> { sym.chunks_exact(width).flat_map(|l| l[lo..hi].iter().map(|v| v.as_u64())).collect() };
    let later: Vec<Fp3> = o
        .rounds
        .iter()
        .skip(1)
        .map(|r| &r.opening)
        .chain(if o.rounds.is_empty() { None } else { Some(&o.final_opening) })
        .flat_map(|op| match &op.symbols {
            Symbols::Ext(v) => v.clone(),
            Symbols::Base(v) => v.iter().map(|&x| Fp3::from_base(x)).collect(),
        })
        .collect();
    let s = &p.spartan;
    vec![
        ("matrix evaluations", limbs(&s.evals)),
        ("outer rounds", limbs(&s.outer.rounds.concat())),
        ("inner rounds", limbs(&s.inner.rounds.concat())),
        ("mask sums", limbs(&[s.g1, s.g2])),
        ("u_psi, u", limbs(&[p.u_psi, p.vals.u])),
        ("round-0 OOD", limbs(&o.ood0)),
        ("round-0 sumcheck", limbs(&o.sumcheck0)),
        ("round-0 c symbols", part(0, k)),
        ("round-0 G symbols", part(k, k + 3)),
        ("round-0 salts", part(k + 3, width)),
        ("round-0 siblings", digests(&open0.siblings)),
        ("later OOD + sumcheck", limbs(&o.rounds.iter().flat_map(|r| r.ood.iter().chain(&r.sumcheck).copied()).collect::<Vec<_>>())),
        ("later roots", digests(&o.rounds.iter().map(|r| r.root).collect::<Vec<_>>())),
        ("later opened symbols", limbs(&later)),
        ("final polynomial", limbs(&o.final_poly)),
    ]
}
