//! Proving and verifying a uniform AIR down to evaluation claims on its
//! committed words (module docs of [`super`]).

use lens::rspcs::field::{eq_eval, eq_table};
use lens::{Commitment, MultilinearPcs, Transcript, Whir, WhirParams};
use nebu::Fp3;

use super::public::{next_eval, next_table};
use super::{Air, Trace, shift, zerocheck};
use crate::accumulate::{Claim, Instance, Witnessed};

/// What the AIR prover sends (the commitments and the IOP messages; the
/// openings are left to accumulation or a decider).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirProof {
    pub root1: Commitment,
    /// `None` when the AIR has no phase-2 columns.
    pub root2: Option<Commitment>,
    pub zerocheck: Vec<Vec<Fp3>>,
    /// Every column (`W1 ‖ W2`) at `ρ`.
    pub local: Vec<Fp3>,
    /// Every column at `ρ`'s successor row polynomial.
    pub next: Vec<Fp3>,
    pub shift: Vec<Fp3>,
    pub v1: Fp3,
    pub v2: Fp3,
}

fn powers(x: Fp3, k: usize) -> Vec<Fp3> {
    let mut out = Vec::with_capacity(k);
    let mut c = Fp3::ONE;
    for _ in 0..k {
        out.push(c);
        c *= x;
    }
    out
}

fn prologue<A: Air>(air: &A, n: usize, t: &mut Transcript) {
    let s = air.shape();
    t.absorb(b"zheng-air-v1");
    for v in [s.w1, s.w2, s.challenges, s.constraints, s.degree, n] {
        t.absorb_u64(v as u64);
    }
}

fn squeeze_vec(t: &mut Transcript, k: usize) -> Vec<Fp3> {
    (0..k).map(|_| t.squeeze_fp3()).collect()
}

/// `Σ_c eq(γ, c)·vals[c]` over `vals.len() ≤ 2^γ.len()` columns.
fn fold_cols(gamma: &[Fp3], vals: &[Fp3]) -> Fp3 {
    eq_table(gamma)
        .iter()
        .zip(vals)
        .fold(Fp3::ZERO, |a, (&e, &v)| a + e * v)
}

/// Prove `air` on `w1` (phase 2 built by `phase2` from the challenges).
/// Returns the proof and the two committed words with their claims.
pub fn prove<A: Air>(
    air: &A,
    whir: &WhirParams,
    w1: &Trace,
    phase2: impl FnOnce(&[Fp3]) -> Trace,
    t: &mut Transcript,
) -> Result<(AirProof, Vec<Witnessed>), String> {
    let s = air.shape();
    let rows = w1.rows();
    if !rows.is_power_of_two() || rows < 2 || w1.width != s.w1 {
        return Err("air: trace shape".into());
    }
    let n = rows.trailing_zeros() as usize;
    let wp = s.padded_width();
    prologue(air, n, t);
    let (root1, data1) = Whir::commit(whir, &w1.column_major(wp));
    t.absorb(root1.as_bytes());
    let ch = squeeze_vec(t, s.challenges);
    let w2 = phase2(&ch);
    if w2.width != s.w2 || (s.w2 > 0 && w2.rows() != rows) {
        return Err("air: phase-2 trace shape".into());
    }
    let second = (s.w2 > 0).then(|| Whir::commit(whir, &w2.column_major(wp)));
    if let Some((r2, _)) = &second {
        t.absorb(r2.as_bytes());
    }
    let tau = squeeze_vec(t, n);
    let mu = powers(t.squeeze_fp3(), s.constraints);
    let w = s.w1 + s.w2;
    let mut cols: Vec<Vec<Fp3>> = Vec::with_capacity(2 * w + air.publics().len());
    let column = |c: usize, shift: usize| -> Vec<Fp3> {
        (0..rows)
            .map(|r| {
                let r = (r + shift) % rows;
                let x = if c < s.w1 { w1.row(r)[c] } else { w2.row(r)[c - s.w1] };
                Fp3::from_base(x)
            })
            .collect()
    };
    for c in 0..w {
        cols.push(column(c, 0));
    }
    for c in 0..w {
        cols.push(column(c, 1));
    }
    for p in air.publics() {
        cols.push(p.table(n));
    }
    let (zc, rho, evals) = zerocheck::prove(air, w, cols, eq_table(&tau), &ch, &mu, t);
    let local = evals[..w].to_vec();
    let next = evals[w..2 * w].to_vec();
    t.absorb_fp3_slice(&local);
    t.absorb_fp3_slice(&next);
    let cbits = wp.trailing_zeros() as usize;
    let g1 = squeeze_vec(t, cbits);
    let g2 = squeeze_vec(t, cbits);
    let beta = t.squeeze_fp3();
    let zeta = t.squeeze_fp3();
    let e1 = eq_table(&g1);
    let e2 = eq_table(&g2);
    let p1: Vec<Fp3> = (0..rows)
        .map(|r| w1.row(r).iter().zip(&e1).fold(Fp3::ZERO, |a, (&x, &e)| a + e * Fp3::from_base(x)))
        .collect();
    let p2: Vec<Fp3> = (0..rows)
        .map(|r| {
            if s.w2 == 0 {
                Fp3::ZERO
            } else {
                w2.row(r).iter().zip(&e2).fold(Fp3::ZERO, |a, (&x, &e)| a + e * Fp3::from_base(x))
            }
        })
        .collect();
    let eqr = eq_table(&rho);
    let nx = next_table(&rho);
    let kt: Vec<Fp3> = eqr.iter().zip(&nx).map(|(&a, &b)| a + beta * b).collect();
    let q: Vec<Fp3> = p1.iter().zip(&p2).map(|(&a, &b)| a + zeta * b).collect();
    let mut extra = vec![p1, p2];
    let (sh, rho2) = shift::prove(t, kt, q, &mut extra);
    let (v1, v2) = (extra[0][0], extra[1][0]);
    t.absorb_fp3(v1);
    t.absorb_fp3(v2);
    let point = |g: &[Fp3]| -> Vec<Fp3> { rho2.iter().chain(g).copied().collect() };
    let mut words = vec![Witnessed {
        instance: Instance {
            root: root1,
            ext: false,
            claims: vec![Claim {
                point: point(&g1),
                value: v1,
            }],
        },
        data: data1,
    }];
    let root2 = second.as_ref().map(|(r, _)| *r);
    if let Some((r2, d2)) = second {
        words.push(Witnessed {
            instance: Instance {
                root: r2,
                ext: false,
                claims: vec![Claim {
                    point: point(&g2),
                    value: v2,
                }],
            },
            data: d2,
        });
    }
    let proof = AirProof {
        root1,
        root2,
        zerocheck: zc,
        local,
        next,
        shift: sh,
        v1,
        v2,
    };
    Ok((proof, words))
}

/// Verify the IOP part of an AIR proof over `2^n` rows; returns the
/// instances (claims on the committed words) the openings must settle.
pub fn verify<A: Air>(
    air: &A,
    n: usize,
    proof: &AirProof,
    t: &mut Transcript,
) -> Result<Vec<Instance>, String> {
    let s = air.shape();
    let w = s.w1 + s.w2;
    if proof.local.len() != w || proof.next.len() != w || proof.root2.is_some() != (s.w2 > 0) {
        return Err("air: proof shape".into());
    }
    let wp = s.padded_width();
    prologue(air, n, t);
    t.absorb(proof.root1.as_bytes());
    let ch = squeeze_vec(t, s.challenges);
    if let Some(r2) = &proof.root2 {
        t.absorb(r2.as_bytes());
    }
    let tau = squeeze_vec(t, n);
    let mu = powers(t.squeeze_fp3(), s.constraints);
    let (rho, claim) =
        zerocheck::verify(t, &proof.zerocheck, n, s.degree).ok_or("air: zerocheck shape")?;
    let publics: Vec<Fp3> = air.publics().iter().map(|p| p.eval(&rho)).collect();
    let vals: Vec<Fp3> = proof
        .local
        .iter()
        .chain(&proof.next)
        .chain(&publics)
        .copied()
        .collect();
    let mut scratch = vec![Fp3::ZERO; s.constraints];
    let c = zerocheck::combine(air, w, &vals, &ch, &mu, &mut scratch);
    if eq_eval(&tau, &rho) * c != claim {
        return Err("air: constraints do not hold".into());
    }
    t.absorb_fp3_slice(&proof.local);
    t.absorb_fp3_slice(&proof.next);
    let cbits = wp.trailing_zeros() as usize;
    let g1 = squeeze_vec(t, cbits);
    let g2 = squeeze_vec(t, cbits);
    let beta = t.squeeze_fp3();
    let zeta = t.squeeze_fp3();
    let a1 = fold_cols(&g1, &proof.local[..s.w1]);
    let b1 = fold_cols(&g1, &proof.next[..s.w1]);
    let a2 = fold_cols(&g2, &proof.local[s.w1..]);
    let b2 = fold_cols(&g2, &proof.next[s.w1..]);
    let sigma = a1 + beta * b1 + zeta * (a2 + beta * b2);
    let (rho2, last) = shift::verify(t, sigma, &proof.shift, n).ok_or("air: shift shape")?;
    let k = eq_eval(&rho, &rho2) + beta * next_eval(&rho, &rho2);
    if k * (proof.v1 + zeta * proof.v2) != last {
        return Err("air: shift reduction".into());
    }
    if s.w2 == 0 && proof.v2 != Fp3::ZERO {
        return Err("air: phase-2 value without phase 2".into());
    }
    t.absorb_fp3(proof.v1);
    t.absorb_fp3(proof.v2);
    let point = |g: &[Fp3]| -> Vec<Fp3> { rho2.iter().chain(g).copied().collect() };
    let mut out = vec![Instance {
        root: proof.root1,
        ext: false,
        claims: vec![Claim {
            point: point(&g1),
            value: proof.v1,
        }],
    }];
    if let Some(r2) = proof.root2 {
        out.push(Instance {
            root: r2,
            ext: false,
            claims: vec![Claim {
                point: point(&g2),
                value: proof.v2,
            }],
        });
    }
    Ok(out)
}
