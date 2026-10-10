//! Proving and verifying a uniform AIR over one or more segments down to
//! evaluation claims on the committed words (module docs of [`super`]).
//!
//! Segments `0..S` are consecutive pieces of one trace (`2^n` rows each).
//! Every phase-1 word is committed before the challenges; the challenges
//! are shared; every phase-2 word is committed after them. The next row of
//! segment `i`'s last row is the *boundary* `B_i` — the first row of
//! segment `i + 1` (cyclically, segment 0 after the last) — sent in the
//! clear and tied to that segment's words by one evaluation claim at row
//! 0 per word. Within a segment the successor is non-cyclic.

use lens::rspcs::field::{eq_eval, eq_table};
use lens::{Commitment, MultilinearPcs, Transcript, Whir, WhirParams};
use nebu::{Fp3, Goldilocks};

use super::public::{next_eval, next_table};
use super::{Air, Trace, shift, zerocheck};
use crate::accumulate::{Claim, Instance};

/// One segment's messages after the commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentProof {
    /// The first row (`W1 ‖ W2`) of the next segment.
    pub boundary: Vec<Goldilocks>,
    pub zerocheck: Vec<Vec<Fp3>>,
    /// Every column at `ρ`, and the next-row columns at `ρ`.
    pub local: Vec<Fp3>,
    pub next: Vec<Fp3>,
    pub shift: Vec<Fp3>,
    pub v1: Fp3,
    pub v2: Fp3,
}

/// What the AIR prover sends for `S` segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirProof {
    pub roots1: Vec<Commitment>,
    pub roots2: Vec<Commitment>,
    /// Per word, its answers `f̂(ζ_j)` to the out-of-domain samples drawn
    /// right after its root (`accumulate::fresh_ood`): each fresh word is
    /// bound to one codeword of its list before any challenge it feeds.
    pub ood1: Vec<Vec<Fp3>>,
    pub ood2: Vec<Vec<Fp3>>,
    pub segments: Vec<SegmentProof>,
}

/// The two committed words of a segment and their claims.
pub type SegmentWords = [Instance; 2];

fn powers(x: Fp3, k: usize) -> Vec<Fp3> {
    let mut out = Vec::with_capacity(k);
    let mut c = Fp3::ONE;
    for _ in 0..k {
        out.push(c);
        c *= x;
    }
    out
}

fn prologue(s: super::Shape, n: usize, segments: usize, t: &mut Transcript) {
    t.absorb(b"zheng-air-v2");
    for v in [s.w1, s.w2, s.challenges, s.constraints, s.degree, n, segments] {
        t.absorb_u64(v as u64);
    }
}

fn squeeze_vec(t: &mut Transcript, k: usize) -> Vec<Fp3> {
    (0..k).map(|_| t.squeeze_fp3()).collect()
}

/// `Σ_c eq(γ, c)·vals[c]`.
fn fold_cols(gamma: &[Fp3], vals: impl IntoIterator<Item = Fp3>) -> Fp3 {
    eq_table(gamma)
        .iter()
        .zip(vals)
        .fold(Fp3::ZERO, |a, (&e, v)| a + e * v)
}

/// Commit a word (column-major, `padded` columns), absorb its root and
/// answer `s` out-of-domain samples; returns the root and the claims.
pub fn commit_bound(
    whir: &WhirParams,
    trace: &Trace,
    padded: usize,
    s: usize,
    t: &mut Transcript,
) -> (Commitment, Vec<Claim>) {
    let (root, data) = Whir::commit(whir, &trace.column_major(padded));
    t.absorb(root.as_bytes());
    let vars = data.num_vars();
    let claims = (0..s)
        .map(|_| {
            let z = t.squeeze_fp3();
            let y = data.univariate(z);
            t.absorb_fp3(y);
            Claim::univariate(z, vars, y)
        })
        .collect();
    (root, claims)
}

/// The verifier's side of [`commit_bound`].
fn absorb_bound(root: &Commitment, answers: &[Fp3], vars: usize, t: &mut Transcript) -> Vec<Claim> {
    t.absorb(root.as_bytes());
    answers
        .iter()
        .map(|&y| {
            let z = t.squeeze_fp3();
            t.absorb_fp3(y);
            Claim::univariate(z, vars, y)
        })
        .collect()
}

/// The words' instances: claims gathered per word across segments.
fn instances(
    roots: [&[Commitment]; 2],
    bound: [Vec<Vec<Claim>>; 2],
    own: Vec<[Claim; 2]>,
    boundary: Vec<[Claim; 2]>,
) -> Vec<SegmentWords> {
    let s = roots[0].len();
    (0..s)
        .map(|i| {
            let from = &boundary[(i + s - 1) % s];
            [0, 1].map(|w| {
                let mut claims = bound[w][i].clone();
                claims.push(own[i][w].clone());
                claims.push(from[w].clone());
                Instance {
                    root: roots[w][i],
                    ext: false,
                    claims,
                }
            })
        })
        .collect()
}

fn word_vars(n: usize, wp: usize) -> usize {
    n + wp.trailing_zeros() as usize
}

/// Prove segments `w1s` (equal row counts); `phase2(i, challenges)` builds
/// segment `i`'s phase-2 trace (segments in order). Returns the proof, the
/// phase-2 traces and every word's instance.
pub fn prove<A: Air>(
    airs: &[A],
    whir: &WhirParams,
    w1s: &[Trace],
    mut phase2: impl FnMut(usize, &[Fp3]) -> Trace,
    t: &mut Transcript,
) -> Result<(AirProof, Vec<Trace>, Vec<SegmentWords>), String> {
    let segs = w1s.len();
    if segs == 0 || airs.len() != segs {
        return Err("air: segments".into());
    }
    let s = airs[0].shape();
    let rows = w1s[0].rows();
    if !rows.is_power_of_two() || rows < 2 || w1s.iter().any(|w| w.rows() != rows || w.width != s.w1) {
        return Err("air: trace shape".into());
    }
    if s.w2 == 0 {
        return Err("air: a phase-2 trace is required".into());
    }
    let n = rows.trailing_zeros() as usize;
    let wp = s.padded_width();
    let nood = crate::accumulate::fresh_ood(whir, word_vars(n, wp))?;
    prologue(s, n, segs, t);
    let (roots1, bound1): (Vec<Commitment>, Vec<Vec<Claim>>) =
        w1s.iter().map(|w| commit_bound(whir, w, wp, nood, t)).unzip();
    let ch = squeeze_vec(t, s.challenges);
    let w2s: Vec<Trace> = (0..segs).map(|i| phase2(i, &ch)).collect();
    if w2s.iter().any(|w| w.width != s.w2 || w.rows() != rows) {
        return Err("air: phase-2 trace shape".into());
    }
    let (roots2, bound2): (Vec<Commitment>, Vec<Vec<Claim>>) =
        w2s.iter().map(|w| commit_bound(whir, w, wp, nood, t)).unzip();
    let answers = |b: &[Vec<Claim>]| -> Vec<Vec<Fp3>> {
        b.iter().map(|cs| cs.iter().map(|c| c.value).collect()).collect()
    };
    let (ood1, ood2) = (answers(&bound1), answers(&bound2));
    let mut segments = Vec::with_capacity(segs);
    let mut own = Vec::with_capacity(segs);
    let mut bound = Vec::with_capacity(segs);
    for i in 0..segs {
        let j = (i + 1) % segs;
        let boundary: Vec<Goldilocks> = w1s[j].row(0).iter().chain(w2s[j].row(0)).copied().collect();
        let (proof, claims, bclaims) = prove_segment(&airs[i], &w1s[i], &w2s[i], boundary, &ch, wp, t);
        segments.push(proof);
        own.push(claims);
        bound.push(bclaims);
    }
    let words = instances([&roots1, &roots2], [bound1, bound2], own, bound);
    Ok((
        AirProof {
            roots1,
            roots2,
            ood1,
            ood2,
            segments,
        },
        w2s,
        words,
    ))
}

#[allow(clippy::type_complexity)]
fn prove_segment<A: Air>(
    air: &A,
    w1: &Trace,
    w2: &Trace,
    boundary: Vec<Goldilocks>,
    ch: &[Fp3],
    wp: usize,
    t: &mut Transcript,
) -> (SegmentProof, [Claim; 2], [Claim; 2]) {
    let s = air.shape();
    let rows = w1.rows();
    let n = rows.trailing_zeros() as usize;
    let w = s.w1 + s.w2;
    for &b in &boundary {
        t.absorb_goldilocks(b);
    }
    let tau = squeeze_vec(t, n);
    let mu = powers(t.squeeze_fp3(), s.constraints);
    let cell = |r: usize, c: usize| if c < s.w1 { w1.row(r)[c] } else { w2.row(r)[c - s.w1] };
    let mut cols: Vec<Vec<Fp3>> = Vec::with_capacity(2 * w + air.publics().len());
    for c in 0..w {
        cols.push((0..rows).map(|r| Fp3::from_base(cell(r, c))).collect());
    }
    for (c, &b) in boundary.iter().enumerate() {
        cols.push(
            (0..rows)
                .map(|r| Fp3::from_base(if r + 1 < rows { cell(r + 1, c) } else { b }))
                .collect(),
        );
    }
    for p in air.publics() {
        cols.push(p.table(n));
    }
    let (zc, rho, evals) = zerocheck::prove(air, w, cols, eq_table(&tau), ch, &mu, t);
    let local = evals[..w].to_vec();
    let next = evals[w..2 * w].to_vec();
    t.absorb_fp3_slice(&local);
    t.absorb_fp3_slice(&next);
    let cbits = wp.trailing_zeros() as usize;
    let (g1, g2) = (squeeze_vec(t, cbits), squeeze_vec(t, cbits));
    let (beta, zeta) = (t.squeeze_fp3(), t.squeeze_fp3());
    let (e1, e2) = (eq_table(&g1), eq_table(&g2));
    let mix = |row: &[Goldilocks], e: &[Fp3]| {
        row.iter().zip(e).fold(Fp3::ZERO, |a, (&x, &q)| a + q * Fp3::from_base(x))
    };
    let p1: Vec<Fp3> = (0..rows).map(|r| mix(w1.row(r), &e1)).collect();
    let p2: Vec<Fp3> = (0..rows).map(|r| mix(w2.row(r), &e2)).collect();
    let eqr = eq_table(&rho);
    let nx = next_table(&rho);
    let kt: Vec<Fp3> = (0..rows)
        .map(|y| eqr[y] + if y == 0 { Fp3::ZERO } else { beta * nx[y] })
        .collect();
    let q: Vec<Fp3> = p1.iter().zip(&p2).map(|(&a, &b)| a + zeta * b).collect();
    let mut extra = vec![p1, p2];
    let (sh, rho2) = shift::prove(t, kt, q, &mut extra);
    let (v1, v2) = (extra[0][0], extra[1][0]);
    t.absorb_fp3(v1);
    t.absorb_fp3(v2);
    let at = |g: &[Fp3]| -> Vec<Fp3> { rho2.iter().chain(g).copied().collect() };
    let own = [
        Claim { point: at(&g1), value: v1 },
        Claim { point: at(&g2), value: v2 },
    ];
    let bclaims = boundary_claims(&boundary, s.w1, n, cbits, t);
    let proof = SegmentProof {
        boundary,
        zerocheck: zc,
        local,
        next,
        shift: sh,
        v1,
        v2,
    };
    (proof, own, bclaims)
}

/// The claims tying a boundary row to the next segment's words at row 0.
fn boundary_claims(b: &[Goldilocks], w1: usize, n: usize, cbits: usize, t: &mut Transcript) -> [Claim; 2] {
    let (g1, g2) = (squeeze_vec(t, cbits), squeeze_vec(t, cbits));
    let lift = |xs: &[Goldilocks]| xs.iter().map(|&x| Fp3::from_base(x)).collect::<Vec<_>>();
    let zero = vec![Fp3::ZERO; n];
    let at = |g: &[Fp3]| -> Vec<Fp3> { zero.iter().chain(g).copied().collect() };
    [
        Claim {
            point: at(&g1),
            value: fold_cols(&g1, lift(&b[..w1])),
        },
        Claim {
            point: at(&g2),
            value: fold_cols(&g2, lift(&b[w1..])),
        },
    ]
}

/// Verify the IOP part over `2^n`-row segments; returns every word's
/// instance (the openings are left to accumulation).
pub fn verify<A: Air>(
    airs: &[A],
    whir: &WhirParams,
    n: usize,
    proof: &AirProof,
    t: &mut Transcript,
) -> Result<Vec<SegmentWords>, String> {
    let segs = proof.segments.len();
    if segs == 0
        || airs.len() != segs
        || [proof.roots1.len(), proof.roots2.len(), proof.ood1.len(), proof.ood2.len()]
            .iter()
            .any(|&l| l != segs)
    {
        return Err("air: segment count".into());
    }
    let s = airs[0].shape();
    let w = s.w1 + s.w2;
    let wp = s.padded_width();
    let cbits = wp.trailing_zeros() as usize;
    let vars = word_vars(n, wp);
    let nood = crate::accumulate::fresh_ood(whir, vars)?;
    if proof.ood1.iter().chain(&proof.ood2).any(|a| a.len() != nood) {
        return Err("air: OOD answers".into());
    }
    prologue(s, n, segs, t);
    let bound1: Vec<Vec<Claim>> = proof
        .roots1
        .iter()
        .zip(&proof.ood1)
        .map(|(r, a)| absorb_bound(r, a, vars, t))
        .collect();
    let ch = squeeze_vec(t, s.challenges);
    let bound2: Vec<Vec<Claim>> = proof
        .roots2
        .iter()
        .zip(&proof.ood2)
        .map(|(r, a)| absorb_bound(r, a, vars, t))
        .collect();
    let mut own = Vec::with_capacity(segs);
    let mut bound = Vec::with_capacity(segs);
    for (air, sp) in airs.iter().zip(&proof.segments) {
        if sp.boundary.len() != w || sp.local.len() != w || sp.next.len() != w {
            return Err("air: segment shape".into());
        }
        for &b in &sp.boundary {
            t.absorb_goldilocks(b);
        }
        let tau = squeeze_vec(t, n);
        let mu = powers(t.squeeze_fp3(), s.constraints);
        let (rho, claim) =
            zerocheck::verify(t, &sp.zerocheck, n, s.degree).ok_or("air: zerocheck shape")?;
        let publics: Vec<Fp3> = air.publics().iter().map(|p| p.eval(&rho)).collect();
        let vals: Vec<Fp3> = sp.local.iter().chain(&sp.next).chain(&publics).copied().collect();
        let mut scratch = vec![Fp3::ZERO; s.constraints];
        let c = zerocheck::combine(air, w, &vals, &ch, &mu, &mut scratch);
        if eq_eval(&tau, &rho) * c != claim {
            return Err("air: constraints do not hold".into());
        }
        t.absorb_fp3_slice(&sp.local);
        t.absorb_fp3_slice(&sp.next);
        let (g1, g2) = (squeeze_vec(t, cbits), squeeze_vec(t, cbits));
        let (beta, zeta) = (t.squeeze_fp3(), t.squeeze_fp3());
        // the last row's next is the boundary, not row 0
        let last = rho.iter().fold(Fp3::ONE, |a, &r| a * r);
        let lift = |xs: &[Goldilocks]| xs.iter().map(|&x| Fp3::from_base(x)).collect::<Vec<_>>();
        let b1 = fold_cols(&g1, lift(&sp.boundary[..s.w1]));
        let b2 = fold_cols(&g2, lift(&sp.boundary[s.w1..]));
        let a1 = fold_cols(&g1, sp.local[..s.w1].iter().copied());
        let n1 = fold_cols(&g1, sp.next[..s.w1].iter().copied()) - last * b1;
        let a2 = fold_cols(&g2, sp.local[s.w1..].iter().copied());
        let n2 = fold_cols(&g2, sp.next[s.w1..].iter().copied()) - last * b2;
        let sigma = a1 + beta * n1 + zeta * (a2 + beta * n2);
        let (rho2, fin) = shift::verify(t, sigma, &sp.shift, n).ok_or("air: shift shape")?;
        let wrap = rho.iter().zip(&rho2).fold(Fp3::ONE, |a, (&x, &y)| a * x * (Fp3::ONE - y));
        let k = eq_eval(&rho, &rho2) + beta * (next_eval(&rho, &rho2) - wrap);
        if k * (sp.v1 + zeta * sp.v2) != fin {
            return Err("air: shift reduction".into());
        }
        t.absorb_fp3(sp.v1);
        t.absorb_fp3(sp.v2);
        let at = |g: &[Fp3]| -> Vec<Fp3> { rho2.iter().chain(g).copied().collect() };
        own.push([
            Claim { point: at(&g1), value: sp.v1 },
            Claim { point: at(&g2), value: sp.v2 },
        ]);
        bound.push(boundary_claims(&sp.boundary, s.w1, n, cbits, t));
    }
    Ok(instances([&proof.roots1, &proof.roots2], [bound1, bound2], own, bound))
}
