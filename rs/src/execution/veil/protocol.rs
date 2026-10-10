//! The zk protocol: Spartan over Fp3 on the masked relation, both sumchecks
//! masked (Libra), every committed value under one hiding commitment, and
//! one linear opening that carries every final claim.
//!
//! Transcript (`zheng` transcript `T`, Fp3 challenges):
//!
//! 1. `T ← "zheng-veil-v1" ‖ statement ‖ params ‖ ℓ ‖ m ‖ d ‖ root`, where
//!    the root commits `(w ‖ g1 ‖ g2)`: the free half of the masked
//!    relation's witness and the two masks' coefficients;
//! 2. outer: `τ`; `T ← Σ g1`; `ρ1`; sumcheck of `eq(τ,·)·G + ρ1·g1` from
//!    `ρ1·Σ g1` (log m rounds, degree d); `T ← v = M̃_i z(ρ_x)`;
//! 3. inner: `γ`; the verifier subtracts the pinned half,
//!    `P = Σ_slot A(1, slot)·p_slot`, from `Σ γ^i v_i`; `T ← Σ g2`; `ρ2`;
//!    sumcheck of `A(0,·)·w̃ + ρ2·g2` over ℓ variables;
//! 4. `λ`; the verifier derives `g1(ρ_x) = (C1 − eq(τ,ρ_x)·G(v))/ρ1` and
//!    asks one opening of `λ·g1(ρ_x) + A(0,r')·w̃(r') + ρ2·g2(r')` at the
//!    value `λ·g1(ρ_x) + C2`, on a lens transcript seeded by a squeeze of
//!    `T`.

use lens::Transcript as LensTranscript;
use nebu::{Fp3, Goldilocks};

use super::coins::Coins;
use super::hiding::{self, Config, Functional, HidingParams};
use super::libra::{self, Mask};
use super::pad::{self, Extension};
use super::wire::{Parsed, Shape};
use crate::execution::succinct::protocol::Layout;
use crate::field::ChallengeField;
use crate::multilinear::eq_evals;
use crate::spartan::iop::combined_weights;
use crate::spartan::reduce::{self, CompressedRounds, Reduction};
use crate::sumcheck::prover::{OuterSumcheckProver, SumcheckProver};
use crate::sumcheck::verifier::SumcheckVerifier;
use crate::transcript::Transcript;
use crate::types::CCSInstance;

const DOMAIN: &[u8] = b"zheng-veil-v1";
const PCS_DOMAIN: &[u8] = b"zheng-veil-pcs-v1";

/// What prover and verifier derive from the relation and the pins.
pub(crate) struct Setup {
    pub instance: CCSInstance,
    pub ext: Extension,
    pub layout: Layout,
    pub log_m: usize,
    pub degree: usize,
}

impl Setup {
    pub fn new(base: &CCSInstance, pins: &[(usize, Goldilocks)]) -> Result<Self, String> {
        let (instance, ext) = pad::extend(base)?;
        let layout = Layout::new(&instance, pins)?;
        if !instance.num_rows.is_power_of_two() {
            return Err("veil: row count".into());
        }
        let log_m = instance.num_rows.trailing_zeros() as usize;
        let degree = usize::from(reduce::outer_degree(&instance));
        Ok(Self {
            instance,
            ext,
            layout,
            log_m,
            degree,
        })
    }
    pub fn half(&self) -> usize {
        1 << self.layout.vars
    }
    fn mask1(&self) -> usize {
        Mask::entries(self.log_m, self.degree)
    }
    fn mask2(&self) -> usize {
        Mask::entries(self.layout.vars, 2)
    }
    pub fn entries(&self) -> usize {
        self.half() + self.mask1() + self.mask2()
    }
    pub fn shape(&self) -> Shape {
        Shape {
            log_m: self.log_m,
            degree: self.degree,
            matrices: self.instance.matrices.len(),
            vars: self.layout.vars,
            entries: self.entries(),
        }
    }
    /// The functional of the final claim.
    fn functional(&self, a0: Fp3, r: &[Fp3], lambda: Fp3, rho_x: &[Fp3], rho2: Fp3) -> Functional {
        let start = self.half();
        let w1 = libra::weights(rho_x, self.degree, lambda);
        let w2 = libra::weights(r, 2, rho2);
        Functional {
            scale: a0,
            point: r.to_vec(),
            explicit: w1.into_iter().chain(w2).enumerate().map(|(i, w)| (start + i, w)).collect(),
        }
    }
}

fn prologue(t: &mut Transcript, statement: &[u8], params: &HidingParams, s: &Setup) {
    t.absorb(DOMAIN);
    t.absorb(&(statement.len() as u64).to_le_bytes());
    t.absorb(statement);
    t.absorb(&params.header());
    for v in [s.layout.vars, s.instance.num_rows, s.degree] {
        t.absorb(&(v as u64).to_le_bytes());
    }
}

fn pcs_transcript(t: &mut Transcript) -> LensTranscript {
    let seed = t.squeeze_hash();
    let mut lt = LensTranscript::new(PCS_DOMAIN);
    lt.absorb(&seed);
    lt
}

/// `eq(τ, ρ_x)`: τ_j pairs with ρ_x[log m − 1 − j] (see `reduce`).
fn eq_tau_rho(tau: &[Fp3], rho_x: &[Fp3]) -> Fp3 {
    tau.iter()
        .zip(rho_x.iter().rev())
        .fold(Fp3::ONE, |acc, (&t, &r)| acc * (t * r + (Fp3::ONE - t) * (Fp3::ONE - r)))
}

fn gate(instance: &CCSInstance, v: &[Fp3]) -> Fp3 {
    instance.multisets.iter().zip(&instance.coeffs).fold(Fp3::ZERO, |acc, (set, &c)| {
        acc + Fp3::from_base(c) * set.iter().fold(Fp3::ONE, |p, &i| p * v[i])
    })
}

/// `P = Σ_i γ^i Σ_row eq(ρ_x, row) Σ_{pinned c} M_i[row][c]·p(c)`.
fn pinned_part(s: &Setup, rho_x: &[Fp3], gamma: Fp3) -> Fp3 {
    let rho_rev: Vec<Fp3> = rho_x.iter().rev().copied().collect();
    let eq_row = eq_evals(&rho_rev);
    let half = s.half();
    let mut acc = Fp3::ZERO;
    let mut g = Fp3::ONE;
    for m in &s.instance.matrices {
        let mut sum = Fp3::ZERO;
        for (row, entries) in m.entries.iter().enumerate() {
            let mut row_sum = Goldilocks::ZERO;
            for &(c, v) in entries {
                if let Some(slot) = s.layout.map.get(c).copied().flatten().filter(|&x| x >= half) {
                    row_sum += v * s.layout.public[slot - half].1;
                }
            }
            if row_sum != Goldilocks::ZERO {
                sum += eq_row[row] * Fp3::from_base(row_sum);
            }
        }
        acc += g * sum;
        g *= gamma;
    }
    acc
}

/// `A(0, r) = Σ_i γ^i M̃'_i(ρ_x, (0, r))`.
fn free_weight(s: &Setup, rho_x: &[Fp3], gamma: Fp3, r: &[Fp3]) -> Fp3 {
    let point: Vec<Fp3> = core::iter::once(Fp3::ZERO).chain(r.iter().copied()).collect();
    let red = Reduction {
        point,
        claim: Fp3::ZERO,
        rho_x: rho_x.to_vec(),
        gamma,
    };
    s.layout.weight(&s.instance, &red)
}

/// Prove that `z` (a witness of `base`, pins `(0, 1)` first) satisfies the
/// relation, hiding everything but the pins.
pub(crate) fn prove(
    params: &HidingParams,
    base: &CCSInstance,
    z: &[Goldilocks],
    pins: &[(usize, Goldilocks)],
    statement: &[u8],
    coins: &mut Coins,
) -> Result<Parsed, String> {
    if z.len() != base.num_cols || pins.iter().any(|&(i, v)| z[i] != v) {
        return Err("veil: witness disagrees with the statement".into());
    }
    let s = Setup::new(base, pins)?;
    let z = s.ext.witness(z, s.instance.num_cols, coins);
    let relabelled = s.layout.instance(&s.instance);
    let mut zp = vec![Goldilocks::ZERO; relabelled.num_cols];
    for (col, slot) in s.layout.map.iter().enumerate() {
        if let Some(x) = slot {
            zp[*x] = z[col];
        }
    }
    let half = s.half();
    let g1 = Mask::sample(s.log_m, s.degree, coins);
    let g2 = Mask::sample(s.layout.vars, 2, coins);
    let mut entries = zp[..half].to_vec();
    entries.extend(g1.limbs());
    entries.extend(g2.limbs());
    let (root, committed) = hiding::commit(params, &entries, coins)?;

    let mut t = Transcript::new();
    prologue(&mut t, statement, params, &s);
    t.absorb_commitment(&root);
    // outer
    let tau: Vec<Fp3> = (0..s.log_m).map(|_| Fp3::squeeze(&mut t)).collect();
    let row_mv: Vec<Vec<Fp3>> = relabelled
        .matrices
        .iter()
        .map(|m| {
            m.entries
                .iter()
                .map(|row| {
                    Fp3::from_base(row.iter().fold(Goldilocks::ZERO, |acc, &(c, v)| acc + v * zp[c]))
                })
                .collect()
        })
        .collect();
    let coeffs = relabelled.coeffs.iter().map(|&c| Fp3::from_base(c)).collect();
    let mut outer =
        OuterSumcheckProver::new(eq_evals(&tau), row_mv, relabelled.multisets.clone(), coeffs);
    let g1_sum = g1.sum();
    t.absorb_eval(g1_sum);
    let rho1 = Fp3::squeeze(&mut t);
    let mut rho_x = Vec::with_capacity(s.log_m);
    let mut outer_polys = Vec::with_capacity(s.log_m);
    for j in 0..s.log_m {
        let poly = libra::masked(outer.round_poly(), rho1, &g1.round_poly(&rho_x));
        t.absorb_sumcheck_poly(j, &poly);
        let r = Fp3::squeeze(&mut t);
        outer.fold(r);
        rho_x.push(r);
        outer_polys.push(poly);
    }
    let evals = outer.matrix_evals();
    for &e in &evals {
        t.absorb_eval(e);
    }
    // inner, over the free half
    let gamma = Fp3::squeeze(&mut t);
    let a_full = combined_weights(&relabelled, &rho_x, gamma, 2 * half);
    let w: Vec<Fp3> = zp[..half].iter().map(|&v| Fp3::from_base(v)).collect();
    let mut inner = SumcheckProver::new(a_full[..half].to_vec(), w);
    let g2_sum = g2.sum();
    t.absorb_eval(g2_sum);
    let rho2 = Fp3::squeeze(&mut t);
    let mut r = Vec::with_capacity(s.layout.vars);
    let mut inner_polys = Vec::with_capacity(s.layout.vars);
    for j in 0..s.layout.vars {
        let poly = libra::masked(inner.round_poly(), rho2, &g2.round_poly(&r));
        t.absorb_sumcheck_poly(j, &poly);
        let x = Fp3::squeeze(&mut t);
        inner.fold(x);
        r.push(x);
        inner_polys.push(poly);
    }
    let lambda = Fp3::squeeze(&mut t);
    // the final claims, assembled exactly as the verifier will
    let a0 = free_weight(&s, &rho_x, gamma, &r);
    let (w_eval, a_eval) = {
        let (a, f) = inner.final_claim();
        (f, a)
    };
    debug_assert_eq!(a_eval, a0);
    let value = lambda * g1.eval_at(&rho_x) + a0 * w_eval + rho2 * g2.eval_at(&r);
    let f = s.functional(a0, &r, lambda, &rho_x, rho2);
    let mut lt = pcs_transcript(&mut t);
    let opening = hiding::open(&committed, &f, value, &mut lt);
    Ok(Parsed {
        root,
        g1: g1_sum,
        outer: reduce::compress(&outer_polys),
        evals,
        g2: g2_sum,
        inner: reduce::compress(&inner_polys),
        opening,
    })
}

fn rounds(
    claim: Fp3,
    degree: usize,
    rounds: &CompressedRounds<Fp3>,
    t: &mut Transcript,
) -> Result<(Fp3, Vec<Fp3>), String> {
    let mut v = SumcheckVerifier::new(claim, rounds.rounds.len());
    for (i, rest) in rounds.rounds.iter().enumerate() {
        let poly = reduce::decompress(v.current_claim(), degree as u8, rest)
            .ok_or_else(|| format!("veil: round {i} shape"))?;
        v.verify_round(&poly, t).map_err(|e| format!("veil: round {i}: {e:?}"))?;
    }
    Ok((v.current_claim(), v.challenges().to_vec()))
}

/// Verify a parsed proof against the relation and pins the caller derived.
pub(crate) fn verify(
    s: &Setup,
    statement: &[u8],
    proof: &Parsed,
) -> Result<(), String> {
    let params = &proof.opening.params;
    admit(params, s.entries())?;
    let mut t = Transcript::new();
    prologue(&mut t, statement, params, s);
    t.absorb_commitment(&proof.root);
    let tau: Vec<Fp3> = (0..s.log_m).map(|_| Fp3::squeeze(&mut t)).collect();
    t.absorb_eval(proof.g1);
    let rho1 = Fp3::squeeze(&mut t);
    if rho1 == Fp3::ZERO {
        return Err("veil: degenerate challenge".into());
    }
    let (c1, rho_x) = rounds(rho1 * proof.g1, s.degree, &proof.outer, &mut t)?;
    for &e in &proof.evals {
        t.absorb_eval(e);
    }
    let g1_at = (c1 - eq_tau_rho(&tau, &rho_x) * gate(&s.instance, &proof.evals)) * rho1.inv();
    let gamma = Fp3::squeeze(&mut t);
    let (batched, _) = proof
        .evals
        .iter()
        .fold((Fp3::ZERO, Fp3::ONE), |(acc, g), &e| (acc + g * e, g * gamma));
    let claim2 = batched - pinned_part(s, &rho_x, gamma);
    t.absorb_eval(proof.g2);
    let rho2 = Fp3::squeeze(&mut t);
    let (c2, r) = rounds(claim2 + rho2 * proof.g2, 2, &proof.inner, &mut t)?;
    let lambda = Fp3::squeeze(&mut t);
    let a0 = free_weight(s, &rho_x, gamma, &r);
    let f = s.functional(a0, &r, lambda, &rho_x, rho2);
    let mut lt = pcs_transcript(&mut t);
    hiding::verify(params, &proof.root, s.entries(), &f, lambda * g1_at + c2, &proof.opening, &mut lt)
}

/// Bits a zk proof must carry.
pub const MIN_SECURITY_BITS: f64 = 128.0;

/// Admit the parameters a proof names: in range and `≥ 128` proven bits.
pub(crate) fn admit(params: &HidingParams, entries: usize) -> Result<f64, String> {
    let cfg = Config::derive(params, entries)?;
    let bits = cfg.security_bits();
    if bits < MIN_SECURITY_BITS {
        return Err(format!("veil: {bits:.2} proven bits, policy requires {MIN_SECURITY_BITS}"));
    }
    Ok(bits)
}
