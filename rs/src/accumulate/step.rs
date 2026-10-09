//! One accumulation step: `m` instances → one accumulator (module docs of
//! [`super`]; `specs/accumulation.md` § protocol).

use lens::rspcs::pow;
use lens::rspcs::whir::{Opening, verify_leaves};
use lens::{Commitment, Transcript, Whir};
use nebu::Fp3;

use super::sumcheck::{self, Weight};
use super::{AccConfig, Claim, Instance, Witnessed};

/// The prover's accumulator: the instance and the committed word `g`.
pub type Accumulator = Witnessed;

/// What an accumulation step sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccProof {
    /// Claim-batching sumcheck: `(h(0), h(2))` per variable.
    pub sumcheck: Vec<Fp3>,
    /// `μ_i = f_i(ρ)` for every input word.
    pub evals: Vec<Fp3>,
    pub comb_nonce: Option<u64>,
    /// Root of the new word `g` (Fp3 symbols).
    pub root: Commitment,
    /// `ĝ(ζ_j)` for the OOD samples.
    pub ood: Vec<Fp3>,
    pub query_nonce: Option<u64>,
    /// One multi-opening per input word at the spot-check leaves.
    pub openings: Vec<Opening>,
}

/// The claim weights of every input under the batching challenge `γ`:
/// claims are numbered across inputs in order, claim `e` gets `γ^e`.
fn weights(inputs: &[&Instance], gamma: Fp3) -> (Vec<Weight>, Fp3) {
    let mut g = Fp3::ONE;
    let mut sigma = Fp3::ZERO;
    let ws = inputs
        .iter()
        .map(|inst| Weight {
            terms: inst
                .claims
                .iter()
                .map(|c| {
                    sigma += g * c.value;
                    let term = (c.point.clone(), g);
                    g *= gamma;
                    term
                })
                .collect(),
        })
        .collect();
    (ws, sigma)
}

fn shape_ok(cfg: &AccConfig, inputs: &[&Instance]) -> Result<(), String> {
    if inputs.is_empty() || inputs.len() > cfg.max_inputs {
        return Err(format!("acc: {} inputs (1..={})", inputs.len(), cfg.max_inputs));
    }
    if inputs
        .iter()
        .flat_map(|i| &i.claims)
        .any(|c| c.point.len() != cfg.num_vars)
    {
        return Err("acc: claim dimension".into());
    }
    Ok(())
}

/// Spot-check symbol positions, and the sorted distinct leaves holding them.
fn positions(cfg: &AccConfig, t: &mut Transcript) -> (Vec<usize>, Vec<usize>) {
    let symbols = t.squeeze_indices(cfg.queries, cfg.layout.log_domain);
    let mut leaves: Vec<usize> = symbols.iter().map(|&s| cfg.layout.locate(s).0).collect();
    leaves.sort_unstable();
    leaves.dedup();
    (symbols, leaves)
}

/// The new accumulator's claims.
fn new_claims(
    cfg: &AccConfig,
    rho: Vec<Fp3>,
    combined: Fp3,
    zetas: &[Fp3],
    ood: &[Fp3],
    symbols: &[usize],
    spot: &[Fp3],
) -> Vec<Claim> {
    let mut claims = vec![Claim {
        point: rho,
        value: combined,
    }];
    for (&z, &y) in zetas.iter().zip(ood) {
        claims.push(Claim::univariate(z, cfg.num_vars, y));
    }
    for (&s, &y) in symbols.iter().zip(spot) {
        let x = Fp3::from_base(cfg.layout.point(s));
        claims.push(Claim::univariate(x, cfg.num_vars, y));
    }
    claims
}

fn powers(r: Fp3, m: usize) -> Vec<Fp3> {
    let mut out = Vec::with_capacity(m);
    let mut c = Fp3::ONE;
    for _ in 0..m {
        out.push(c);
        c *= r;
    }
    out
}

/// Accumulate `inputs` (all over `cfg`'s code). `t` must be the caller's
/// accumulation transcript; the verifier replays it with [`verify_step`].
pub fn accumulate(
    cfg: &AccConfig,
    inputs: &[&Witnessed],
    t: &mut Transcript,
) -> Result<(Accumulator, AccProof), String> {
    let insts: Vec<&Instance> = inputs.iter().map(|w| &w.instance).collect();
    shape_ok(cfg, &insts)?;
    if inputs.iter().any(|w| w.data.num_vars() != cfg.num_vars) {
        return Err("acc: word size".into());
    }
    t.absorb(b"zheng-acc-step-v1");
    t.absorb_u64(insts.len() as u64);
    for inst in &insts {
        inst.absorb(t);
    }
    let gamma = t.squeeze_fp3();
    let (ws, _) = weights(&insts, gamma);
    let tables: Vec<Vec<Fp3>> = inputs.iter().map(|w| w.data.table()).collect();
    let (msgs, rho, evals) = sumcheck::prove(t, tables.clone(), &ws, cfg.num_vars);
    t.absorb_fp3_slice(&evals);
    let comb_nonce = pow::grind(t, cfg.comb_pow_for(inputs.len()));
    let r = t.squeeze_fp3();
    let coef = powers(r, inputs.len());
    let mut g = vec![Fp3::ZERO; 1 << cfg.num_vars];
    for (table, &c) in tables.iter().zip(&coef) {
        for (gi, &f) in g.iter_mut().zip(table) {
            *gi += c * f;
        }
    }
    let combined = evals.iter().zip(&coef).fold(Fp3::ZERO, |a, (&e, &c)| a + c * e);
    let (root, data) = Whir::commit_ext(&cfg.whir, &g);
    t.absorb(root.as_bytes());
    let mut zetas = Vec::with_capacity(cfg.ood);
    let mut ood = Vec::with_capacity(cfg.ood);
    for _ in 0..cfg.ood {
        let z = t.squeeze_fp3();
        let y = data.univariate(z);
        t.absorb_fp3(y);
        zetas.push(z);
        ood.push(y);
    }
    let query_nonce = pow::grind(t, cfg.query_pow);
    let (symbols, leaves) = positions(cfg, t);
    let openings: Vec<Opening> = inputs.iter().map(|w| w.data.open_leaves(&leaves)).collect();
    let spot: Vec<Fp3> = symbols
        .iter()
        .map(|&s| {
            inputs
                .iter()
                .zip(&coef)
                .fold(Fp3::ZERO, |a, (w, &c)| a + c * w.data.symbol(s))
        })
        .collect();
    let claims = new_claims(cfg, rho, combined, &zetas, &ood, &symbols, &spot);
    let instance = Instance {
        root,
        ext: true,
        claims,
    };
    let proof = AccProof {
        sumcheck: msgs,
        evals,
        comb_nonce,
        root,
        ood,
        query_nonce,
        openings,
    };
    Ok((Witnessed { instance, data }, proof))
}

fn nonce_ok(t: &mut Transcript, bits: u32, nonce: Option<u64>) -> bool {
    match (bits, nonce) {
        (0, None) => true,
        (b, Some(n)) if b > 0 => pow::check(t, b, n),
        _ => false,
    }
}

/// Verify one step and derive the new accumulator instance.
pub fn verify_step(
    cfg: &AccConfig,
    inputs: &[&Instance],
    proof: &AccProof,
    t: &mut Transcript,
) -> Result<Instance, String> {
    shape_ok(cfg, inputs)?;
    let m = inputs.len();
    if proof.evals.len() != m || proof.openings.len() != m || proof.ood.len() != cfg.ood {
        return Err("acc: proof shape".into());
    }
    t.absorb(b"zheng-acc-step-v1");
    t.absorb_u64(m as u64);
    for inst in inputs {
        inst.absorb(t);
    }
    let gamma = t.squeeze_fp3();
    let (ws, sigma) = weights(inputs, gamma);
    let (rho, last) = sumcheck::verify(t, sigma, &proof.sumcheck, cfg.num_vars)
        .ok_or("acc: sumcheck shape")?;
    let expect = ws
        .iter()
        .zip(&proof.evals)
        .fold(Fp3::ZERO, |a, (w, &e)| a + w.eval(&rho) * e);
    if expect != last {
        return Err("acc: sumcheck final claim".into());
    }
    t.absorb_fp3_slice(&proof.evals);
    if !nonce_ok(t, cfg.comb_pow_for(m), proof.comb_nonce) {
        return Err("acc: combination grinding".into());
    }
    let r = t.squeeze_fp3();
    let coef = powers(r, m);
    let combined = proof
        .evals
        .iter()
        .zip(&coef)
        .fold(Fp3::ZERO, |a, (&e, &c)| a + c * e);
    t.absorb(proof.root.as_bytes());
    let mut zetas = Vec::with_capacity(cfg.ood);
    for &y in &proof.ood {
        zetas.push(t.squeeze_fp3());
        t.absorb_fp3(y);
    }
    if !nonce_ok(t, cfg.query_pow, proof.query_nonce) {
        return Err("acc: query grinding".into());
    }
    let (symbols, leaves) = positions(cfg, t);
    let mut spot = vec![Fp3::ZERO; symbols.len()];
    for ((inst, opening), &c) in inputs.iter().zip(&proof.openings).zip(&coef) {
        let got = verify_leaves(&inst.root.0, &cfg.layout, inst.ext, &leaves, opening)
            .map_err(|e| format!("acc: opening: {e}"))?;
        for (y, &s) in spot.iter_mut().zip(&symbols) {
            let (leaf, pos) = cfg.layout.locate(s);
            let q = leaves.binary_search(&leaf).expect("leaf of a sampled symbol");
            *y += c * got[q][pos];
        }
    }
    let claims = new_claims(cfg, rho, combined, &zetas, &proof.ood, &symbols, &spot);
    Ok(Instance {
        root: proof.root,
        ext: true,
        claims,
    })
}

/// `Σ_j c_j eq(z_j, x)` for an instance's claims under powers of `γ`
/// (the decider's weight).
pub(crate) fn single_weight(inst: &Instance, gamma: Fp3) -> (Weight, Fp3) {
    let (mut ws, sigma) = weights(&[inst], gamma);
    (ws.remove(0), sigma)
}
