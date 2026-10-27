//! The decider: one accumulator (or any instance) → a claim-batching
//! sumcheck and one WHIR opening of its word.
//!
//! `γ` batches the instance's `J` claims into `Σ_b w(b)·f(b) = σ` with
//! `w = Σ_j γ^j eq(z_j, ·)`; the sumcheck ends at `ρ*` with the claim
//! `w(ρ*)·f(ρ*)`; the prover sends `v* = f(ρ*)` and opens the word at `ρ*`
//! with WHIR (an Fp3 opening for an accumulator). Soundness: the batching
//! and sumcheck terms of [`super::config`] with `m = 1`, plus WHIR's proven
//! bound at `(whir, ℓ)` (lens `security_bits`), whose round-0 distance is
//! the accumulation's `δ`.

use lens::rspcs::WhirProof;
use lens::{MultilinearPcs, Transcript, Whir};
use nebu::Fp3;

use super::step::single_weight;
use super::sumcheck;
use super::{AccConfig, Instance, Witnessed};

/// A decider proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeciderProof {
    pub sumcheck: Vec<Fp3>,
    /// `f(ρ*)`.
    pub value: Fp3,
    pub whir: WhirProof,
}

fn whir_transcript(t: &mut Transcript) -> Transcript {
    let seed = t.squeeze();
    let mut lt = Transcript::new(b"zheng-acc-decide-whir-v1");
    lt.absorb(seed.as_bytes());
    lt
}

/// Prove that `acc`'s word is a codeword whose message satisfies its claims.
pub fn decide(cfg: &AccConfig, acc: &Witnessed, t: &mut Transcript) -> Result<DeciderProof, String> {
    let inst = &acc.instance;
    if acc.data.num_vars() != cfg.num_vars || acc.data.is_ext() != inst.ext {
        return Err("decide: word shape".into());
    }
    t.absorb(b"zheng-acc-decide-v1");
    inst.absorb(t);
    let gamma = t.squeeze_fp3();
    let (w, _) = single_weight(inst, gamma);
    let (msgs, point, evals) = sumcheck::prove(t, vec![acc.data.table()], &[w], cfg.num_vars);
    let value = evals[0];
    t.absorb_fp3(value);
    let mut lt = whir_transcript(t);
    let (v, whir) = Whir::open(&cfg.whir, &acc.data, &point, &mut lt);
    debug_assert_eq!(v, value);
    Ok(DeciderProof {
        sumcheck: msgs,
        value,
        whir,
    })
}

/// Verify a decider proof for `inst`.
pub fn verify_decider(
    cfg: &AccConfig,
    inst: &Instance,
    proof: &DeciderProof,
    t: &mut Transcript,
) -> Result<(), String> {
    if inst.claims.iter().any(|c| c.point.len() != cfg.num_vars) || inst.claims.len() > cfg.max_claims.max(cfg.acc_claims()) {
        return Err("decide: claim shape".into());
    }
    t.absorb(b"zheng-acc-decide-v1");
    inst.absorb(t);
    let gamma = t.squeeze_fp3();
    let (w, sigma) = single_weight(inst, gamma);
    let (point, last) = sumcheck::verify(t, sigma, &proof.sumcheck, cfg.num_vars)
        .ok_or("decide: sumcheck shape")?;
    if w.eval(&point) * proof.value != last {
        return Err("decide: sumcheck final claim".into());
    }
    t.absorb_fp3(proof.value);
    let mut lt = whir_transcript(t);
    let r = if inst.ext {
        Whir::verify_ext(&cfg.whir, &inst.root, cfg.num_vars, &point, proof.value, &proof.whir, &mut lt)
    } else {
        Whir::verify(&cfg.whir, &inst.root, cfg.num_vars, &point, proof.value, &proof.whir, &mut lt)
    };
    r.map_err(|e| format!("decide: whir: {e}"))
}
