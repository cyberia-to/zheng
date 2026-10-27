//! Statements of one CCS relation, folded into one decider (the shape a
//! fold-mining cluster needs: many tickets of one relation, one decider).
//!
//! Each statement runs the succinct profile's IOP (`execution::succinct`:
//! committed free witness, Spartan over Fp3) down to its single evaluation
//! claim `w̃(r') = v`, which becomes an accumulation instance instead of a
//! WHIR opening. The instances are accumulated in steps of at most `chunk`
//! words (the accumulator rides along), and the last accumulator is
//! decided once. The verifier checks every statement's IOP messages, every
//! step and the decider; nothing is opened per statement.

use lens::rspcs::field::ml_eval_base;
use lens::{Commitment, MultilinearPcs, Transcript as LensTranscript, Whir, WhirParams};
use nebu::{Fp3, Goldilocks};

use super::{AccConfig, AccProof, Claim, DeciderProof, Instance, Witnessed};
use crate::execution::succinct::protocol::{Layout, pcs_point, prologue};
use crate::spartan::{iop, reduce};
use crate::types::CCSInstance;

/// One statement of the relation: the verifier-derived instance, its pins
/// (`(0, 1)` first) and the statement bytes.
pub struct Statement<'a> {
    pub instance: &'a CCSInstance,
    pub pins: Vec<(usize, Goldilocks)>,
    pub bytes: Vec<u8>,
}

/// A statement's IOP messages up to its witness claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimProof {
    pub root: Commitment,
    pub matrix_evals: Vec<Fp3>,
    pub outer: reduce::CompressedRounds<Fp3>,
    pub inner: reduce::CompressedRounds<Fp3>,
    pub witness_eval: Fp3,
    /// Answers `ŵ(ζ_j)` to the out-of-domain samples drawn right after the
    /// root (`fresh_ood`): the word is bound to one codeword of its list
    /// before the IOP's challenges.
    pub ood: Vec<Fp3>,
}

/// Domain separation of a claim proof from a succinct-profile proof.
const CLAIM_DOMAIN: &[u8] = b"zheng-ccs-claim-v1";

/// Every statement's claim proof, the accumulation steps and one decider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folded {
    pub claims: Vec<ClaimProof>,
    pub steps: Vec<AccProof>,
    pub decider: DeciderProof,
}

/// The IOP of one statement down to its claim; returns the claim proof and
/// the committed witness as an accumulation input.
pub fn prove_claim(
    whir: &WhirParams,
    st: &Statement<'_>,
    z: &[Goldilocks],
) -> Result<(ClaimProof, Witnessed), String> {
    let instance = st.instance;
    if z.len() != instance.num_cols || st.pins.iter().any(|&(i, v)| z[i] != v) {
        return Err("fold: witness disagrees with the statement".into());
    }
    let layout = Layout::new(instance, &st.pins)?;
    crate::execution::succinct::admit::<Whir>(whir, layout.vars)?;
    let relabelled = layout.instance(instance);
    let mut zp = vec![Goldilocks::ZERO; relabelled.num_cols];
    for (col, slot) in layout.map.iter().enumerate() {
        if let Some(s) = slot {
            zp[*s] = z[col];
        }
    }
    let half = 1usize << layout.vars;
    let (root, data) = Whir::commit(whir, &zp[..half]);
    let mut t = prologue::<Whir>(&st.bytes, whir, layout.vars, instance.num_rows, &root);
    t.absorb(CLAIM_DOMAIN);
    let mut claims = Vec::new();
    let mut ood = Vec::new();
    for _ in 0..super::fresh_ood(whir, layout.vars)? {
        let z = t.squeeze_fp3();
        let y = data.univariate(z);
        t.absorb_eval(y);
        claims.push(Claim::univariate(z, layout.vars, y));
        ood.push(y);
    }
    let (proof, point) = iop::prove::<Fp3>(&relabelled, &zp, &mut t);
    let (outer, inner) = reduce::compress_proof(&proof);
    let cpoint = pcs_point(&point[1..]);
    let witness_eval = ml_eval_base(&zp[..half], &cpoint);
    claims.push(Claim {
        point: cpoint,
        value: witness_eval,
    });
    let cp = ClaimProof {
        root,
        matrix_evals: proof.matrix_evals,
        outer,
        inner,
        witness_eval,
        ood,
    };
    let instance = Instance {
        root,
        ext: false,
        claims,
    };
    Ok((cp, Witnessed { instance, data }))
}

/// Check one statement's IOP messages; returns its accumulation instance.
pub fn verify_claim(whir: &WhirParams, st: &Statement<'_>, proof: &ClaimProof) -> Result<Instance, String> {
    let instance = st.instance;
    let layout = Layout::new(instance, &st.pins)?;
    crate::execution::succinct::admit::<Whir>(whir, layout.vars)?;
    if !instance.num_rows.is_power_of_two() {
        return Err("fold: row count".into());
    }
    let mut t = prologue::<Whir>(&st.bytes, whir, layout.vars, instance.num_rows, &proof.root);
    t.absorb(CLAIM_DOMAIN);
    if proof.ood.len() != super::fresh_ood(whir, layout.vars)? {
        return Err("fold: OOD answers".into());
    }
    let mut claims = Vec::new();
    for &y in &proof.ood {
        let z = t.squeeze_fp3();
        t.absorb_eval(y);
        claims.push(Claim::univariate(z, layout.vars, y));
    }
    let r = reduce::reduce::<Fp3>(
        instance,
        &proof.matrix_evals,
        &proof.outer,
        &proof.inner,
        layout.vars + 1,
        &mut t,
    )
    .map_err(|e| format!("fold: spartan: {e:?}"))?;
    let (r0, rest) = (r.point[0], &r.point[1..]);
    let z_eval = (Fp3::ONE - r0) * proof.witness_eval + r0 * layout.public_eval(rest);
    if r.claim != layout.weight(instance, &r) * z_eval {
        return Err("fold: spartan final claim".into());
    }
    claims.push(Claim {
        point: pcs_point(rest),
        value: proof.witness_eval,
    });
    Ok(Instance {
        root: proof.root,
        ext: false,
        claims,
    })
}

fn fold_transcript(statements: &[Statement<'_>], cfg: &AccConfig) -> LensTranscript {
    let mut t = LensTranscript::new(b"zheng-ccs-fold-v1");
    t.absorb_u64(statements.len() as u64);
    for st in statements {
        t.absorb_u64(st.bytes.len() as u64);
        t.absorb(&st.bytes);
    }
    super::bind(&mut t, cfg);
    t
}

/// The accumulation config of statements whose witnesses have `vars`
/// variables, folded `chunk` at a time.
pub fn config(whir: &WhirParams, vars: usize, chunk: usize) -> Result<AccConfig, String> {
    let word = super::fresh_ood(whir, vars)? + 1;
    let probe = AccConfig::derive(whir, vars, chunk + 1, chunk * word)?;
    AccConfig::derive(whir, vars, chunk + 1, probe.acc_claims() + chunk * word)
}

/// Prove every statement's claim, accumulate `chunk` at a time, decide once.
pub fn fold(
    whir: &WhirParams,
    statements: &[Statement<'_>],
    witnesses: &[Vec<Goldilocks>],
    chunk: usize,
) -> Result<Folded, String> {
    if statements.is_empty() || statements.len() != witnesses.len() || chunk == 0 {
        return Err("fold: statements".into());
    }
    let mut claims = Vec::with_capacity(statements.len());
    let mut words = Vec::with_capacity(statements.len());
    for (st, z) in statements.iter().zip(witnesses) {
        let (cp, w) = prove_claim(whir, st, z)?;
        claims.push(cp);
        words.push(w);
    }
    let vars = words[0].data.num_vars();
    if words.iter().any(|w| w.data.num_vars() != vars) {
        return Err("fold: statements of different relations".into());
    }
    let cfg = config(whir, vars, chunk)?;
    let mut t = fold_transcript(statements, &cfg);
    let mut acc: Option<Witnessed> = None;
    let mut steps = Vec::new();
    for group in words.chunks(chunk) {
        let mut inputs: Vec<&Witnessed> = acc.iter().collect();
        inputs.extend(group.iter());
        let (next, proof) = super::accumulate(&cfg, &inputs, &mut t)?;
        steps.push(proof);
        acc = Some(next);
    }
    let decider = super::decide(&cfg, acc.as_ref().expect("a statement"), &mut t)?;
    Ok(Folded {
        claims,
        steps,
        decider,
    })
}

/// Verify a folded proof of `statements` (one relation).
pub fn verify_folded(
    whir: &WhirParams,
    statements: &[Statement<'_>],
    proof: &Folded,
    chunk: usize,
) -> Result<(), String> {
    if statements.is_empty()
        || proof.claims.len() != statements.len()
        || chunk == 0
        || proof.steps.len() != statements.len().div_ceil(chunk)
    {
        return Err("fold: shape".into());
    }
    let insts = statements
        .iter()
        .zip(&proof.claims)
        .map(|(st, cp)| verify_claim(whir, st, cp))
        .collect::<Result<Vec<_>, _>>()?;
    let vars = insts[0].claims.last().expect("a claim").point.len();
    let cfg = config(whir, vars, chunk)?;
    let mut t = fold_transcript(statements, &cfg);
    let mut acc: Option<Instance> = None;
    for (group, step) in insts.chunks(chunk).zip(&proof.steps) {
        let mut inputs: Vec<&Instance> = acc.iter().collect();
        inputs.extend(group.iter());
        acc = Some(super::verify_step(&cfg, &inputs, step, &mut t)?);
    }
    super::verify_decider(&cfg, acc.as_ref().expect("a statement"), &proof.decider, &mut t)
}

impl ClaimProof {
    /// `32 B root · exts matrix_evals · u32 R + R × exts outer · u32 R + R ×
    /// exts inner · ext witness_eval`.
    pub fn write(&self, w: &mut lens::rspcs::wire::Writer) {
        w.digest(&self.root.0);
        w.exts(&self.matrix_evals);
        for rounds in [&self.outer.rounds, &self.inner.rounds] {
            w.u32(rounds.len());
            for r in rounds.iter() {
                w.exts(r);
            }
        }
        w.ext(self.witness_eval);
        w.exts(&self.ood);
    }
}

impl Folded {
    /// Bytes on the wire: claims, steps, decider (Fp3 word).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = lens::rspcs::wire::Writer::default();
        w.u32(self.claims.len());
        for c in &self.claims {
            c.write(&mut w);
        }
        w.u32(self.steps.len());
        for s in &self.steps {
            s.write(&mut w);
        }
        self.decider.write(&mut w, true);
        w.buf
    }
}
