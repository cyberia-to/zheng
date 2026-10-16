//! veil-W: veil's masked Spartan with the hiding Ligero opening replaced
//! by a WHIR opening whose round 0 is masked (`lens::rspcs::whir::zk`).
//!
//! Transcript (`zheng` transcript `T`, Fp3 challenges):
//!
//! 1. `T ← "zheng-veil-w-v1" ‖ statement ‖ WHIR header ‖ ℓ ‖ m ‖ d ‖ n ‖
//!    root`; the root commits `c` (`layout`), the mask table `G` and the
//!    round-0 salts;
//! 2. veil's outer and inner sumchecks (Libra-masked) and `λ`
//!    (`protocol::spartan_*`): the final claim's value `V = λ·g1(ρ_x) +
//!    A(0,r')·w̃(r') + ρ2·g2(r')`, where `w̃` is the free half with every
//!    mask slot read as zero;
//! 3. `z_ψ ← T`; `T ← u_ψ = Ψ(c)`, `Ψ = eq(pow(z_ψ), ·)` on the block;
//!    `μ ← T`;
//! 4. one zero-knowledge WHIR opening of `Λ = F' + μ·Ψ` at value
//!    `V + μ·u_ψ`, on a lens transcript seeded by a squeeze of `T`, where
//!    `F' = A(0,r')·eq(r', ·)` off the mask region plus the Libra weights
//!    on `g1`, `g2`'s slots.

use lens::rspcs::whir::zk::{self, Weight, ZkMask, ZkValues};
use lens::rspcs::WhirProof;
use lens::{Commitment, WhirParams};
use nebu::{Fp3, Goldilocks};

use super::super::coins::{Coins, label};
use super::super::libra::{self, Mask};
use super::super::protocol::{Setup, SpartanEnd, SpartanMsgs, pcs_transcript, spartan_prove, spartan_verify};
use super::layout::Slots;
use crate::execution::succinct::protocol::pcs_point;
use crate::field::ChallengeField;
use crate::transcript::Transcript;
use crate::types::CCSInstance;

const DOMAIN: &[u8] = b"zheng-veil-w-v1";

/// Proof fields (`wire` has the bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parts {
    pub params: WhirParams,
    pub root: Commitment,
    pub spartan: SpartanMsgsWire,
    pub u_psi: Fp3,
    pub vals: ZkValues,
    pub opening: WhirProof,
}

/// The Spartan messages as carried (clonable, comparable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpartanMsgsWire {
    pub g1: Fp3,
    pub outer: crate::spartan::reduce::CompressedRounds<Fp3>,
    pub evals: Vec<Fp3>,
    pub g2: Fp3,
    pub inner: crate::spartan::reduce::CompressedRounds<Fp3>,
}

impl From<SpartanMsgs> for SpartanMsgsWire {
    fn from(m: SpartanMsgs) -> Self {
        Self { g1: m.g1, outer: m.outer, evals: m.evals, g2: m.g2, inner: m.inner }
    }
}

impl SpartanMsgsWire {
    fn msgs(&self) -> SpartanMsgs {
        SpartanMsgs {
            g1: self.g1,
            outer: self.outer.clone(),
            evals: self.evals.clone(),
            g2: self.g2,
            inner: self.inner.clone(),
        }
    }
}

fn prologue(t: &mut Transcript, statement: &[u8], params: &WhirParams, s: &Setup, slots: &Slots, root: &Commitment) {
    t.absorb(DOMAIN);
    t.absorb(&(statement.len() as u64).to_le_bytes());
    t.absorb(statement);
    t.absorb(&params.header());
    for v in [s.layout.vars, s.instance.num_rows, s.degree, slots.n] {
        t.absorb(&(v as u64).to_le_bytes());
    }
    t.absorb_commitment(root);
}

/// `∏_{i ≥ ρ} q_i`: the weight `eq(q, ·)` puts on the block, as one eq
/// term at `(q_{<ρ}, 1, …, 1)`.
fn block_term(q: &[Fp3], rho: usize, scale: Fp3) -> (Vec<Fp3>, Fp3) {
    let coef = q[rho..].iter().fold(scale, |a, &x| a * x);
    let point = q[..rho].iter().copied().chain(core::iter::repeat_n(Fp3::ONE, q.len() - rho)).collect();
    (point, coef)
}

/// `eq(q, b)` at a hypercube point (bit `l` of `b` ↔ `q_l`).
fn eq_at(q: &[Fp3], b: usize) -> Fp3 {
    q.iter().enumerate().fold(Fp3::ONE, |a, (l, &x)| if (b >> l) & 1 == 1 { a * x } else { a * (Fp3::ONE - x) })
}

/// `(z, z², z⁴, …)` over `n` coordinates.
fn pow_point(z: Fp3, n: usize) -> Vec<Fp3> {
    let mut out = Vec::with_capacity(n);
    let mut c = z;
    for _ in 0..n {
        out.push(c);
        c = c * c;
    }
    out
}

/// The claim functional `Λ = F' + μ·Ψ` and the `(point, coef)` of `Ψ`.
fn weight(s: &Setup, slots: &Slots, end: &SpartanEnd, psi: &(Vec<Fp3>, Fp3), mu: Fp3) -> Weight {
    let n = slots.n;
    // r' in lens order, the top n − ℓ coordinates zero
    let mut q = pcs_point(&end.r);
    q.resize(n, Fp3::ZERO);
    let a0 = end.a0;
    let mut eq = vec![(q.clone(), a0), block_term(&q, slots.rho, -a0)];
    eq.push((psi.0.clone(), mu * psi.1));
    let w1 = libra::weights(&end.rho_x, s.degree, end.lambda);
    let w2 = libra::weights(&end.r, 2, end.rho2);
    let explicit = w1
        .into_iter()
        .chain(w2)
        .enumerate()
        .map(|(i, w)| {
            let b = slots.lib + i;
            (b, w - a0 * eq_at(&q, b))
        })
        .collect();
    Weight { eq, explicit }
}

/// `Ψ` at `z`: the block restriction of `eq(pow(z), ·)` as one eq term.
fn psi_term(z: Fp3, slots: &Slots) -> (Vec<Fp3>, Fp3) {
    block_term(&pow_point(z, slots.n), slots.rho, Fp3::ONE)
}

/// Prove; `zp` is the relabelled masked-relation witness.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove(
    params: &WhirParams,
    s: &Setup,
    slots: &Slots,
    relabelled: &CCSInstance,
    zp: &[Goldilocks],
    statement: &[u8],
    coins: &Coins,
) -> Result<Parts, String> {
    let lap = crate::laps::timer("veil-w");
    let half = s.half();
    let g1 = Mask::sample(s.log_m, s.degree, coins, label::LIBRA_G1);
    let g2 = Mask::sample(s.layout.vars, 2, coins, label::LIBRA_G2);
    let mut c = vec![Goldilocks::ZERO; 1 << slots.n];
    c[..slots.used].copy_from_slice(&zp[..slots.used]);
    debug_assert!(zp[slots.used..half].iter().all(|&x| x == Goldilocks::ZERO));
    let lib: Vec<Goldilocks> = g1.limbs().into_iter().chain(g2.limbs()).collect();
    c[slots.lib..slots.lib + slots.lib_len].copy_from_slice(&lib);
    coins.fill(label::W_BLOCK, &mut c[slots.block_start()..]);
    let (_, log_leaves) = zk::round0_shape(params, slots.n).map_err(|e| format!("veil-W: {e:?}"))?;
    let mask = ZkMask {
        g: coins.exts(label::W_G, 1 << (slots.n - slots.k0)),
        salts: coins.bases(label::W_SALT, zk::SALT_LIMBS << log_leaves),
    };
    lap("masks");
    let (root, data) = zk::commit_zk(params, &c, mask).map_err(|e| format!("veil-W: commit: {e:?}"))?;
    lap("commit");
    let mut t = Transcript::new();
    prologue(&mut t, statement, params, s, slots, &root);
    let (msgs, end) = spartan_prove(s, relabelled, zp, &g1, &g2, &mut t);
    lap("sumchecks");
    let z = Fp3::squeeze(&mut t);
    let psi = psi_term(z, slots);
    let block = &c[slots.block_start()..];
    let u_psi = psi.1 * lens::rspcs::field::ml_eval_base(block, &psi.0[..slots.rho]);
    t.absorb_eval(u_psi);
    let mu = Fp3::squeeze(&mut t);
    let w = weight(s, slots, &end, &psi, mu);
    let mut lt = pcs_transcript(&mut t);
    let (vals, opening) = zk::open_zk(params, &data, &w, &mut lt).map_err(|e| format!("veil-W: open: {e:?}"))?;
    debug_assert_eq!(vals.v, end.value + mu * u_psi, "the claim's value");
    lap("open");
    Ok(Parts { params: *params, root, spartan: msgs.into(), u_psi, vals, opening })
}

/// Verify against the relation and pins the caller derived.
pub(crate) fn verify(s: &Setup, statement: &[u8], p: &Parts) -> Result<(), String> {
    super::admit(&p.params, s)?;
    let slots = Slots::derive(s, &p.params)?;
    let mut t = Transcript::new();
    prologue(&mut t, statement, &p.params, s, &slots, &p.root);
    let end = spartan_verify(s, &p.spartan.msgs(), &mut t)?;
    let z = Fp3::squeeze(&mut t);
    let psi = psi_term(z, &slots);
    t.absorb_eval(p.u_psi);
    let mu = Fp3::squeeze(&mut t);
    let w = weight(s, &slots, &end, &psi, mu);
    // the claim's value is the verifier's own, never the prover's
    let vals = ZkValues { v: end.value + mu * p.u_psi, ..p.vals };
    let mut lt = pcs_transcript(&mut t);
    zk::verify_zk(&p.params, &p.root, slots.n, &w, &vals, &p.opening, &mut lt)
        .map_err(|e| format!("veil-W: opening: {e}"))
}
