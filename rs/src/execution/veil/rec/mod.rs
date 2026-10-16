//! veil-r: the zk profile's protocol on the recursion profile's
//! field-native transcript, so that a block proof can verify transaction
//! proofs inside the recursion circuit (`recursion::agg`,
//! `specs/aggregation.md`).
//!
//! The interactive protocol is veil's (`protocol`): the masked relation
//! (`pad`), SuperSpartan over Fp3 with both sumchecks Libra-masked
//! (`libra`), every committed value under one hiding Reed–Solomon tensor
//! commitment with a zero-knowledge linear test (`hiding`), the prover's
//! coins from the counter-mode PRF (`coins`). Three things differ, all of
//! them hashing:
//!
//! - the transcript is the recursion profile's duplex sponge over hemera's
//!   permutation (tag `VEIL`; challenges are output limbs, indices the low
//!   bits of a limb, grinding a nonce absorbed as one lane);
//! - the commitment's leaf `j` is the field-native leaf sponge (tag
//!   `LEAF`) over column `j`'s `T` symbols and its four salt limbs, the
//!   tree 4-ary (`recursion::word`);
//! - query indices are not deduplicated: each query opens its column with
//!   its own path, so the verifier is a fixed program (a repeated index
//!   opens the same column twice; at most `queries ≤ k − 1` distinct
//!   columns are ever opened, the zero-knowledge condition of `hiding`).
//!
//! The statement is the verifying key's digest and the pinned public
//! values (`(0, 1)` excluded), absorbed as field elements. The width `k`
//! of the commitment is chosen for the circuit (`Config::derive_rec`).
//!
//! The verifier ([`verify::verify`]) is written once over
//! [`crate::recursion::ops::Ops`]: natively it is this flavour's verifier;
//! in the recursion circuit it is the aggregation step's check.

pub mod verify;
mod wire;

use nebu::{Fp3, Goldilocks};

use super::coins::{Coins, label};
use super::hiding::{self, Config, HidingParams};
use super::key::ProvingKey;
use super::libra::{self, Mask};
use super::protocol;
use crate::execution::ExecutionNoun;
use crate::execution::private::PrivateStatement;
use crate::multilinear::eq_evals;
use crate::recursion::perm::tag;
use crate::recursion::sponge::ProverTranscript;
use crate::recursion::word::{self, Arity, Digest, LeafOpening};
use crate::spartan::iop::combined_weights;
use crate::sumcheck::prover::{OuterSumcheckProver, SumcheckProver};

pub use wire::MAGIC;

/// The commitment tree's fan-in.
pub const ARITY: Arity = Arity::Four;

/// One aggregation-ready relation: veil's proving key, the field-native
/// commitment's shape and the sparse data its verifier evaluates.
pub struct RecKey {
    pub(crate) pk: ProvingKey,
    pub params: HidingParams,
    pub(crate) cfg: Config,
    /// The verifying key's digest as four limbs (bytes `8i..8i + 8`, mod p).
    pub vk_digest: Digest,
    /// Per matrix, per non-empty row of the relabelled masked relation:
    /// `(row, free entries (slot, value), pinned entries (pin, value))`.
    pub(crate) sparse: Vec<Vec<SparseRow>>,
}

pub(crate) struct SparseRow {
    pub row: usize,
    pub free: Vec<(usize, Goldilocks)>,
    pub pinned: Vec<(usize, Goldilocks)>,
}

/// The shape of a key, for reports.
#[derive(Clone, Debug)]
pub struct KeyReport {
    pub log_m: usize,
    pub vars: usize,
    pub degree: usize,
    pub matrices: usize,
    pub nnz: usize,
    pub pins: usize,
    pub entries: usize,
    pub k: usize,
    pub rows: usize,
    pub log_n: u32,
    pub queries: usize,
    pub opening_bits: f64,
}

impl RecKey {
    /// The key for `program` with `inputs` public inputs under the default
    /// hiding parameters.
    pub fn new(program: &ExecutionNoun, inputs: usize) -> Result<Self, String> {
        Self::with_params(program, inputs, HidingParams::default())
    }

    pub fn with_params(program: &ExecutionNoun, inputs: usize, params: HidingParams) -> Result<Self, String> {
        let pk = ProvingKey::new(program, inputs)?;
        let s = &pk.setup;
        let cfg = Config::derive_rec(&params, s.entries())?;
        if cfg.security_bits() < protocol::MIN_SECURITY_BITS {
            return Err("veil-r: parameters below the policy".into());
        }
        let d = pk.vk.digest();
        let vk_digest: Digest = core::array::from_fn(|i| {
            Goldilocks::new(u64::from_le_bytes(d[8 * i..8 * i + 8].try_into().expect("8")) % nebu::field::P)
        });
        let half = s.half();
        let sparse = pk
            .relabelled
            .matrices
            .iter()
            .map(|m| {
                m.entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| !e.is_empty())
                    .map(|(row, e)| SparseRow {
                        row,
                        free: e.iter().filter(|&&(c, _)| c < half).copied().collect(),
                        pinned: e.iter().filter(|&&(c, _)| c >= half).map(|&(c, v)| (c - half, v)).collect(),
                    })
                    .collect()
            })
            .collect();
        Ok(Self { pk, params, cfg, vk_digest, sparse })
    }

    /// Pinned public values a statement carries (the constant excluded).
    pub fn pins(&self) -> usize {
        self.pk.pinned.len() - 1
    }

    pub fn report(&self) -> KeyReport {
        let s = &self.pk.setup;
        KeyReport {
            log_m: s.log_m,
            vars: s.layout.vars,
            degree: s.degree,
            matrices: s.instance.matrices.len(),
            nnz: self.sparse.iter().flatten().map(|r| r.free.len() + r.pinned.len()).sum(),
            pins: self.pins(),
            entries: s.entries(),
            k: self.cfg.k,
            rows: self.cfg.rows,
            log_n: self.cfg.log_n,
            queries: self.cfg.queries,
            opening_bits: self.cfg.security_bits(),
        }
    }

    /// The pinned values of `statement` (the constant excluded), checked
    /// against the key's coordinates.
    pub fn statement_pins(&self, statement: &PrivateStatement) -> Result<Vec<Goldilocks>, String> {
        if statement.execution.program_key() != self.pk.vk.program_key() {
            return Err("veil-r: the statement is for another program".into());
        }
        let pins = super::with_constant(&statement.execution.bindings(self.pk.vk.relation())?);
        if pins.len() != self.pk.pinned.len() || pins.iter().zip(&self.pk.pinned).any(|(&(i, _), &j)| i != j) {
            return Err("veil-r: pinned coordinates differ from the key's".into());
        }
        Ok(pins[1..].iter().map(|&(_, v)| v).collect())
    }
}

/// A field-native zk proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecProof {
    pub root: Digest,
    pub g1: Fp3,
    /// Outer rounds without `c_1`: `log m × d`.
    pub outer: Vec<Vec<Fp3>>,
    pub evals: Vec<Fp3>,
    pub g2: Fp3,
    /// Inner rounds without `c_1`: `ℓ × 2`.
    pub inner: Vec<Vec<Fp3>>,
    pub mu: Fp3,
    pub row_test: Vec<Fp3>,
    pub linear: Vec<Fp3>,
    pub nonce: u64,
    /// One opened column a query: `T` symbols, the four salt limbs, the path.
    pub openings: Vec<LeafOpening>,
}

/// The transcript prologue (prover side; the verifier's is
/// [`verify::prologue`], the same lanes).
pub(crate) fn header(key: &RecKey) -> Vec<Goldilocks> {
    let s = &key.pk.setup;
    let p = &key.params;
    let mut h: Vec<Goldilocks> = key.vk_digest.to_vec();
    for v in [
        u64::from(p.log_inv_rate),
        u64::from(p.pow_bits),
        u64::from(p.security_target),
        s.layout.vars as u64,
        s.instance.num_rows as u64,
        s.degree as u64,
        key.cfg.k as u64,
    ] {
        h.push(Goldilocks::new(v));
    }
    h
}

/// Prove `program` on public `input` and `secret` input in zero knowledge
/// with fresh OS randomness.
pub fn prove(key: &RecKey, program: &ExecutionNoun, input: &[u64], secret: &[u64], budget: u64) -> Result<(PrivateStatement, RecProof), String> {
    prove_with(key, program, input, secret, budget, &Coins::os()?)
}

#[cfg(any(test, feature = "test-hooks"))]
/// [`prove`] with a fixed seed (tests and reproducible benches only: a
/// fixed seed fixes every mask).
pub fn prove_seeded(key: &RecKey, program: &ExecutionNoun, input: &[u64], secret: &[u64], budget: u64, seed: [u8; 32]) -> Result<(PrivateStatement, RecProof), String> {
    prove_with(key, program, input, secret, budget, &Coins::seeded(seed))
}

pub(crate) fn prove_with(key: &RecKey, program: &ExecutionNoun, input: &[u64], secret: &[u64], budget: u64, coins: &Coins) -> Result<(PrivateStatement, RecProof), String> {
    let (statement, z, pins) = super::key::prepare_keyed(&key.pk, program, input, secret, budget)?;
    let proof = prove_prepared(key, &z, &pins[1..].iter().map(|&(_, v)| v).collect::<Vec<_>>(), coins)?;
    Ok((statement, proof))
}

fn prove_prepared(key: &RecKey, z: &[Goldilocks], pins: &[Goldilocks], coins: &Coins) -> Result<RecProof, String> {
    let lap = crate::laps::timer("veil-r");
    let s = &key.pk.setup;
    let relabelled = &key.pk.relabelled;
    let cfg = key.cfg;
    let z = s.ext.witness(z, s.instance.num_cols, coins);
    let mut zp = vec![Goldilocks::ZERO; relabelled.num_cols];
    for (col, slot) in s.layout.map.iter().enumerate() {
        if let Some(x) = slot {
            zp[*x] = z[col];
        }
    }
    let half = s.half();
    let g1 = Mask::sample(s.log_m, s.degree, coins, label::LIBRA_G1);
    let g2 = Mask::sample(s.layout.vars, 2, coins, label::LIBRA_G2);
    let mut entries = zp[..half].to_vec();
    entries.extend(g1.limbs());
    entries.extend(g2.limbs());
    if Config::derive_rec(&key.params, entries.len())? != cfg {
        return Err("veil-r: commitment shape".into());
    }
    let (coeffs, encoded, salts) = hiding::prove::rows(&cfg, &entries, coins);
    let tr = cfg.total_rows();
    let leaves = word::hash_leaves(cfg.n(), tr + hiding::SALT, false, |j, t| {
        Fp3::from_base(if t < tr { encoded[t][j] } else { salts[j][t - tr] })
    });
    let levels = word::tree_of(leaves, ARITY);
    let root = levels.last().expect("root")[0];
    lap("commit");

    let mut t = ProverTranscript::new(tag::VEIL);
    t.absorb_all(&header(key));
    t.absorb_all(pins);
    t.absorb_all(&root);
    let tau: Vec<Fp3> = t.squeeze_exts(s.log_m);
    let row_mv: Vec<Vec<Fp3>> = relabelled
        .matrices
        .iter()
        .map(|m| m.entries.iter().map(|row| Fp3::from_base(row.iter().fold(Goldilocks::ZERO, |acc, &(c, v)| acc + v * zp[c]))).collect())
        .collect();
    let mcoeffs = relabelled.coeffs.iter().map(|&c| Fp3::from_base(c)).collect();
    let mut outer = OuterSumcheckProver::new(eq_evals(&tau), row_mv, relabelled.multisets.clone(), mcoeffs);
    let g1_sum = g1.sum();
    t.absorb_ext(g1_sum);
    let rho1 = t.squeeze_ext();
    let mut rho_x = Vec::with_capacity(s.log_m);
    let mut outer_msgs = Vec::with_capacity(s.log_m);
    for _ in 0..s.log_m {
        let poly = libra::masked(outer.round_poly(), rho1, &g1.round_poly(&rho_x));
        let msg = compressed(&poly.coeffs);
        msg.iter().for_each(|&c| t.absorb_ext(c));
        let r = t.squeeze_ext();
        outer.fold(r);
        rho_x.push(r);
        outer_msgs.push(msg);
    }
    let evals = outer.matrix_evals();
    evals.iter().for_each(|&e| t.absorb_ext(e));
    let gamma = t.squeeze_ext();
    let a_full = combined_weights(relabelled, &rho_x, gamma, 2 * half);
    let w: Vec<Fp3> = zp[..half].iter().map(|&v| Fp3::from_base(v)).collect();
    let mut inner = SumcheckProver::new(a_full[..half].to_vec(), w);
    let g2_sum = g2.sum();
    t.absorb_ext(g2_sum);
    let rho2 = t.squeeze_ext();
    let mut r = Vec::with_capacity(s.layout.vars);
    let mut inner_msgs = Vec::with_capacity(s.layout.vars);
    for _ in 0..s.layout.vars {
        let poly = libra::masked(inner.round_poly(), rho2, &g2.round_poly(&r));
        let msg = compressed(&poly.coeffs);
        msg.iter().for_each(|&c| t.absorb_ext(c));
        let x = t.squeeze_ext();
        inner.fold(x);
        r.push(x);
        inner_msgs.push(msg);
    }
    lap("sumchecks");
    let lambda = t.squeeze_ext();
    let a0 = protocol::free_weight(s, &rho_x, gamma, &r);
    let f = s.functional(a0, &r, lambda, &rho_x, rho2);
    let mu = Fp3::from_base(coeffs[cfg.rows][cfg.k - 1]);
    t.absorb_ext(mu);
    let alpha = t.squeeze_ext();
    let rho_l = t.squeeze_ext();
    let (row_test, linear) = hiding::prove::messages(&coeffs, &cfg, &f, alpha, rho_l);
    row_test.iter().chain(&linear).for_each(|&c| t.absorb_ext(c));
    let nonce = t.grind(cfg.pow_bits);
    let idx = t.indices(cfg.queries, cfg.log_n as usize)?;
    let openings = idx
        .iter()
        .map(|&j| LeafOpening {
            symbols: (0..tr).map(|i| encoded[i][j]).chain(salts[j]).map(Fp3::from_base).collect(),
            path: word::path_in(&levels, ARITY, j),
            leaf: Some(j),
        })
        .collect();
    lap("open");
    Ok(RecProof { root, g1: g1_sum, outer: outer_msgs, evals, g2: g2_sum, inner: inner_msgs, mu, row_test, linear, nonce, openings })
}

/// A round polynomial's coefficients without `c_1`.
fn compressed(c: &[Fp3]) -> Vec<Fp3> {
    let mut v = c.to_vec();
    v.remove(1);
    v
}

/// Verify natively against the statement's pinned values.
pub fn verify_pins(key: &RecKey, pins: &[Goldilocks], proof: &RecProof) -> Result<(), String> {
    use crate::recursion::ops::{Native, Ops};
    wire::check_shape(key, proof)?;
    if pins.len() != key.pins() {
        return Err("veil-r: pinned value count".into());
    }
    let mut o = Native::batched();
    let pv: Vec<Fp3> = pins.iter().map(|&v| o.constant(Fp3::from_base(v))).collect();
    verify::verify(&mut o, key, &pv, proof);
    o.finish().map_err(|e| format!("veil-r: {e}"))
}

/// Verify a proof of `statement`.
pub fn verify(key: &RecKey, statement: &PrivateStatement, proof: &RecProof) -> Result<(), String> {
    verify_pins(key, &key.statement_pins(statement)?, proof)
}

impl RecProof {
    pub fn to_bytes(&self, key: &RecKey) -> Vec<u8> {
        wire::write(key, self)
    }
    pub fn from_bytes(bytes: &[u8], key: &RecKey) -> Result<Self, String> {
        wire::read(bytes, key)
    }
}

#[cfg(test)]
mod tests;
