//! The succinct profile over any CCS the verifier derived itself.
//!
//! Layout. The verifier knows which columns of `z` are pinned — `z[0] = 1`
//! and the public coordinates the statement fixes — and their values. It
//! relabels columns so that `z' = (w ‖ p)` with both halves `2^ℓ` long:
//! `w` holds the free columns in index order (zero beyond them), `p` holds
//! the pinned values in index order (zero beyond them). Columns no matrix
//! reads are dropped. With the top index bit selecting the half,
//!
//! ```text
//! z̃'(r_0, r') = (1 − r_0) · w̃(r') + r_0 · p̃(r')
//! ```
//!
//! and the verifier computes `p̃(r') = Σ_j p_j · eq(r', j)` itself from the
//! statement. Only `w` is committed. A prover therefore cannot change a
//! pinned value: it is not in the committed polynomial and the IOP's final
//! check uses the verifier's own `p̃`. This is what binds the statement once
//! the witness leaves the wire.
//!
//! Protocol (`zheng` transcript `T`, Fp3 challenges throughout):
//! 1. `T ← "zheng-succinct-v1" ‖ statement bytes ‖ pcs id ‖ params ‖ ℓ ‖ m`;
//! 2. `root = PCS.commit(w)`; `T ← root`;
//! 3. Spartan (outer sumcheck of degree `d + 1` over `log m` rounds, inner
//!    sumcheck over `ℓ + 1` rounds batching the matrix evaluations by `γ`);
//!    round polynomials travel without their linear coefficient;
//! 4. one PCS opening of `w̃` at `r'` (reversed into lens's LSB-first
//!    order) with value `v`, on a lens transcript seeded by a squeeze of
//!    `T`; the verifier checks `claim = weight · ((1 − r_0) v + r_0 p̃(r'))`.

use lens::{Commitment, Transcript as LensTranscript};
use nebu::{Fp3, Goldilocks};

use super::pcs::{SuccinctPcs, admit};
use crate::multilinear::eq_evals;
use crate::spartan::{iop, reduce};
use crate::transcript::Transcript;
use crate::types::{CCSInstance, SparseMatrix};

const DOMAIN: &[u8] = b"zheng-succinct-v1";
const PCS_DOMAIN: &[u8] = b"zheng-succinct-pcs-v1";

/// A succinct proof: the commitment, the Spartan messages and one opening.
#[derive(Clone, Debug)]
pub struct SuccinctProof<P: SuccinctPcs> {
    pub params: P::Params,
    pub root: Commitment,
    /// `M̃_i(ρ_x)` for every matrix.
    pub matrix_evals: Vec<Fp3>,
    pub outer: reduce::CompressedRounds<Fp3>,
    pub inner: reduce::CompressedRounds<Fp3>,
    /// `w̃(r')`.
    pub witness_eval: Fp3,
    pub opening: P::Proof,
}

impl<P: SuccinctPcs> PartialEq for SuccinctProof<P> {
    fn eq(&self, o: &Self) -> bool {
        self.params == o.params
            && self.root == o.root
            && self.matrix_evals == o.matrix_evals
            && self.outer == o.outer
            && self.inner == o.inner
            && self.witness_eval == o.witness_eval
            && self.opening == o.opening
    }
}
impl<P: SuccinctPcs> Eq for SuccinctProof<P> {}

/// Column relabelling shared by prover and verifier.
pub(crate) struct Layout {
    /// `ℓ`: variables of the committed half.
    pub vars: usize,
    /// Original column → column of `z'` (`None`: never read).
    pub map: Vec<Option<usize>>,
    /// `(slot in p, value)`, slots increasing.
    pub public: Vec<(usize, Goldilocks)>,
}

impl Layout {
    /// `pins` must hold `(0, 1)` and be strictly increasing.
    pub fn new(instance: &CCSInstance, pins: &[(usize, Goldilocks)]) -> Result<Self, String> {
        if pins.first() != Some(&(0, Goldilocks::ONE))
            || pins.windows(2).any(|w| w[0].0 >= w[1].0)
            || pins.last().is_some_and(|&(i, _)| i >= instance.num_cols)
        {
            return Err("succinct: pinned coordinates out of order or range".into());
        }
        let referenced = instance
            .matrices
            .iter()
            .flat_map(|m| m.entries.iter().flatten())
            .filter(|&&(_, v)| v != Goldilocks::ZERO)
            .map(|&(c, _)| c + 1)
            .max()
            .unwrap_or(0)
            .min(instance.num_cols);
        let mut pinned = pins.iter().map(|&(i, _)| i).peekable();
        let mut free = 0usize;
        let mut slots = Vec::with_capacity(referenced);
        for col in 0..referenced {
            if pinned.peek() == Some(&col) {
                pinned.next();
                slots.push(None);
            } else {
                slots.push(Some(free));
                free += 1;
            }
        }
        let vars = free
            .max(pins.len())
            .max(2)
            .next_power_of_two()
            .trailing_zeros() as usize;
        let half = 1usize << vars;
        let mut map = vec![None; instance.num_cols];
        let mut public = Vec::with_capacity(pins.len());
        for (slot, &(col, value)) in pins.iter().enumerate() {
            map[col] = Some(half + slot);
            public.push((slot, value));
        }
        for (col, s) in slots.into_iter().enumerate() {
            if let Some(s) = s {
                map[col] = Some(s);
            }
        }
        Ok(Self { vars, map, public })
    }

    /// The relation over `z'` (`2^{ℓ+1}` columns).
    pub fn instance(&self, instance: &CCSInstance) -> CCSInstance {
        let cols = 2usize << self.vars;
        let matrices = instance
            .matrices
            .iter()
            .map(|m| SparseMatrix {
                rows: m.rows,
                cols,
                entries: m
                    .entries
                    .iter()
                    .map(|row| {
                        row.iter()
                            .filter(|&&(_, v)| v != Goldilocks::ZERO)
                            .filter_map(|&(c, v)| self.map.get(c).copied().flatten().map(|c| (c, v)))
                            .collect()
                    })
                    .collect(),
            })
            .collect();
        CCSInstance {
            matrices,
            multisets: instance.multisets.clone(),
            coeffs: instance.coeffs.clone(),
            num_rows: instance.num_rows,
            num_cols: cols,
        }
    }

    /// `Σ_i γ^i M̃'_i(ρ_x, r)` for the relabelled matrices `M'`, read from
    /// the original `instance` through the column map (no relabelled copy):
    /// `eq(r, c') = (1 − r_0)·eq(r', c')` for a free column and
    /// `r_0·eq(r', c' − 2^ℓ)` for a pinned one.
    pub fn weight(&self, instance: &CCSInstance, red: &reduce::Reduction<Fp3>) -> Fp3 {
        let rho_rev: Vec<Fp3> = red.rho_x.iter().rev().copied().collect();
        let eq_row = eq_evals(&rho_rev);
        // eq_evals is LSB-first (r[j] ↔ bit j); the IOP point is MSB-first
        let col_rev: Vec<Fp3> = red.point[1..].iter().rev().copied().collect();
        let eq_col = eq_evals(&col_rev);
        let r0 = red.point[0];
        // eq(r, c') over z' = (w ‖ p): (1 − r_0)·eq(r', c') or r_0·eq(r', c' − 2^ℓ)
        let (lo, hi) = (Fp3::ONE - r0, r0);
        let eq_full = |s: usize| -> Fp3 {
            if s < eq_col.len() { lo * eq_col[s] } else { hi * eq_col[s - eq_col.len()] }
        };
        let eq_z: Vec<Fp3> = (0..2 * eq_col.len()).map(eq_full).collect();
        let scale = |a: Fp3, v: Goldilocks| Fp3::new(a.c0 * v, a.c1 * v, a.c2 * v);
        let mut acc = Fp3::ZERO;
        let mut gamma_pow = Fp3::ONE;
        for matrix in &instance.matrices {
            let mut sum = Fp3::ZERO;
            for (row, entries) in matrix.entries.iter().enumerate() {
                if entries.is_empty() {
                    continue;
                }
                let mut row_sum = Fp3::ZERO;
                for &(c, v) in entries {
                    if let Some(s) = self.map.get(c).copied().flatten() {
                        row_sum += scale(eq_z[s], v);
                    }
                }
                sum += eq_row.get(row).copied().unwrap_or(Fp3::ZERO) * row_sum;
            }
            acc += gamma_pow * sum;
            gamma_pow *= red.gamma;
        }
        acc
    }

    /// `p̃(r')` with `r'` MSB-first over `ℓ` variables.
    pub fn public_eval(&self, r: &[Fp3]) -> Fp3 {
        self.public.iter().fold(Fp3::ZERO, |acc, &(slot, v)| {
            let eq = r.iter().enumerate().fold(Fp3::ONE, |e, (j, &rj)| {
                if (slot >> (self.vars - 1 - j)) & 1 == 1 {
                    e * rj
                } else {
                    e * (Fp3::ONE - rj)
                }
            });
            acc + eq * Fp3::from_base(v)
        })
    }
}

fn prologue<P: SuccinctPcs>(
    statement: &[u8],
    params: &P::Params,
    vars: usize,
    rows: usize,
    root: &Commitment,
) -> Transcript {
    let mut t = Transcript::new();
    t.absorb(DOMAIN);
    t.absorb(&(statement.len() as u64).to_le_bytes());
    t.absorb(statement);
    t.absorb(&[P::ID]);
    t.absorb(&P::header(params));
    t.absorb(&(vars as u64).to_le_bytes());
    t.absorb(&(rows as u64).to_le_bytes());
    t.absorb_commitment(root);
    t
}

/// The lens transcript of the opening, chained to everything before it.
fn opening_transcript(t: &mut Transcript) -> LensTranscript {
    let seed = t.squeeze_hash();
    let mut lt = LensTranscript::new(PCS_DOMAIN);
    lt.absorb(&seed);
    lt
}

/// Lens points are LSB-first; the IOP's are MSB-first.
fn pcs_point(r: &[Fp3]) -> Vec<Fp3> {
    r.iter().rev().copied().collect()
}

/// Prove that `z` satisfies `instance` with the pinned coordinates `pins`
/// (`(0, 1)` first). `statement` is absorbed first; the verifier must hold
/// the same bytes.
pub fn prove<P: SuccinctPcs>(
    params: &P::Params,
    instance: &CCSInstance,
    z: &[Goldilocks],
    pins: &[(usize, Goldilocks)],
    statement: &[u8],
) -> Result<SuccinctProof<P>, String> {
    if z.len() != instance.num_cols || pins.iter().any(|&(i, v)| z[i] != v) {
        return Err("succinct: witness disagrees with the statement".into());
    }
    let layout = Layout::new(instance, pins)?;
    admit::<P>(params, layout.vars)?;
    let relabelled = layout.instance(instance);
    let mut zp = vec![Goldilocks::ZERO; relabelled.num_cols];
    for (col, slot) in layout.map.iter().enumerate() {
        if let Some(s) = slot {
            zp[*s] = z[col];
        }
    }
    let half = 1usize << layout.vars;
    let (root, data) = P::commit(params, &zp[..half]);
    let mut t = prologue::<P>(statement, params, layout.vars, instance.num_rows, &root);
    let (iop_proof, point) = iop::prove::<Fp3>(&relabelled, &zp, &mut t);
    let (outer, inner) = reduce::compress_proof(&iop_proof);
    let mut lt = opening_transcript(&mut t);
    let (witness_eval, opening) = P::open(params, &data, &pcs_point(&point[1..]), &mut lt);
    Ok(SuccinctProof {
        params: *params,
        root,
        matrix_evals: iop_proof.matrix_evals,
        outer,
        inner,
        witness_eval,
        opening,
    })
}

/// Verify a succinct proof against a relation and pins the caller derived
/// itself from the statement whose bytes are `statement`.
pub fn verify<P: SuccinctPcs>(
    instance: &CCSInstance,
    pins: &[(usize, Goldilocks)],
    statement: &[u8],
    proof: &SuccinctProof<P>,
) -> Result<(), String> {
    let layout = Layout::new(instance, pins)?;
    admit::<P>(&proof.params, layout.vars)?;
    if !instance.num_rows.is_power_of_two() {
        return Err("succinct: row count".into());
    }
    let mut t = prologue::<P>(statement, &proof.params, layout.vars, instance.num_rows, &proof.root);
    let r = reduce::reduce::<Fp3>(
        instance,
        &proof.matrix_evals,
        &proof.outer,
        &proof.inner,
        layout.vars + 1,
        &mut t,
    )
    .map_err(|e| format!("succinct: spartan: {e:?}"))?;
    let (r0, rest) = (r.point[0], &r.point[1..]);
    let z_eval = (Fp3::ONE - r0) * proof.witness_eval + r0 * layout.public_eval(rest);
    if r.claim != layout.weight(instance, &r) * z_eval {
        return Err("succinct: spartan: final claim".into());
    }
    let mut lt = opening_transcript(&mut t);
    P::verify(
        &proof.params,
        &proof.root,
        layout.vars,
        &pcs_point(rest),
        proof.witness_eval,
        &proof.opening,
        &mut lt,
    )
    .map_err(|e| format!("succinct: opening: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{ExecutionNoun as N, certify_execution};

    #[test]
    fn mapped_weight_equals_the_relabelled_weight() {
        let pair = |a, b| N::Pair(Box::new(a), Box::new(b));
        let add = pair(N::Atom(5), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(6))));
        let program = pair(N::Atom(7), pair(add, pair(N::Atom(0), N::Atom(2))));
        let (statement, _) = certify_execution(&program, &[7, 5], 1000).unwrap();
        let (instance, pins) = super::super::relation_and_pins(&statement).unwrap();
        let layout = Layout::new(&instance, &pins).unwrap();
        let relabelled = layout.instance(&instance);
        let f = |i: u64| Fp3::new(Goldilocks::new(i), Goldilocks::new(i + 3), Goldilocks::new(2 * i));
        let red = reduce::Reduction {
            point: (0..=layout.vars as u64).map(f).collect(),
            claim: Fp3::ZERO,
            rho_x: (0..instance.num_rows.trailing_zeros() as u64).map(|i| f(i + 50)).collect(),
            gamma: f(99),
        };
        assert_eq!(layout.weight(&instance, &red), red.weight(&relabelled));
    }
}
