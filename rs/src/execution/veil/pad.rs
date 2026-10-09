//! Masking rows: the zk relation is the statement's relation plus rows that
//! hold uniformly random satisfying assignments on fresh witness columns.
//!
//! The verifier learns the matrix evaluations `v_j = (M_j z)~(ρ_x)` in the
//! clear (it must, to check the CCS gate at `ρ_x`). Each `v_j` is the real
//! rows' contribution plus `Σ_k eq(ρ_x, row_k)·s_k` over masking rows. Every
//! masking row satisfies the gate for *any* value of its fresh columns, so
//! the extension is equisatisfiable with the original relation (a witness
//! of one restricts to, or extends to, a witness of the other), and the
//! prover fills the fresh columns with uniform values.
//!
//! Gate `y0·y1 − y2` (relations without a hash), three rows of each type:
//!
//! | type | row | contributes |
//! |---|---|---|
//! | T0 | `y0 = s` | `v0 += e·s` |
//! | T1 | `y1 = s` | `v1 += e·s` |
//! | TB | `y0 = s, y1 = z[0] = 1, y2 = s` | `v0, v2 += e·s`, `v1 += e` |
//!
//! Gate `y0·y1 − y2 + y3^7 − y4` (with the hemera S-box), also:
//!
//! | type | row | contributes |
//! |---|---|---|
//! | TA | `y2 = s, y4 = −s` | `v2 += e·s`, `v4 −= e·s` |
//! | TE | `y3 = s, y4 = t`, `t = s^7` | `v3 += e·s`, `v4 += e·s^7` |
//!
//! With `A_T = Σ_{rows of T} eq(ρ_x, row)·s_row`, the masks are
//! `v0 ← A_T0 + A_TB`, `v1 ← A_T1`, `v2 ← A_TB + A_TA`, `v3 ← A_TE`,
//! `v4 ← −A_TA + Σ_TE e·s^7`: an invertible triangular change of
//! variables, so `(v_j)_j` is uniform over Fp3^t whenever every `A_T` is.
//! `A_T` is uniform over Fp3 as soon as the three Fp3 weights `eq(ρ_x,
//! row)` of its rows are linearly independent over F_p; for distinct rows
//! a dependence is a nonzero multilinear relation of degree `log m` in
//! `ρ_x`, so it holds with probability at most `p²·log m / p³ = log m / p`
//! per type over the verifier's uniform `ρ_x` (union bound over the `p²`
//! projective coefficient vectors, Schwartz–Zippel over Fp3).

use nebu::Goldilocks;

use super::coins::Coins;
use crate::types::{CCSInstance, SparseMatrix};

/// Rows per masking type.
pub const PER_TYPE: usize = 3;

/// The gates the masking rows support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    /// `y0·y1 − y2`.
    Product,
    /// `y0·y1 − y2 + y3^7 − y4`.
    ProductSbox,
}

impl Gate {
    pub fn of(instance: &CCSInstance) -> Result<Self, String> {
        let one = Goldilocks::ONE;
        let neg = -Goldilocks::ONE;
        match (instance.matrices.len(), instance.multisets.as_slice(), instance.coeffs.as_slice()) {
            (3, [a, b], [c0, c1]) if *a == [0, 1] && *b == [2] && (*c0, *c1) == (one, neg) => {
                Ok(Self::Product)
            }
            (5, [a, b, c, d], [c0, c1, c2, c3])
                if *a == [0, 1]
                    && *b == [2]
                    && *c == [3; 7]
                    && *d == [4]
                    && (*c0, *c1, *c2, *c3) == (one, neg, one, neg) =>
            {
                Ok(Self::ProductSbox)
            }
            _ => Err("veil: unsupported CCS gate".into()),
        }
    }

    /// Masking types in row order.
    fn types(self) -> &'static [Kind] {
        match self {
            Self::Product => &[Kind::T0, Kind::T1, Kind::TB],
            Self::ProductSbox => &[Kind::T0, Kind::T1, Kind::TB, Kind::TA, Kind::TE],
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    T0,
    T1,
    TB,
    TA,
    TE,
}

impl Kind {
    /// Fresh columns per row.
    fn columns(self) -> usize {
        match self {
            Self::TE => 2,
            _ => 1,
        }
    }
}

/// The fresh columns of the masking rows and how to fill them.
pub(crate) struct Extension {
    /// `(column, raise to the 7th power of column)`: `None` = uniform.
    fill: Vec<(usize, Option<usize>)>,
}

fn empty_row(i: &CCSInstance, r: usize) -> bool {
    i.matrices.iter().all(|m| m.entries.get(r).is_none_or(Vec::is_empty))
}

/// The statement's relation with masking rows; the same for prover and
/// verifier.
pub(crate) fn extend(base: &CCSInstance) -> Result<(CCSInstance, Extension), String> {
    let gate = Gate::of(base)?;
    let kinds = gate.types();
    let rows_needed = kinds.len() * PER_TYPE;
    let cols_needed: usize = kinds.iter().map(|k| k.columns() * PER_TYPE).sum();
    let trailing = (0..base.num_rows).rev().take_while(|&r| empty_row(base, r)).count();
    let num_rows = if trailing >= rows_needed {
        base.num_rows
    } else {
        (base.num_rows + rows_needed).next_power_of_two()
    };
    let first_row = num_rows - rows_needed;
    let first_col = base.num_cols;
    let num_cols = (base.num_cols + cols_needed).next_power_of_two();
    let mut matrices: Vec<SparseMatrix> = base
        .matrices
        .iter()
        .map(|m| {
            let mut entries = m.entries.clone();
            entries.resize(num_rows, vec![]);
            SparseMatrix {
                rows: num_rows,
                cols: num_cols,
                entries,
            }
        })
        .collect();
    let (one, neg) = (Goldilocks::ONE, -Goldilocks::ONE);
    let mut row = first_row;
    let mut col = first_col;
    let mut fill = Vec::with_capacity(cols_needed);
    for &kind in kinds {
        for _ in 0..PER_TYPE {
            let s = col;
            let mut set = |j: usize, c: usize, v: Goldilocks| matrices[j].entries[row].push((c, v));
            match kind {
                Kind::T0 => set(0, s, one),
                Kind::T1 => set(1, s, one),
                Kind::TB => {
                    set(0, s, one);
                    set(1, 0, one);
                    set(2, s, one);
                }
                Kind::TA => {
                    set(2, s, one);
                    set(4, s, neg);
                }
                Kind::TE => {
                    set(3, s, one);
                    set(4, s + 1, one);
                }
            }
            fill.push((s, None));
            if let Kind::TE = kind {
                fill.push((s + 1, Some(s)));
            }
            col += kind.columns();
            row += 1;
        }
    }
    let instance = CCSInstance {
        matrices,
        multisets: base.multisets.clone(),
        coeffs: base.coeffs.clone(),
        num_rows,
        num_cols,
    };
    Ok((instance, Extension { fill }))
}

impl Extension {
    /// Extend a witness of the base relation with uniform masking values.
    pub fn witness(&self, base: &[Goldilocks], num_cols: usize, coins: &mut Coins) -> Vec<Goldilocks> {
        let mut z = base.to_vec();
        z.resize(num_cols, Goldilocks::ZERO);
        for &(c, power_of) in &self.fill {
            z[c] = match power_of {
                None => coins.base(),
                Some(s) => z[s].pow7(),
            };
        }
        z
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ExecutionNoun as N;
    use crate::execution::private::prepare_execution;

    fn pair(a: N, b: N) -> N {
        N::Pair(Box::new(a), Box::new(b))
    }

    #[test]
    fn extended_relations_are_satisfied_by_every_mask() {
        // a·b, and hash(a) through the S-box
        let mul = pair(N::Atom(7), pair(pair(N::Atom(0), N::Atom(2)), pair(N::Atom(0), N::Atom(6))));
        let hash = pair(N::Atom(15), pair(N::Atom(0), N::Atom(2)));
        for (program, gate) in [(mul, Gate::Product), (hash, Gate::ProductSbox)] {
            let (_, prepared, z) = prepare_execution(&program, &[3, 4], &[], 1000).unwrap();
            let base = &prepared.relation.instance;
            assert_eq!(Gate::of(base).unwrap(), gate);
            let (ext, fill) = extend(base).unwrap();
            assert!(ext.num_rows.is_power_of_two() && ext.num_cols.is_power_of_two());
            let z: Vec<_> = z.into_iter().map(Goldilocks::new).collect();
            let mut coins = Coins::seeded([9; 32]);
            for _ in 0..4 {
                let w = fill.witness(&z, ext.num_cols, &mut coins);
                assert!(ext.is_satisfied_by(&crate::types::CCSWitness { z: w }));
            }
            // a wrong mask value breaks a row only where it must
            if gate == Gate::ProductSbox {
                let mut w = fill.witness(&z, ext.num_cols, &mut coins);
                let (t, _) = fill.fill.iter().find(|f| f.1.is_some()).unwrap();
                w[*t] += Goldilocks::ONE;
                assert!(!ext.is_satisfied_by(&crate::types::CCSWitness { z: w }));
            }
        }
    }
}
