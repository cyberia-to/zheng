//! Public columns: per-row values the verifier derives from the statement
//! and evaluates as multilinear extensions over the row variables itself.
//!
//! Row `x ∈ [0, N)`, `N = 2^n`, is the point whose bit `k` is variable `k`
//! (lens order). Three shapes cover the machine's needs, each with a
//! verifier cost independent of `N` (up to a `log N` factor):
//!
//! - `Sparse`: values at listed rows, zero elsewhere — `Σ_j eq(ρ, x_j)·v_j`;
//! - `Prefix`: values at rows `0..len` — one eq table over the low
//!   `⌈log len⌉` variables times `Π_{k ≥ ⌈log len⌉} (1 − ρ_k)`;
//! - `Periodic`: a `2^p`-periodic sequence — its MLE over the low `p`
//!   variables (the high variables sum `eq` to one).

use lens::rspcs::field::{eq_eval, eq_table};
use nebu::Fp3;

/// One public column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Public {
    Sparse(Vec<(usize, Fp3)>),
    Prefix(Vec<Fp3>),
    /// Length a power of two, at most `N`.
    Periodic(Vec<Fp3>),
}

/// The point of row `x` over `n` variables.
pub fn row_point(x: usize, n: usize) -> Vec<Fp3> {
    (0..n)
        .map(|k| if (x >> k) & 1 == 1 { Fp3::ONE } else { Fp3::ZERO })
        .collect()
}

impl Public {
    /// The column over `N = 2^n` rows (prover).
    pub fn table(&self, n: usize) -> Vec<Fp3> {
        let rows = 1usize << n;
        let mut out = vec![Fp3::ZERO; rows];
        match self {
            Public::Sparse(v) => {
                for &(x, val) in v {
                    out[x] += val;
                }
            }
            Public::Prefix(v) => out[..v.len()].copy_from_slice(v),
            Public::Periodic(v) => {
                for (x, o) in out.iter_mut().enumerate() {
                    *o = v[x % v.len()];
                }
            }
        }
        out
    }

    /// The MLE at `point` (verifier), `point.len() = n`.
    pub fn eval(&self, point: &[Fp3]) -> Fp3 {
        let n = point.len();
        match self {
            Public::Sparse(v) => v
                .iter()
                .fold(Fp3::ZERO, |acc, &(x, val)| acc + val * eq_eval(&row_point(x, n), point)),
            Public::Prefix(v) => {
                if v.is_empty() {
                    return Fp3::ZERO;
                }
                let bits = v.len().next_power_of_two().trailing_zeros() as usize;
                let table = eq_table(&point[..bits]);
                let high = point[bits..]
                    .iter()
                    .fold(Fp3::ONE, |acc, &r| acc * (Fp3::ONE - r));
                v.iter().zip(&table).fold(Fp3::ZERO, |a, (&x, &e)| a + x * e) * high
            }
            Public::Periodic(v) => {
                let bits = v.len().trailing_zeros() as usize;
                let table = eq_table(&point[..bits]);
                v.iter().zip(&table).fold(Fp3::ZERO, |a, (&x, &e)| a + x * e)
            }
        }
    }

    /// Constant `c` on every row.
    pub fn constant(c: Fp3) -> Self {
        Public::Periodic(vec![c])
    }
}

/// `nxt(x, y) = 1` iff `y = x + 1 mod 2^n` (lens order, bit `k` ↔ var
/// `k`), as a multilinear polynomial in both arguments:
///
/// ```text
/// Σ_k [Π_{i<k} x_i(1−y_i)] · (1−x_k) y_k · Π_{i>k} eq(x_i, y_i)  +  Π_i x_i(1−y_i)
/// ```
pub fn next_eval(x: &[Fp3], y: &[Fp3]) -> Fp3 {
    let n = x.len();
    assert_eq!(n, y.len());
    // suffix[k] = Π_{i ≥ k} eq(x_i, y_i)
    let mut suffix = vec![Fp3::ONE; n + 1];
    for i in (0..n).rev() {
        let e = x[i] * y[i] + (Fp3::ONE - x[i]) * (Fp3::ONE - y[i]);
        suffix[i] = suffix[i + 1] * e;
    }
    let mut carry = Fp3::ONE;
    let mut acc = Fp3::ZERO;
    for k in 0..n {
        acc += carry * (Fp3::ONE - x[k]) * y[k] * suffix[k + 1];
        carry *= x[k] * (Fp3::ONE - y[k]);
    }
    acc + carry
}

/// `Σ_x eq(ρ, x)·[y = x + 1]` for every row `y` (prover): `eq(ρ, y − 1)`.
pub fn next_table(rho: &[Fp3]) -> Vec<Fp3> {
    let eq = eq_table(rho);
    let n = eq.len();
    (0..n).map(|y| eq[(y + n - 1) % n]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nebu::Goldilocks;

    fn e(i: u64) -> Fp3 {
        Fp3::new(Goldilocks::new(i * 7 + 1), Goldilocks::new(i + 11), Goldilocks::new(3 * i))
    }

    #[test]
    fn next_mle_matches_the_successor_on_the_cube_and_its_table() {
        let n = 4;
        for x in 0..16 {
            for y in 0..16 {
                let v = next_eval(&row_point(x, n), &row_point(y, n));
                let want = if y == (x + 1) % 16 { Fp3::ONE } else { Fp3::ZERO };
                assert_eq!(v, want, "{x} {y}");
            }
        }
        let rho: Vec<Fp3> = (0..n as u64).map(e).collect();
        let table = next_table(&rho);
        for (y, &t) in table.iter().enumerate() {
            assert_eq!(t, next_eval(&rho, &row_point(y, n)));
        }
        // multilinear in y: the MLE of the table at a point equals next_eval
        let z: Vec<Fp3> = (0..n as u64).map(|i| e(i + 40)).collect();
        let mle = table
            .iter()
            .zip(eq_table(&z))
            .fold(Fp3::ZERO, |a, (&t, w)| a + t * w);
        assert_eq!(mle, next_eval(&rho, &z));
    }

    #[test]
    fn public_columns_evaluate_like_their_tables() {
        let n = 6;
        let z: Vec<Fp3> = (0..n as u64).map(|i| e(i + 5)).collect();
        let weights = eq_table(&z);
        for p in [
            Public::Sparse(vec![(0, e(1)), (13, e(2)), (63, e(3))]),
            Public::Prefix((0..11).map(e).collect()),
            Public::Periodic((0..8).map(e).collect()),
            Public::constant(e(9)),
        ] {
            let t = p.table(n);
            let mle = t.iter().zip(&weights).fold(Fp3::ZERO, |a, (&x, &w)| a + x * w);
            assert_eq!(mle, p.eval(&z), "{p:?}");
        }
    }
}
