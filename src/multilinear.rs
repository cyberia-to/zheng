// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Multilinear polynomial utilities for the sumcheck prover/verifier.

use nebu::Goldilocks;

/// Compute eq(r, x) for all x ∈ {0,1}^k in lex order (MSB-first indexing).
///
/// Returns 2^k values where table[b_0*2^{k-1}+...+b_{k-1}] = Π_i eq(r_i, b_i).
pub fn eq_evals(r: &[Goldilocks]) -> Vec<Goldilocks> {
    let mut table = vec![Goldilocks::ONE];
    for &ri in r {
        let n = table.len();
        let one_minus_ri = Goldilocks::ONE - ri;
        let mut new_table = vec![Goldilocks::ZERO; 2 * n];
        for m in 0..n {
            new_table[m]     = table[m] * one_minus_ri;
            new_table[m + n] = table[m] * ri;
        }
        table = new_table;
    }
    table
}

/// Bookkeeping fold: pin x_0 (MSB) to challenge r.
///
/// table[m] ← (1-r)·table[m] + r·table[m+half], then truncate to half.
pub fn fold_inplace(table: &mut Vec<Goldilocks>, r: Goldilocks) {
    let sz = table.len();
    debug_assert!(sz >= 2 && sz.is_power_of_two(), "table must be power-of-2 size ≥ 2");
    let half = sz / 2;
    let one_minus_r = Goldilocks::ONE - r;
    for m in 0..half {
        let lo = table[m];
        let hi = table[m + half];
        table[m] = one_minus_r * lo + r * hi;
    }
    table.truncate(half);
}

/// Evaluate the multilinear extension at an arbitrary point by repeated folding.
pub fn evaluate_multilinear(evals: &[Goldilocks], point: &[Goldilocks]) -> Goldilocks {
    debug_assert_eq!(evals.len(), 1 << point.len());
    let mut table = evals.to_vec();
    for &r in point {
        fold_inplace(&mut table, r);
    }
    table[0]
}

/// Linearly extend two values at 0, 1 to an arbitrary t: (1-t)·v0 + t·v1.
#[inline]
pub fn linear_ext(v0: Goldilocks, v1: Goldilocks, t: Goldilocks) -> Goldilocks {
    (Goldilocks::ONE - t) * v0 + t * v1
}

/// Lagrange interpolation from evaluations at integer points 0, 1, ..., d.
///
/// Returns coefficients in ascending monomial order.
pub fn evals_to_coeffs(evals: &[Goldilocks]) -> Vec<Goldilocks> {
    let d = evals.len() - 1;
    let mut coeffs = vec![Goldilocks::ZERO; d + 1];
    for i in 0..=d {
        // compute L_i(t) = Π_{j≠i} (t-j)/(i-j) as polynomial in t
        let mut li = vec![Goldilocks::ONE]; // polynomial 1
        let mut denom = Goldilocks::ONE;
        for j in 0..=d {
            if j == i {
                continue;
            }
            // multiply li by (t - j)
            let mut new_li = vec![Goldilocks::ZERO; li.len() + 1];
            let j_field = Goldilocks::new(j as u64);
            for k in 0..li.len() {
                new_li[k + 1] = new_li[k + 1] + li[k];
                new_li[k] = new_li[k] - j_field * li[k];
            }
            li = new_li;
            // accumulate denominator: (i - j)
            let diff = if i > j {
                Goldilocks::new((i - j) as u64)
            } else {
                // negative: -(j-i) = p-(j-i)
                Goldilocks::ZERO - Goldilocks::new((j - i) as u64)
            };
            denom = denom * diff;
        }
        let denom_inv = denom.inv();
        let scale = evals[i] * denom_inv;
        for k in 0..=d {
            coeffs[k] = coeffs[k] + scale * li[k];
        }
    }
    coeffs
}

/// Evaluate polynomial (monomial coefficients, ascending) via Horner.
pub fn eval_poly(coeffs: &[Goldilocks], x: Goldilocks) -> Goldilocks {
    let mut r = Goldilocks::ZERO;
    for &c in coeffs.iter().rev() {
        r = r * x + c;
    }
    r
}

/// Zero-pad a table to the next power of 2 ≥ target, filling with Goldilocks::ZERO.
pub fn pad_to_power_of_two(table: &mut Vec<Goldilocks>, target: usize) {
    let n = target.next_power_of_two().max(1);
    table.resize(n, Goldilocks::ZERO);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_evals_sums_to_one() {
        let r = vec![
            Goldilocks::new(3),
            Goldilocks::new(7),
            Goldilocks::new(11),
        ];
        let evals = eq_evals(&r);
        let sum = evals.iter().copied().fold(Goldilocks::ZERO, |a, b| a + b);
        assert_eq!(sum, Goldilocks::ONE);
    }

    #[test]
    fn eq_evals_binary_point() {
        let r = vec![Goldilocks::new(5), Goldilocks::new(9)];
        let evals = eq_evals(&r);
        // eq((5,9), (0,0)) = (1-5)(1-9) = (-4)(-8) = 32
        let expected = (Goldilocks::ONE - r[0]) * (Goldilocks::ONE - r[1]);
        assert_eq!(evals[0], expected);
    }

    #[test]
    fn fold_halves_table() {
        let mut t = vec![
            Goldilocks::new(1),
            Goldilocks::new(2),
            Goldilocks::new(3),
            Goldilocks::new(4),
        ];
        let r = Goldilocks::new(2);
        fold_inplace(&mut t, r);
        assert_eq!(t.len(), 2);
        // t[0] = (1-2)*1 + 2*3 = -1+6 = 5 = 5
        let expected0 = (Goldilocks::ONE - r) * Goldilocks::new(1) + r * Goldilocks::new(3);
        let expected1 = (Goldilocks::ONE - r) * Goldilocks::new(2) + r * Goldilocks::new(4);
        assert_eq!(t[0], expected0);
        assert_eq!(t[1], expected1);
    }

    #[test]
    fn evaluate_multilinear_at_binary() {
        let evals = vec![
            Goldilocks::new(10),
            Goldilocks::new(20),
            Goldilocks::new(30),
            Goldilocks::new(40),
        ];
        // evaluate at (0, 1) should give evals[0*2+1] = 20
        let v = evaluate_multilinear(
            &evals,
            &[Goldilocks::ZERO, Goldilocks::ONE],
        );
        assert_eq!(v, Goldilocks::new(20));
    }

    #[test]
    fn evals_to_coeffs_roundtrip() {
        // f(t) = 3t^2 + 2t + 1
        // evals at 0,1,2: 1, 6, 17
        let evals = vec![Goldilocks::new(1), Goldilocks::new(6), Goldilocks::new(17)];
        let coeffs = evals_to_coeffs(&evals);
        assert_eq!(coeffs[0], Goldilocks::new(1));
        assert_eq!(coeffs[1], Goldilocks::new(2));
        assert_eq!(coeffs[2], Goldilocks::new(3));
    }

    #[test]
    fn evals_to_coeffs_eval_matches() {
        let evals = vec![
            Goldilocks::new(5),
            Goldilocks::new(11),
            Goldilocks::new(23),
            Goldilocks::new(41),
        ];
        let coeffs = evals_to_coeffs(&evals);
        for (i, &e) in evals.iter().enumerate() {
            let v = eval_poly(&coeffs, Goldilocks::new(i as u64));
            assert_eq!(v, e);
        }
    }
}
