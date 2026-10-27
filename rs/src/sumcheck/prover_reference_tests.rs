use nebu::{Fp3, Goldilocks};

use super::OuterSumcheckProver;
use crate::multilinear::{eq_evals, evals_to_coeffs, fold_inplace};

/// The textbook round: every point, every product, no reuse.
fn naive_round(eq: &[Fp3], f: &[Vec<Fp3>], ms: &[Vec<usize>], c: &[Fp3], d: usize) -> Vec<Fp3> {
    let half = eq.len() / 2;
    let evals: Vec<Fp3> = (0..d + 2)
        .map(|t| {
            let t = Fp3::from_base(Goldilocks::new(t as u64));
            (0..half).fold(Fp3::ZERO, |acc, m| {
                let at = |v: &[Fp3]| (Fp3::ONE - t) * v[m] + t * v[m + half];
                let g = ms.iter().zip(c).fold(Fp3::ZERO, |g, (s, &c)| {
                    g + c * s.iter().fold(Fp3::ONE, |p, &i| p * at(&f[i]))
                });
                acc + at(eq) * g
            })
        })
        .collect();
    evals_to_coeffs(&evals)
}

#[test]
fn base_and_threaded_rounds_equal_the_textbook_rounds() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        Goldilocks::new(seed)
    };
    let ms = vec![vec![0, 1], vec![2], vec![3; 7], vec![4]];
    for log_m in [1usize, 5, 13] {
        let m = 1 << log_m;
        let base: Vec<Vec<Goldilocks>> = (0..5).map(|_| (0..m).map(|_| next()).collect()).collect();
        let coeffs = vec![Goldilocks::ONE, -Goldilocks::ONE, next(), -Goldilocks::ONE];
        let tau: Vec<Fp3> = (0..log_m)
            .map(|_| Fp3::new(next(), next(), next()))
            .collect();
        let mut f: Vec<Vec<Fp3>> = base
            .iter()
            .map(|t| t.iter().map(|&v| Fp3::from_base(v)).collect())
            .collect();
        let c: Vec<Fp3> = coeffs.iter().map(|&v| Fp3::from_base(v)).collect();
        let mut eq = eq_evals(&tau);
        let mut p = OuterSumcheckProver::new_base(eq.clone(), base, ms.clone(), coeffs);
        let mut q = OuterSumcheckProver::new(eq.clone(), f.clone(), ms.clone(), c.clone());
        for _ in 0..log_m {
            let want = naive_round(&eq, &f, &ms, &c, 7);
            assert_eq!(p.round_poly().coeffs, want);
            assert_eq!(q.round_poly().coeffs, want);
            let r = Fp3::new(next(), next(), next());
            p.fold(r);
            q.fold(r);
            fold_inplace(&mut eq, r);
            for t in &mut f {
                fold_inplace(t, r);
            }
        }
        assert_eq!(p.matrix_evals(), f.iter().map(|t| t[0]).collect::<Vec<_>>());
        assert_eq!(q.matrix_evals(), p.matrix_evals());
    }
}
