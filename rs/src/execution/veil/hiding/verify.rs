//! Hiding commitment: verify an opening.

use lens::rspcs::merkle::{self, dedup_sorted};
use lens::rspcs::{field::root_of_unity, pow};
use lens::{Commitment, Transcript};
use nebu::{Fp3, Goldilocks};

use super::prove::{column_bytes, eq_msb, prologue, split};
use super::{Config, Functional, HidingParams, HidingProof, SALT};

fn mul_base(a: Fp3, b: Goldilocks) -> Fp3 {
    Fp3::new(a.c0 * b, a.c1 * b, a.c2 * b)
}

fn horner(coeffs: &[Fp3], x: Goldilocks) -> Fp3 {
    coeffs.iter().rev().fold(Fp3::ZERO, |acc, &c| mul_base(acc, x) + c)
}

/// Verify `proof` opens `f` at `value` for the commitment `root` to
/// `entries` values; `params` are the ones the proof names, admitted by
/// the caller's policy.
pub(crate) fn verify(
    params: &HidingParams,
    root: &Commitment,
    entries: usize,
    f: &Functional,
    value: Fp3,
    proof: &HidingProof,
    t: &mut Transcript,
) -> Result<(), String> {
    if proof.params != *params {
        return Err("veil: hiding parameters differ".into());
    }
    let cfg = Config::derive(params, entries)?;
    let (k, big_k, rows, tr) = (cfg.k, cfg.big_k(), cfg.rows, cfg.total_rows());
    let opened = proof.salts.len() / SALT;
    if proof.row_test.len() != big_k
        || proof.linear.len() != big_k + k - 1
        || proof.pow_nonce.is_some() != (cfg.pow_bits > 0)
        || proof.salts.len() != opened * SALT
        || proof.columns.len() != opened * tr
        || (1usize << f.point.len()) > entries
        || f.explicit.windows(2).any(|w| w[0].0 >= w[1].0)
        || f.explicit.first().is_some_and(|e| e.0 < 1 << f.point.len())
        || f.explicit.last().is_some_and(|e| e.0 >= rows * k)
    {
        return Err("veil: opening shape".into());
    }
    prologue(t, params, entries, root, value);
    t.absorb_fp3(proof.mu);
    let alpha = t.squeeze_fp3();
    let rho = t.squeeze_fp3();
    if proof.linear[k - 1] != value + rho * proof.mu {
        return Err("veil: linear claim".into());
    }
    t.absorb_fp3_slice(&proof.row_test);
    t.absorb_fp3_slice(&proof.linear);
    if !pow::check(t, cfg.pow_bits, proof.pow_nonce.unwrap_or(0)) {
        return Err("veil: proof of work".into());
    }
    let idx = dedup_sorted(t.squeeze_indices(cfg.queries, cfg.log_n));
    if idx.len() != opened {
        return Err("veil: opened columns".into());
    }
    let bytes: Vec<Vec<u8>> = proof
        .columns
        .chunks_exact(tr)
        .zip(proof.salts.chunks_exact(SALT))
        .map(|(c, s)| column_bytes(c, s))
        .collect();
    let leaves: Vec<(&[u8], usize)> =
        bytes.iter().map(Vec::as_slice).zip(idx.iter().copied()).collect();
    let digests = merkle::leaf_digests(&leaves, cfg.n());
    merkle::verify(&root.0, cfg.log_n as usize, &idx, digests, &proof.siblings)
        .map_err(|e| format!("veil: merkle: {e}"))?;

    // the functional's per-row weights at a column point
    let (hi, lo) = split(&f.point, k);
    let row_w: Vec<Fp3> = eq_msb(&f.point[..hi]).iter().map(|&w| f.scale * w).collect();
    let lo_point = &f.point[hi..hi + lo];
    let omega = root_of_unity(cfg.log_n);
    let n = cfg.n() as u64;
    let mut alpha_pows = Vec::with_capacity(tr);
    let mut a = Fp3::ONE;
    for _ in 0..tr {
        alpha_pows.push(a);
        a *= alpha;
    }
    for (&j, col) in idx.iter().zip(proof.columns.chunks_exact(tr)) {
        let x = omega.exp(j as u64);
        let y = omega.exp((n - j as u64) % n); // x^{-1}
        // test row: Σ α^i col_i
        let test = col.iter().zip(&alpha_pows).fold(Fp3::ZERO, |acc, (&v, &w)| acc + mul_base(w, v));
        if horner(&proof.row_test, x) != test {
            return Err("veil: proximity column".into());
        }
        // E(x) = x^{k−1} Π_t ((1 − p_t) + p_t · y^{2^{lo−1−t}})
        let mut e = Fp3::from_base(x.exp((k - 1) as u64));
        for (t_i, &p) in lo_point.iter().enumerate() {
            let yp = y.exp(1u64 << (lo - 1 - t_i));
            e *= (Fp3::ONE - p) + mul_base(p, yp);
        }
        let mut lin = Fp3::ZERO;
        for (i, &w) in row_w.iter().enumerate() {
            lin += mul_base(w * e, col[i]);
        }
        // explicit weights: Λ'_i(x) = Σ_c w_c x^{k−1−c}
        let mut y_pows = Vec::with_capacity(k);
        let mut yp = x.exp((k - 1) as u64);
        for _ in 0..k {
            y_pows.push(yp);
            yp *= y;
        }
        for &(entry, w) in &f.explicit {
            lin += mul_base(w, y_pows[entry % k] * col[entry / k]);
        }
        lin += mul_base(rho, col[rows] + x.exp(big_k as u64) * col[rows + 1]);
        if horner(&proof.linear, x) != lin {
            return Err("veil: linear column".into());
        }
    }
    Ok(())
}
