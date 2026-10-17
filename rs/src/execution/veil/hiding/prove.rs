//! Hiding commitment: commit and open (prover side).

use lens::rspcs::merkle::{Tree, dedup_sorted};
use lens::rspcs::{pow, rs::encode_base_with};
use lens::{Commitment, Transcript};
use nebu::{Fp3, Goldilocks};

use super::{Config, Functional, HidingParams, HidingProof, SALT};
use crate::execution::veil::coins::{Coins, label};
use crate::par;
use crate::multilinear::eq_evals;

/// Prover state between commit and open.
pub(crate) struct Committed {
    pub params: HidingParams,
    pub config: Config,
    pub entries: usize,
    /// `T` row polynomials, `K` coefficients each (data, `m_a`, `m_b`, `m_P`).
    coeffs: Vec<Vec<Goldilocks>>,
    encoded: Vec<Vec<Goldilocks>>,
    salts: Vec<[Goldilocks; SALT]>,
    tree: Tree,
}

pub(crate) fn column_bytes(column: &[Goldilocks], salt: &[Goldilocks]) -> Vec<u8> {
    column
        .iter()
        .chain(salt)
        .flat_map(|v| v.as_u64().to_le_bytes())
        .collect()
}

/// The codeword rows of a commitment under `config`: the coefficients
/// (data rows with their padding, then `m_a`, `m_b`, `m_P`), their
/// encodings and the column salts — shared by the byte-hashed commitment
/// and the field-native one (`veil::rec`).
pub(crate) type Rows = (Vec<Vec<Goldilocks>>, Vec<Vec<Goldilocks>>, Vec<[Goldilocks; SALT]>);

pub(crate) fn rows(config: &Config, entries: &[Goldilocks], coins: &Coins) -> Rows {
    let lap = crate::laps::timer("veil commit");
    let (k, big_k) = (config.k, config.big_k());
    lap(&format!("shape k={k} rows={} log_n={} queries={}", config.rows, config.log_n, config.queries));
    // data rows with their padding ν_i, in threads (row i's ν_i is
    // ROW_PAD elements i·k .. (i + 1)·k)
    let mut coeffs: Vec<Vec<Goldilocks>> = vec![Vec::new(); config.total_rows()];
    par::chunks_mut(&mut coeffs[..config.rows], (1 << 12) / k + 1, |first, rows| {
        for (i, p) in rows.iter_mut().enumerate() {
            let row = first + i;
            *p = vec![Goldilocks::ZERO; big_k];
            let start = (row * k).min(entries.len());
            let end = ((row + 1) * k).min(entries.len());
            p[..end - start].copy_from_slice(&entries[start..end]);
            coins.fill_at(label::ROW_PAD, row * k, &mut p[k..]);
        }
    });
    let mut m_b = coins.bases(label::MASK_B, k - 1);
    m_b.resize(big_k, Goldilocks::ZERO);
    coeffs[config.rows] = coins.bases(label::MASK_A, big_k);
    coeffs[config.rows + 1] = m_b;
    coeffs[config.rows + 2] = coins.bases(label::MASK_P, big_k);
    lap("row padding + masks");
    // one row per thread, each encoded on the CPU: measured ahead of one
    // device dispatch per row on Metal and of the threaded per-row NTT on
    // the CPU backend (audit/veil-coins-2026-10.md); a single thread keeps
    // the backend's per-row path
    let encoded: Vec<Vec<Goldilocks>> = if par::threads() > 1 {
        par::ranges(coeffs.len(), 1, |r| {
            r.map(|i| encode_base_with(&coeffs[i], config.log_n, false)).collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect()
    } else {
        coeffs.iter().map(|p| encode_base_with(p, config.log_n, true)).collect()
    };
    lap("encode");
    let n = config.n();
    let flat = coins.bases(label::SALT, n * SALT);
    let salts: Vec<[Goldilocks; SALT]> =
        flat.chunks_exact(SALT).map(|s| core::array::from_fn(|i| s[i])).collect();
    lap("salts");
    (coeffs, encoded, salts)
}

/// Commit to `entries` (row-major, rows of `config.k`).
pub(crate) fn commit(
    params: &HidingParams,
    entries: &[Goldilocks],
    coins: &Coins,
) -> Result<(Commitment, Committed), String> {
    let lap = crate::laps::timer("veil commit");
    let config = Config::derive(params, entries.len())?;
    let (coeffs, encoded, salts) = rows(&config, entries, coins);
    let n = config.n();
    let tree = Tree::build(n, |j| {
        let column: Vec<Goldilocks> = encoded.iter().map(|row| row[j]).collect();
        column_bytes(&column, &salts[j])
    });
    lap("tree");
    let root = Commitment(tree.root());
    Ok((
        root,
        Committed {
            params: *params,
            config,
            entries: entries.len(),
            coeffs,
            encoded,
            salts,
            tree,
        },
    ))
}

/// Transcript prologue shared by prover and verifier.
pub(crate) fn prologue(t: &mut Transcript, params: &HidingParams, entries: usize, root: &Commitment, value: Fp3) {
    t.absorb(b"zheng-veil-hiding-v1");
    t.absorb(&params.header());
    t.absorb_u64(entries as u64);
    t.absorb(root.as_bytes());
    t.absorb_fp3(value);
}

fn add_scaled(acc: &mut [Fp3], scale: Fp3, p: &[Goldilocks]) {
    for (a, &c) in acc.iter_mut().zip(p) {
        *a += Fp3::new(scale.c0 * c, scale.c1 * c, scale.c2 * c);
    }
}

/// `Λ'_i(X) · p_i(X)` accumulated into `q` for the explicit weights of row
/// `i`: `Λ'_i(X) = Σ_c w_c X^{k−1−c}`.
fn add_row_product(q: &mut [Fp3], k: usize, weights: &[(usize, Fp3)], p: &[Goldilocks]) {
    for &(c, w) in weights {
        let shift = k - 1 - c;
        add_scaled(&mut q[shift..], w, p);
    }
}

/// The tensor block: rows `< 2^hi`, columns `< 2^lo`.
pub(crate) fn split(point: &[Fp3], k: usize) -> (usize, usize) {
    let lo = point.len().min(k.trailing_zeros() as usize);
    (point.len() - lo, lo)
}

/// `eq(point, ·)` over `2^point.len()` entries, MSB-first point.
pub(crate) fn eq_msb(point: &[Fp3]) -> Vec<Fp3> {
    let rev: Vec<Fp3> = point.iter().rev().copied().collect();
    eq_evals(&rev)
}

/// `q(X) = Σ_i Λ'_i(X) p_i(X)` over the data rows.
fn functional_rows(coeffs: &[Vec<Goldilocks>], config: &Config, f: &Functional) -> Vec<Fp3> {
    let (k, big_k) = (config.k, config.big_k());
    let mut q = vec![Fp3::ZERO; big_k + k - 1];
    let (hi, lo) = split(&f.point, k);
    // tensor rows: (Σ_i scale·eq(hi, i)·p_i) · E(X), E = Σ_c eq(lo, c) X^{k−1−c}
    let row_w = eq_msb(&f.point[..hi]);
    let mut comb = vec![Fp3::ZERO; big_k];
    for (i, &w) in row_w.iter().enumerate() {
        add_scaled(&mut comb, f.scale * w, &coeffs[i]);
    }
    for (col, &e) in eq_msb(&f.point[hi..hi + lo]).iter().enumerate() {
        let shift = k - 1 - col;
        for (a, &b) in q[shift..].iter_mut().zip(&comb) {
            *a += e * b;
        }
    }
    // explicit weights, row by row
    let mut i = 0;
    while i < f.explicit.len() {
        let row = f.explicit[i].0 / k;
        let mut ws = Vec::new();
        while i < f.explicit.len() && f.explicit[i].0 / k == row {
            ws.push((f.explicit[i].0 % k, f.explicit[i].1));
            i += 1;
        }
        add_row_product(&mut q, k, &ws, &coeffs[row]);
    }
    q
}

/// The opening's two polynomials for challenges `(α, ρ_L)`: the row test
/// `p_P = Σ_i α^i p_i` over every codeword row and the linear
/// `q = Σ_i Λ'_i p_i + ρ_L·(m_a + X^K m_b)`.
pub(crate) fn messages(coeffs: &[Vec<Goldilocks>], config: &Config, f: &Functional, alpha: Fp3, rho: Fp3) -> (Vec<Fp3>, Vec<Fp3>) {
    let (k, big_k, rows) = (config.k, config.big_k(), config.rows);
    let (m_a, m_b) = (&coeffs[rows], &coeffs[rows + 1]);
    let mut row_test = vec![Fp3::ZERO; big_k];
    let mut power = Fp3::ONE;
    for p in coeffs {
        add_scaled(&mut row_test, power, p);
        power *= alpha;
    }
    let mut linear = functional_rows(coeffs, config, f);
    add_scaled(&mut linear[..big_k], rho, m_a);
    add_scaled(&mut linear[big_k..], rho, &m_b[..k - 1]);
    (row_test, linear)
}

/// Open `f` at `value = Σ Λ_e u_e` on the lens transcript `t`.
pub(crate) fn open(c: &Committed, f: &Functional, value: Fp3, t: &mut Transcript) -> HidingProof {
    let cfg = c.config;
    let root = Commitment(c.tree.root());
    prologue(t, &c.params, c.entries, &root, value);
    let mu = Fp3::from_base(c.coeffs[cfg.rows][cfg.k - 1]);
    t.absorb_fp3(mu);
    let alpha = t.squeeze_fp3();
    let rho = t.squeeze_fp3();
    let (row_test, linear) = messages(&c.coeffs, &cfg, f, alpha, rho);
    t.absorb_fp3_slice(&row_test);
    t.absorb_fp3_slice(&linear);
    let pow_nonce = pow::grind(t, cfg.pow_bits);
    let idx = dedup_sorted(t.squeeze_indices(cfg.queries, cfg.log_n));
    let mut columns = Vec::with_capacity(idx.len() * cfg.total_rows());
    let mut salts = Vec::with_capacity(idx.len() * super::SALT);
    for &j in &idx {
        columns.extend(c.encoded.iter().map(|row| row[j]));
        salts.extend_from_slice(&c.salts[j]);
    }
    HidingProof {
        params: c.params,
        mu,
        row_test,
        linear,
        pow_nonce,
        columns,
        salts,
        siblings: c.tree.open(&idx),
    }
}
