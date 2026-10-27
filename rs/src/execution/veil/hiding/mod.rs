//! A hiding Reed–Solomon tensor commitment with a zero-knowledge linear
//! test: the Ligero geometry (Ames, Hazay, Ishai, Venkitasubramaniam, CCS
//! 2017, §4–5) over Goldilocks with Fp3 challenges.
//!
//! Commit. The entries are laid out row-major in rows of `k` (message
//! width). Row `i`'s polynomial is `p_i(X) = Σ_{c<k} u_{i,c} X^c + X^k·ν_i(X)`
//! with `ν_i` uniform of degree `< k` (`K = 2k` coefficients in all), RS-
//! encoded on the order-`N = K·2^r` subgroup. Three masking rows follow the
//! data rows: `m_a` (uniform, degree `< K`), `m_b` (uniform, degree
//! `< k − 1`) and `m_P` (uniform, degree `< K`). Column `j` with four
//! uniform salt limbs is leaf `j` of a hemera Merkle tree; the root is the
//! commitment.
//!
//! Open a linear functional `Λ` (weights on the entries) at claimed value
//! `V = Σ Λ_e u_e`:
//!
//! 1. send `μ = [X^{k−1}] m_a`; draw `α, ρ_L ∈ Fp3`;
//! 2. send `p_P = Σ_i α^i p_i + α^T m_P` over all `T` codeword rows (degree
//!    `< K`) and `q = Σ_i Λ'_i·p_i + ρ_L·(m_a + X^K m_b)` (degree
//!    `< K + k − 1`), where `Λ'_i(X) = Σ_c Λ_{i,c} X^{k−1−c}`, so that
//!    `[X^{k−1}] q = V + ρ_L·μ`;
//! 3. grind, draw `t` column indices, open the columns, their salts and the
//!    Merkle multi-opening; the verifier checks the coefficient identity,
//!    `p_P(ω^j)` and `q(ω^j)` against every opened column.
//!
//! Soundness (unique decoding, `D = 2K` bounds the degree of the true `q*`
//! whatever the masking rows hold): with `e = ⌊(N − D + 1)/2⌋`, either the
//! committed rows are jointly `e`-far from RS[N, K] — then, except with
//! probability `(T − 1)·N/|Fp3|` over `α` (correlated agreement for the
//! powers generator, BCIKS20 as in WHIR eprint 2024/1586 Thm 4.8), the
//! combination is far and every query passes with probability `≤ 1 − e/N`
//! — or they are `e`-close with a common agreement set, and a `p_P` or `q`
//! other than the true one passes a query with probability `≤ (D − 1 +
//! e)/N`; when both are the true ones, a wrong `V` survives the coefficient
//! check only for one `ρ_L` (`1/|Fp3|`). Per query `≤ (1 + (D − 1)/N)/2`;
//! grinding adds `pow_bits` to the query round.
//!
//! Zero knowledge (honest verifier, salted leaves in the random-oracle
//! model): every data row has `k ≥ t` uniform padding coefficients, so its
//! values at the `≤ t` opened points are uniform and independent of its
//! message; `p_P` is one-time padded by `m_P`, `q` by `m_L = m_a + X^K m_b`
//! except its `X^{k−1}` coefficient, which equals `V + ρ_L μ` with `μ`
//! uniform; the masking rows' opened values are then determined by `p_P`,
//! `q` and the data columns (`m_b`'s by its `k − 1 ≥ t` coefficients).
//! Unopened leaves are hemera outputs on inputs with 256 bits of salt.
//! A simulator given `V` reproduces the distribution exactly up to the
//! random-oracle term.

pub(crate) mod proof;
mod prove;
mod verify;

pub(crate) use proof::HidingProof;
pub(crate) use prove::{commit, open};
pub(crate) use verify::verify;

use nebu::Fp3;

/// Masking rows after the data rows: `m_a`, `m_b`, `m_P`.
pub(crate) const MASK_ROWS: usize = 3;
/// Salt limbs per column leaf.
pub(crate) const SALT: usize = 4;
const VERSION: u8 = 1;

/// Security parameters: printed into the proof, admitted by policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HidingParams {
    /// `N = K·2^log_inv_rate`.
    pub log_inv_rate: u8,
    /// Grinding bits before the query round.
    pub pow_bits: u8,
    /// Target soundness in bits; sets the query count.
    pub security_target: u16,
}

impl Default for HidingParams {
    fn default() -> Self {
        Self {
            log_inv_rate: 5,
            pow_bits: 16,
            security_target: 128,
        }
    }
}

impl HidingParams {
    pub const HEADER: usize = 5;
    pub fn header(&self) -> [u8; Self::HEADER] {
        let t = self.security_target.to_le_bytes();
        [VERSION, self.log_inv_rate, self.pow_bits, t[0], t[1]]
    }
    pub fn from_header(h: &[u8]) -> Option<Self> {
        let h: [u8; Self::HEADER] = h.try_into().ok()?;
        (h[0] == VERSION).then(|| Self {
            log_inv_rate: h[1],
            pow_bits: h[2],
            security_target: u16::from_le_bytes([h[3], h[4]]),
        })
    }
    /// Inside the ranges a verifier will run.
    pub fn in_range(&self) -> bool {
        (3..=8).contains(&self.log_inv_rate)
            && self.pow_bits <= 30
            && (128..=256).contains(&self.security_target)
    }
}

/// The shape a commitment of `entries` values takes under `params`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Config {
    /// Message width `k` (a power of two); `K = 2k`.
    pub k: usize,
    /// Data rows.
    pub rows: usize,
    /// `log2 N`.
    pub log_n: u32,
    /// Sampled column indices (before deduplication).
    pub queries: usize,
    pub pow_bits: u32,
}

/// `log2 |Fp3|`.
fn ext_bits() -> f64 {
    3.0 * (nebu::field::P as f64).log2()
}

impl Config {
    pub fn big_k(&self) -> usize {
        2 * self.k
    }
    pub fn n(&self) -> usize {
        1 << self.log_n
    }
    /// Codeword rows: data and masking.
    pub fn total_rows(&self) -> usize {
        self.rows + MASK_ROWS
    }
    /// Bits of one query: `−log2((1 + (2K − 1)/N)/2)`.
    fn query_bits(log_inv_rate: u32) -> f64 {
        let d_over_n = (-(f64::from(log_inv_rate) - 1.0)).exp2();
        -((1.0 + d_over_n) / 2.0).log2()
    }

    fn with_width(params: &HidingParams, entries: usize, k: usize) -> Option<Self> {
        let r = u32::from(params.log_inv_rate);
        let need = (f64::from(params.security_target) - f64::from(params.pow_bits)).max(0.0);
        let queries = ((need / Self::query_bits(r)).ceil() as usize).max(1);
        let log_n = (2 * k).trailing_zeros() + r;
        // zero knowledge needs t = k ≥ every opened column, and m_b's
        // k − 1 coefficients too
        if k < queries + 1 || log_n > 30 {
            return None;
        }
        Some(Self {
            k,
            rows: entries.div_ceil(k).max(1),
            log_n,
            queries,
            pow_bits: u32::from(params.pow_bits),
        })
    }

    /// Estimated proof bytes (selection heuristic).
    fn estimate(&self) -> f64 {
        let t = self.queries as f64;
        let leaf = (self.total_rows() + SALT) as f64 * 8.0;
        let path = (self.log_n as f64 - t.log2()).max(0.0) * 32.0;
        t * (leaf + path) + 24.0 * (2.0 * self.big_k() as f64 + self.k as f64)
    }

    /// The size-minimal width for `entries` values.
    pub fn derive(params: &HidingParams, entries: usize) -> Result<Self, String> {
        if !params.in_range() || entries == 0 || entries > 1 << 26 {
            return Err("veil: commitment parameters or size out of range".into());
        }
        (6..=16)
            .filter_map(|lk| Self::with_width(params, entries, 1 << lk))
            .min_by(|a, b| a.estimate().total_cmp(&b.estimate()))
            .ok_or_else(|| "veil: no commitment shape".into())
    }

    /// Proven soundness bits of the opening (no conjecture).
    pub fn security_bits(&self) -> f64 {
        let r = self.log_n - self.big_k().trailing_zeros();
        let alpha = ext_bits() - ((self.total_rows() - 1) as f64).log2() - self.log_n as f64;
        let queries = self.queries as f64 * Self::query_bits(r) + self.pow_bits as f64;
        let rho = ext_bits();
        // log2 of the summed error, then back to bits
        let err: f64 = [alpha, queries, rho].iter().map(|b| (-b).exp2()).sum();
        -err.log2()
    }
}

/// A linear functional on the committed entries: `scale·eq(point, e)` on
/// the first `2^point.len()` entries (MSB-first point; high bits pick the
/// row, low bits the column) plus explicit weights on later entries.
#[derive(Clone, Debug)]
pub(crate) struct Functional {
    pub scale: Fp3,
    pub point: Vec<Fp3>,
    /// `(entry index, weight)`, indices strictly increasing, beyond the
    /// tensor block.
    pub explicit: Vec<(usize, Fp3)>,
}

#[cfg(test)]
mod tests;
