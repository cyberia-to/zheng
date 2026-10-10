//! Streaming Reed–Solomon commitments: a word's codeword is never held.
//!
//! The domain of `2^log_n` points splits into `B = 2^log_n / k` cosets
//! `ω^s·H` of the order-`k` subgroup (`k = 2^ℓ` coefficients); symbol
//! `u·B + s` is `ĉ(ω^s·η^u)` (lens `rs`). A leaf `j` of WHIR's round-0
//! layout holds symbols `j + t·L` (`L` leaves, `W` symbols a leaf); since
//! `B` divides `L`, every symbol of leaf `j` lies in coset `j mod B`, at
//! `u = ⌊j/B⌋ + t·L/B`. The committer therefore runs one size-`k` NTT per
//! coset, hashes that coset's `L/B` leaves at once and drops the values:
//! memory is the coefficients and the tree, not the codeword. An opening
//! recomputes its `W` symbols from the coefficients (`O(k)` per leaf).

use nebu::ntt::{ntt_with_twiddles, precompute_twiddles_vec};
use nebu::{Fp3, Goldilocks};

use lens::rspcs::field::root_of_unity;

/// Codewords above `2^STREAM_LOG` symbols are streamed (below, held: the
/// accumulation's spot checks read single symbols cheaply).
pub const STREAM_LOG: u32 = 25;

/// The coefficients of a word, base or extension.
#[derive(Clone, Copy)]
pub enum Coeffs<'a> {
    Base(&'a [Goldilocks]),
    Ext(&'a [Fp3]),
}

impl Coeffs<'_> {
    pub fn len(&self) -> usize {
        match self {
            Coeffs::Base(c) => c.len(),
            Coeffs::Ext(c) => c.len(),
        }
    }
    pub fn is_ext(&self) -> bool {
        matches!(self, Coeffs::Ext(_))
    }
}

/// Coset `s` of the code of `c` over `2^log_n` points, as Fp3 values
/// (`η^u` order: index `u`).
fn coset(c: Coeffs<'_>, log_n: u32, s: usize, tw: &[Goldilocks]) -> Vec<Fp3> {
    let shift = root_of_unity(log_n).exp(s as u64);
    let limb = |f: &dyn Fn(usize) -> Goldilocks, k: usize| {
        let mut v = Vec::with_capacity(k);
        let mut x = Goldilocks::ONE;
        for i in 0..k {
            v.push(f(i) * x);
            x *= shift;
        }
        ntt_with_twiddles(&mut v, tw);
        v
    };
    match c {
        Coeffs::Base(b) => limb(&|i| b[i], b.len()).into_iter().map(Fp3::from_base).collect(),
        Coeffs::Ext(e) => {
            let k = e.len();
            let l0 = limb(&|i| e[i].c0, k);
            let l1 = limb(&|i| e[i].c1, k);
            let l2 = limb(&|i| e[i].c2, k);
            (0..k).map(|u| Fp3::new(l0[u], l1[u], l2[u])).collect()
        }
    }
}

/// Leaf digests of the words `members` (one tree, a leaf hashing every
/// member's `W = 2^log_width` symbols in member order) over `2^log_n`
/// points, coset by coset; `hash(leaves)` digests a batch of leaves given
/// as symbol rows.
pub fn digests(members: &[Coeffs<'_>], log_n: u32, log_width: u32, hash: impl Fn(&[Vec<Fp3>]) -> Vec<[Goldilocks; 4]> + Sync) -> Vec<[Goldilocks; 4]> {
    let k = members[0].len();
    let n = 1usize << log_n;
    let b = n / k;
    let w = 1usize << log_width;
    let leaves = n / w;
    let per = leaves / b;
    assert!(per >= 1 && leaves % b == 0, "a leaf lies in one coset");
    let tw = precompute_twiddles_vec(k);
    let threads = std::thread::available_parallelism().map_or(1, |x| x.get()).min(16).min(b);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let parts: Vec<Vec<(usize, Vec<[Goldilocks; 4]>)>> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..threads)
            .map(|_| {
                sc.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let s = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if s >= b {
                            break;
                        }
                        let vals: Vec<Vec<Fp3>> = members.iter().map(|&m| coset(m, log_n, s, &tw)).collect();
                        let rows: Vec<Vec<Fp3>> = (0..per)
                            .map(|a| vals.iter().flat_map(|v| (0..w).map(move |t| v[a + t * per])).collect())
                            .collect();
                        out.push((s, hash(&rows)));
                    }
                    out
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().expect("coset worker")).collect()
    });
    let mut d = vec![[Goldilocks::ZERO; 4]; leaves];
    for (s, ds) in parts.into_iter().flatten() {
        for (a, x) in ds.into_iter().enumerate() {
            d[s + b * a] = x;
        }
    }
    d
}

/// [`digests`] for a device backend: cosets in groups of at least
/// [`GROUP_LEAVES`] leaves; a group's cosets come from the prover
/// backend's coset NTT (one call per member limb), its leaves are hashed
/// by one `hash` call. The same digests as [`digests`].
pub fn digests_grouped(members: &[Coeffs<'_>], log_n: u32, log_width: u32, hash: impl Fn(&[Vec<Fp3>]) -> Vec<[Goldilocks; 4]>) -> Vec<[Goldilocks; 4]> {
    let k = members[0].len();
    let n = 1usize << log_n;
    let b = n / k;
    let w = 1usize << log_width;
    let leaves = n / w;
    let per = leaves / b;
    assert!(per >= 1 && leaves % b == 0, "a leaf lies in one coset");
    let g = GROUP_LEAVES.div_ceil(per).clamp(1, b);
    let omega = root_of_unity(log_n);
    let be = lens::rspcs::backend::current();
    let limbs = |f: &dyn Fn(usize) -> Goldilocks| -> Vec<u64> { (0..k).map(|i| f(i).as_u64()).collect() };
    let mut d = vec![[Goldilocks::ZERO; 4]; leaves];
    for s0 in (0..b).step_by(g) {
        let s1 = (s0 + g).min(b);
        let shifts: Vec<u64> = (s0..s1).map(|s| omega.exp(s as u64).as_u64()).collect();
        // vals[m][c] = coset s0 + c of member m, Fp3 values
        let vals: Vec<Vec<Vec<Fp3>>> = members
            .iter()
            .map(|&m| match m {
                Coeffs::Base(c) => be
                    .coset_ntt(&limbs(&|i| c[i]), &shifts)
                    .into_iter()
                    .map(|v| v.into_iter().map(|x| Fp3::from_base(Goldilocks::new(x))).collect())
                    .collect(),
                Coeffs::Ext(e) => {
                    let l: Vec<Vec<Vec<u64>>> = [0, 1, 2]
                        .iter()
                        .map(|&q| be.coset_ntt(&limbs(&|i| [e[i].c0, e[i].c1, e[i].c2][q]), &shifts))
                        .collect();
                    (0..shifts.len())
                        .map(|c| (0..k).map(|u| Fp3::new(Goldilocks::new(l[0][c][u]), Goldilocks::new(l[1][c][u]), Goldilocks::new(l[2][c][u]))).collect())
                        .collect()
                }
            })
            .collect();
        let rows: Vec<Vec<Fp3>> = (0..s1 - s0)
            .flat_map(|c| {
                let vals = &vals;
                (0..per).map(move |a| vals.iter().flat_map(|v| (0..w).map(move |t| v[c][a + t * per])).collect())
            })
            .collect();
        let ds = hash(&rows);
        for (c, chunk) in ds.chunks_exact(per).enumerate() {
            for (a, x) in chunk.iter().enumerate() {
                d[s0 + c + b * a] = *x;
            }
        }
    }
    d
}

/// Leaves per device batch of [`digests_grouped`].
pub const GROUP_LEAVES: usize = 1 << 16;

/// The `W` symbols of leaf `j` (`L` leaves over `2^log_n` points):
/// `ĉ(x_0·ζ^t)` with `x_0 = ω^j`, `ζ = ω^L` of order `W`. Splitting
/// `ĉ(X) = Σ_{r<W} X^r·g_r(X^W)`, symbol `t` is `Σ_r ζ^{tr}·x_0^r·g_r(x_0^W)`.
pub fn leaf(c: Coeffs<'_>, log_n: u32, log_width: u32, j: usize) -> Vec<Fp3> {
    let w = 1usize << log_width;
    let leaves = 1usize << (log_n - log_width);
    let omega = root_of_unity(log_n);
    let x0 = omega.exp(j as u64);
    let zeta = omega.exp(leaves as u64);
    let y = x0.exp(w as u64);
    // g_r(y) by Horner over m, all r at once
    let k = c.len();
    let mut g = vec![Fp3::ZERO; w];
    for m in (0..k / w).rev() {
        for (r, gr) in g.iter_mut().enumerate() {
            let ci = match c {
                Coeffs::Base(b) => Fp3::from_base(b[m * w + r]),
                Coeffs::Ext(e) => e[m * w + r],
            };
            *gr = lens::rspcs::field::mul_base(*gr, y) + ci;
        }
    }
    let mut xr = Goldilocks::ONE;
    for gr in g.iter_mut() {
        *gr = lens::rspcs::field::mul_base(*gr, xr);
        xr *= x0;
    }
    (0..w)
        .map(|t| {
            let zt = zeta.exp(t as u64);
            let mut acc = Fp3::ZERO;
            let mut z = Goldilocks::ONE;
            for &gr in &g {
                acc += lens::rspcs::field::mul_base(gr, z);
                z *= zt;
            }
            acc
        })
        .collect()
}

/// Symbol `s`: `ĉ(ω^s)`.
pub fn symbol(c: Coeffs<'_>, log_n: u32, s: usize) -> Fp3 {
    let x = root_of_unity(log_n).exp(s as u64);
    match c {
        Coeffs::Base(b) => Fp3::from_base(b.iter().rev().fold(Goldilocks::ZERO, |a, &v| a * x + v)),
        Coeffs::Ext(e) => e.iter().rev().fold(Fp3::ZERO, |a, &v| lens::rspcs::field::mul_base(a, x) + v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lens::rspcs::rs::{encode_base, encode_ext};

    #[test]
    fn streamed_leaves_and_symbols_are_the_codeword() {
        let k = 1usize << 8;
        let base: Vec<Goldilocks> = (0..k as u64).map(|i| Goldilocks::new(i * i + 7)).collect();
        let ext: Vec<Fp3> = (0..k as u64).map(|i| Fp3::new(Goldilocks::new(i), Goldilocks::new(3 * i + 1), Goldilocks::new(i ^ 5))).collect();
        for log_n in [10u32, 12] {
            for log_w in [2u32, 4] {
                let cb = encode_base(&base, log_n);
                let ce = encode_ext(&ext, log_n);
                let leaves = 1usize << (log_n - log_w);
                for j in [0, 1, 5, leaves - 1] {
                    let want_b: Vec<Fp3> = (0..1usize << log_w).map(|t| Fp3::from_base(cb[j + t * leaves])).collect();
                    let want_e: Vec<Fp3> = (0..1usize << log_w).map(|t| ce[j + t * leaves]).collect();
                    assert_eq!(leaf(Coeffs::Base(&base), log_n, log_w, j), want_b);
                    assert_eq!(leaf(Coeffs::Ext(&ext), log_n, log_w, j), want_e);
                }
                for s in [0, 3, (1 << log_n) - 1] {
                    assert_eq!(symbol(Coeffs::Base(&base), log_n, s), Fp3::from_base(cb[s]));
                    assert_eq!(symbol(Coeffs::Ext(&ext), log_n, s), ce[s]);
                }
                // every coset's leaves, in leaf order
                let got = digests(&[Coeffs::Base(&base), Coeffs::Ext(&ext)], log_n, log_w, |rows| {
                    rows.iter().map(|r| [r[0].c0, r[1].c0, r[r.len() - 1].c1, Goldilocks::new(r.len() as u64)]).collect()
                });
                let grouped = digests_grouped(&[Coeffs::Base(&base), Coeffs::Ext(&ext)], log_n, log_w, |rows| {
                    rows.iter().map(|r| [r[0].c0, r[1].c0, r[r.len() - 1].c1, Goldilocks::new(r.len() as u64)]).collect()
                });
                assert_eq!(grouped, got);
                for j in 0..leaves {
                    let w = 1usize << log_w;
                    let row: Vec<Fp3> = (0..w).map(|t| Fp3::from_base(cb[j + t * leaves])).chain((0..w).map(|t| ce[j + t * leaves])).collect();
                    assert_eq!(got[j], [row[0].c0, row[1].c0, row[row.len() - 1].c1, Goldilocks::new(row.len() as u64)]);
                }
            }
        }
    }
}
