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
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn is_ext(&self) -> bool {
        matches!(self, Coeffs::Ext(_))
    }
}

/// Coset `s` of the code of `c` over `2^log_n` points: one limb vector
/// per field coordinate (one for a base word, three for Fp3), `η^u`
/// order.
fn coset(c: Coeffs<'_>, log_n: u32, s: usize, tw: &[Goldilocks]) -> Vec<Vec<Goldilocks>> {
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
        Coeffs::Base(b) => vec![limb(&|i| b[i], b.len())],
        Coeffs::Ext(e) => {
            let k = e.len();
            vec![
                limb(&|i| e[i].c0, k),
                limb(&|i| e[i].c1, k),
                limb(&|i| e[i].c2, k),
            ]
        }
    }
}

/// A pointer workers write disjoint entries through.
struct Out<T>(*mut T);
// SAFETY: each coset's entries (its leaves `s + B·a`, its values
// `[p·n + s·k, p·n + (s+1)·k)` of every limb plane `p`) are written by the
// one worker that claimed the coset; no two cosets share an entry.
unsafe impl<T> Sync for Out<T> {}

/// Leaf digests of the words `members` (one tree, a leaf hashing every
/// member's `W = 2^log_width` symbols in member order) over `2^log_n`
/// points, coset by coset: one NTT per member and coset, that coset's
/// leaves hashed by `hash(leaves, width, symbol)` and written in place.
/// Memory: the digests and, per worker, one coset per member.
#[allow(clippy::type_complexity)]
pub fn digests(
    members: &[Coeffs<'_>],
    log_n: u32,
    log_width: u32,
    hash: impl Fn(usize, usize, &dyn Fn(usize, usize) -> Fp3) -> Vec<[Goldilocks; 4]> + Sync,
) -> Vec<[Goldilocks; 4]> {
    commit(members, log_n, log_width, None, hash, false).0
}

/// [`digests`] with a device: the prover backend takes every coset in
/// groups (NTTs, leaf sponges and the coset values all in device memory:
/// only the digests come back); the groups it declines (`coset_leaves` →
/// `None`) go to CPU workers. The same digests as [`digests`];
/// `init`/`rate` are the leaf sponge's.
#[allow(clippy::type_complexity)]
pub fn digests_device(
    members: &[Coeffs<'_>],
    log_n: u32,
    log_width: u32,
    init: [u64; 16],
    rate: usize,
    hash: impl Fn(usize, usize, &dyn Fn(usize, usize) -> Fp3) -> Vec<[Goldilocks; 4]> + Sync,
) -> Vec<[Goldilocks; 4]> {
    commit(members, log_n, log_width, Some((init, rate)), hash, false).0
}

/// The coset-major codeword a held word keeps: one plane of `2^log_n`
/// canonical limbs per limb vector (member-major, then limb), plane `p`
/// holding coset `s` at `[s·k, (s+1)·k)` in `η^u` order — symbol
/// `u·B + s` of the plane is entry `s·k + u` ([`Kept::at`]).
pub struct Kept {
    pub planes: Vec<u64>,
    pub k: usize,
    pub log_n: u32,
}

impl Kept {
    /// Entry of symbol `s` within a plane.
    pub fn at(&self, s: usize) -> usize {
        let b = (1usize << self.log_n) / self.k;
        (s % b) * self.k + s / b
    }
    /// Limb `q` of symbol `s`.
    pub fn limb(&self, q: usize, s: usize) -> u64 {
        self.planes[(q << self.log_n) + self.at(s)]
    }
}

/// [`digests`] / [`digests_device`] (`device`: the leaf sponge's
/// `init`/`rate`), and with `keep` the coset values as a [`Kept`]
/// codeword — a held word committed in one pass (the device writes its
/// cosets' values out with the digests: `coset_leaves_kept`).
#[allow(clippy::type_complexity)]
pub fn commit(
    members: &[Coeffs<'_>],
    log_n: u32,
    log_width: u32,
    device: Option<([u64; 16], usize)>,
    hash: impl Fn(usize, usize, &dyn Fn(usize, usize) -> Fp3) -> Vec<[Goldilocks; 4]> + Sync,
    keep: bool,
) -> (Vec<[Goldilocks; 4]>, Option<Kept>) {
    let k = members[0].len();
    let n = 1usize << log_n;
    let b = n / k;
    let w = 1usize << log_width;
    let leaves = n / w;
    let per = leaves / b;
    assert!(per >= 1 && leaves.is_multiple_of(b), "a leaf lies in one coset");
    let lpm = if members[0].is_ext() { 3 } else { 1 };
    let planes = members.len() * lpm;
    let mut vals_out = if keep {
        vec![0u64; planes * n]
    } else {
        Vec::new()
    };
    // twiddles for the CPU's cosets, computed when one is needed
    let tw_cell = std::sync::OnceLock::new();
    let tw = || tw_cell.get_or_init(|| precompute_twiddles_vec(k));
    let threads = std::thread::available_parallelism()
        .map_or(1, |x| x.get())
        .min(16)
        .min(b);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut d = vec![[Goldilocks::ZERO; 4]; leaves];
    let cpu_coset = |s: usize, out: &Out<[Goldilocks; 4]>, vout: &Out<u64>| {
        let vals: Vec<Vec<Vec<Goldilocks>>> =
            members.iter().map(|&m| coset(m, log_n, s, tw())).collect();
        let symbol = |a: usize, t: usize| {
            let v = &vals[t / w];
            let u = a + (t % w) * per;
            if v.len() == 1 {
                Fp3::from_base(v[0][u])
            } else {
                Fp3::new(v[0][u], v[1][u], v[2][u])
            }
        };
        let ds = hash(per, w * members.len(), &symbol);
        for (a, x) in ds.into_iter().enumerate() {
            // SAFETY: `s + b·a < leaves`; coset `s` was claimed once.
            unsafe { *out.0.add(s + b * a) = x };
        }
        if keep {
            for (p, v) in vals.iter().flatten().enumerate() {
                // SAFETY: plane `p`'s entries of coset `s` (see `Out`).
                let dst = unsafe { core::slice::from_raw_parts_mut(vout.0.add(p * n + s * k), k) };
                for (o, x) in dst.iter_mut().zip(v) {
                    *o = x.as_u64();
                }
            }
        }
    };
    // the device's job: limb vectors member-major
    let limb_vecs: Vec<Vec<u64>> = if device.is_some() {
        members
            .iter()
            .flat_map(|&m| match m {
                Coeffs::Base(c) => vec![c.iter().map(|x| x.as_u64()).collect::<Vec<u64>>()],
                Coeffs::Ext(e) => vec![
                    e.iter().map(|x| x.c0.as_u64()).collect(),
                    e.iter().map(|x| x.c1.as_u64()).collect(),
                    e.iter().map(|x| x.c2.as_u64()).collect(),
                ],
            })
            .collect()
    } else {
        Vec::new()
    };
    // the device takes every coset in groups (a CPU worker's coset costs
    // ~30× a device group's share: workers beside it only delay the end);
    // the cosets it declines go to the CPU workers
    let mut declined: Vec<usize> = Vec::new();
    if let Some((init, rate)) = device {
        let job = lens::rspcs::backend::CosetLeaves {
            limbs: limb_vecs.iter().map(|v| v.as_slice()).collect(),
            limbs_per_member: lpm,
            log_n,
            log_width,
            init,
            rate,
        };
        // cosets per device call: the coset values within DEVICE_VALUES bytes
        let g = (DEVICE_VALUES / (planes * k * 8)).clamp(1, b);
        let be = lens::rspcs::backend::current();
        let mut tmp = if keep && planes > 1 {
            vec![0u64; planes * g * k]
        } else {
            Vec::new()
        };
        for s0 in (0..b).step_by(g) {
            let s1 = (s0 + g).min(b);
            let gg = s1 - s0;
            let got = if !keep {
                be.coset_leaves(&job, s0..s1)
            } else if planes == 1 {
                be.coset_leaves_kept(&job, s0..s1, &mut vals_out[s0 * k..s1 * k])
            } else {
                let r = be.coset_leaves_kept(&job, s0..s1, &mut tmp[..planes * gg * k]);
                if r.is_some() {
                    for p in 0..planes {
                        vals_out[p * n + s0 * k..p * n + s1 * k]
                            .copy_from_slice(&tmp[p * gg * k..(p + 1) * gg * k]);
                    }
                }
                r
            };
            match got {
                Some(ds) => {
                    for (j, x) in ds.into_iter().enumerate() {
                        let (c, a) = (j / per, j % per);
                        d[s0 + c + b * a] = x.map(Goldilocks::new);
                    }
                }
                None => declined.extend(s0..s1),
            }
        }
    } else {
        declined.extend(0..b);
    }
    if !declined.is_empty() {
        let vout = Out(vals_out.as_mut_ptr());
        let out = Out(d.as_mut_ptr());
        let threads = threads.min(declined.len());
        std::thread::scope(|sc| {
            for _ in 0..threads {
                sc.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= declined.len() {
                            break;
                        }
                        cpu_coset(declined[i], &out, &vout);
                    }
                });
            }
        });
    }
    (
        d,
        keep.then_some(Kept {
            planes: vals_out,
            k,
            log_n,
        }),
    )
}

/// Bytes of coset values a device call holds.
pub const DEVICE_VALUES: usize = 1 << 28;

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
        Coeffs::Ext(e) => e
            .iter()
            .rev()
            .fold(Fp3::ZERO, |a, &v| lens::rspcs::field::mul_base(a, x) + v),
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
        let ext: Vec<Fp3> = (0..k as u64)
            .map(|i| {
                Fp3::new(
                    Goldilocks::new(i),
                    Goldilocks::new(3 * i + 1),
                    Goldilocks::new(i ^ 5),
                )
            })
            .collect();
        for log_n in [10u32, 12] {
            for log_w in [2u32, 4] {
                let cb = encode_base(&base, log_n);
                let ce = encode_ext(&ext, log_n);
                let leaves = 1usize << (log_n - log_w);
                for j in [0, 1, 5, leaves - 1] {
                    let want_b: Vec<Fp3> = (0..1usize << log_w)
                        .map(|t| Fp3::from_base(cb[j + t * leaves]))
                        .collect();
                    let want_e: Vec<Fp3> =
                        (0..1usize << log_w).map(|t| ce[j + t * leaves]).collect();
                    assert_eq!(leaf(Coeffs::Base(&base), log_n, log_w, j), want_b);
                    assert_eq!(leaf(Coeffs::Ext(&ext), log_n, log_w, j), want_e);
                }
                for s in [0, 3, (1 << log_n) - 1] {
                    assert_eq!(symbol(Coeffs::Base(&base), log_n, s), Fp3::from_base(cb[s]));
                    assert_eq!(symbol(Coeffs::Ext(&ext), log_n, s), ce[s]);
                }
                // every coset's leaves, in leaf order
                let got = digests(
                    &[Coeffs::Base(&base), Coeffs::Ext(&ext)],
                    log_n,
                    log_w,
                    |leaves, width, sym| {
                        (0..leaves)
                            .map(|a| {
                                [
                                    sym(a, 0).c0,
                                    sym(a, 1).c0,
                                    sym(a, width - 1).c1,
                                    Goldilocks::new(width as u64),
                                ]
                            })
                            .collect()
                    },
                );
                let mut init = [0u64; 16];
                init[9] = 2;
                let hashed = |leaves: usize,
                              len: usize,
                              sym: &dyn Fn(usize, usize) -> Fp3|
                 -> Vec<[Goldilocks; 4]> {
                    (0..leaves)
                        .map(|a| {
                            [
                                sym(a, 0).c0,
                                sym(a, 1).c0,
                                sym(a, len - 1).c1,
                                Goldilocks::new(len as u64),
                            ]
                        })
                        .collect()
                };
                // the CPU backend declines coset_leaves: the CPU workers take all
                assert_eq!(
                    digests_device(
                        &[Coeffs::Base(&base), Coeffs::Ext(&ext)],
                        log_n,
                        log_w,
                        init,
                        9,
                        hashed
                    ),
                    got
                );
                for j in 0..leaves {
                    let w = 1usize << log_w;
                    let row: Vec<Fp3> = (0..w)
                        .map(|t| Fp3::from_base(cb[j + t * leaves]))
                        .chain((0..w).map(|t| ce[j + t * leaves]))
                        .collect();
                    assert_eq!(
                        got[j],
                        [
                            row[0].c0,
                            row[1].c0,
                            row[row.len() - 1].c1,
                            Goldilocks::new(row.len() as u64)
                        ]
                    );
                }
            }
        }
    }
}
