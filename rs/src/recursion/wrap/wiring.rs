//! The final mode's linear wiring: its data, the weight `u_λ` it puts on
//! the opening, and the closing check's evaluation of that weight.
//!
//! The closing check needs `Σ_x u_λ(x)·eq(α, x_lo)·f_M(x_hi)` (`x_lo` the
//! low `ℓ − fv` bits of a word index `x = col·2^n + row`, `f_M` the final
//! polynomial on the cube). With `ℓ − fv ≤ n` every cell of one slot
//! shares `x_lo` (it is the slot's row), so a slot's term is
//! `eq(α, row_lo)·Σ_cells coef·f_M(x_hi)` — one product per slot instead
//! of one per cell — and the λ-batching is a Horner sum over the reads of
//! `S_read − S_write` ([`Wiring::closing`]).

use std::sync::OnceLock;

use lens::rspcs::field::eq_table;
use nebu::Fp3;

use super::verify::{par_chunks, powers};
use super::WrapKey;
use crate::recursion::whir;

/// The linear form of the memory argument (final mode): every read slot
/// with the slot that writes its address, and every used slot's value as
/// a combination of its row's phase-1 cells.
pub struct Wiring {
    /// Slot ranges for the closing check, built on first use.
    pub(super) index: std::sync::OnceLock<Option<Index>>,
    /// Read slots (each paired with the slot writing its address).
    pub reads: usize,
    /// `u_λ = Σ_i λ^i·read_i − Σ_w Λ_w·write_w` with `Λ_w` the sum of the
    /// powers of `w`'s reads: every read slot's cells `(i, word index,
    /// coefficient)` (a word index is `col·2^n + row`) …
    pub read_cells: Vec<(u32, u32, Coef)>,
    /// … every write slot's reads (`write_reads[write_at[w]..write_at[w + 1]]`)
    pub write_reads: Vec<u32>,
    pub write_at: Vec<u32>,
    /// … and its cells `(w, word index, coefficient)`.
    pub write_cells: Vec<(u32, u32, Coef)>,
}

/// A cell's coefficient in its slot's value: 1, `T`, `T²` (an Fp3 value's
/// limbs) or any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coef {
    One,
    T,
    T2,
    Other(Fp3),
}

impl Coef {
    pub fn of(c: Fp3) -> Self {
        use nebu::Goldilocks as G;
        let (z, o) = (G::ZERO, G::ONE);
        match (c.c0, c.c1, c.c2) {
            (a, b, d) if a == o && b == z && d == z => Coef::One,
            (a, b, d) if a == z && b == o && d == z => Coef::T,
            (a, b, d) if a == z && b == z && d == o => Coef::T2,
            _ => Coef::Other(c),
        }
    }
    /// `coefficient · v` (`T³ = T + 1`: a product by `T` is a limb shift).
    pub fn apply(self, v: Fp3) -> Fp3 {
        match self {
            Coef::One => v,
            Coef::T => Fp3::new(v.c2, v.c0 + v.c2, v.c1),
            Coef::T2 => Fp3::new(v.c1, v.c1 + v.c2, v.c0 + v.c2),
            Coef::Other(c) => c * v,
        }
    }
}

impl Wiring {
    /// `1, λ, …, λ^{reads−1}`.
    pub fn powers(&self, lambda: Fp3) -> Vec<Fp3> {
        let mut out = Vec::with_capacity(self.reads);
        let mut l = Fp3::ONE;
        for _ in 0..self.reads {
            out.push(l);
            l *= lambda;
        }
        out
    }
    /// `Λ_w` for every write slot.
    pub fn write_sums(&self, lp: &[Fp3]) -> Vec<Fp3> {
        self.write_at
            .windows(2)
            .map(|r| self.write_reads[r[0] as usize..r[1] as usize].iter().fold(Fp3::ZERO, |a, &i| a + lp[i as usize]))
            .collect()
    }
}


/// Slot ranges of a wiring whose cells are grouped by slot (as derived).
pub(super) struct Index {
    /// The closing's `|α|` the packed cells were built for.
    pre: usize,
    /// `rcell[read_at[i]..read_at[i + 1]]` are read `i`'s cells, packed
    /// `(x >> pre) << 2 | coefficient` (1, `T`, `T²`); `rrow[i]` its
    /// `x & (2^pre − 1)`.
    read_at: Vec<u32>,
    rcell: Vec<u16>,
    rrow: Vec<u16>,
    /// The write slot each read reads.
    read_write: Vec<u32>,
    /// As for reads: write `j`'s cells and row.
    cell_at: Vec<u32>,
    wcell: Vec<u16>,
    wrow: Vec<u16>,
}

/// `coefficient · v` for a packed coefficient (0: 1, 1: `T`, 2: `T²`).
#[inline(always)]
fn apply_tag(tag: u16, v: Fp3) -> Fp3 {
    match tag {
        0 => v,
        1 => Fp3::new(v.c2, v.c0 + v.c2, v.c1),
        _ => Fp3::new(v.c1, v.c1 + v.c2, v.c0 + v.c2),
    }
}

impl Wiring {
    pub fn new(reads: usize, read_cells: Vec<(u32, u32, Coef)>, write_reads: Vec<u32>, write_at: Vec<u32>, write_cells: Vec<(u32, u32, Coef)>) -> Self {
        Self { index: OnceLock::new(), reads, read_cells, write_reads, write_at, write_cells }
    }

    /// The slot index for closing checks with `|α| = pre`, when cells
    /// are grouped by slot in order, every read has one write, every
    /// coefficient is 1, `T` or `T²` and the indices pack in 16 bits (else
    /// `None`: the closing takes the per-cell path).
    fn index(&self, pre: usize) -> Option<&Index> {
        self.index
            .get_or_init(|| {
                let at = |cells: &[(u32, u32, Coef)], slots: usize| -> Option<Vec<u32>> {
                    if cells.windows(2).any(|p| p[0].0 > p[1].0) {
                        return None;
                    }
                    let mut at = vec![0u32; slots + 1];
                    for &(i, _, _) in cells {
                        at[i as usize + 1] += 1;
                    }
                    for k in 0..slots {
                        at[k + 1] += at[k];
                    }
                    Some(at)
                };
                if pre > 16 {
                    return None;
                }
                let mask = (1u32 << pre) - 1;
                let pack = |cells: &[(u32, u32, Coef)]| -> Option<Vec<u16>> {
                    cells
                        .iter()
                        .map(|&(_, x, c)| {
                            let hi = x >> pre;
                            let tag = match c {
                                Coef::One => 0,
                                Coef::T => 1,
                                Coef::T2 => 2,
                                Coef::Other(_) => return None,
                            };
                            (hi < 1 << 14).then_some(((hi << 2) | tag) as u16)
                        })
                        .collect()
                };
                let rows = |cells: &[(u32, u32, Coef)], at: &[u32]| -> Option<Vec<u16>> {
                    at.windows(2)
                        .map(|w| {
                            let s = &cells[w[0] as usize..w[1] as usize];
                            let r = s.first().map_or(0, |c| c.1 & mask);
                            // every cell of a slot is in its row
                            s.iter().all(|c| c.1 & mask == r).then_some(r as u16)
                        })
                        .collect()
                };
                let writes = self.write_at.len().checked_sub(1)?;
                let read_at = at(&self.read_cells, self.reads)?;
                let cell_at = at(&self.write_cells, writes)?;
                let mut read_write = vec![u32::MAX; self.reads];
                for j in 0..writes {
                    for &i in &self.write_reads[self.write_at[j] as usize..self.write_at[j + 1] as usize] {
                        if read_write[i as usize] != u32::MAX {
                            return None;
                        }
                        read_write[i as usize] = j as u32;
                    }
                }
                if read_write.contains(&u32::MAX) {
                    return None;
                }
                Some(Index {
                    pre,
                    rcell: pack(&self.read_cells)?,
                    rrow: rows(&self.read_cells, &read_at)?,
                    wcell: pack(&self.write_cells)?,
                    wrow: rows(&self.write_cells, &cell_at)?,
                    read_at,
                    read_write,
                    cell_at,
                })
            })
            .as_ref()
            .filter(|ix| ix.pre == pre)
    }

    /// `Σ_x u_λ(x)·eq(α, x_lo)·f_M(x_hi)` with `x_lo` the low `|α|` bits
    /// of `x` (module docs); `None` when the slot form does not apply.
    pub fn closing(&self, n: usize, lambda: Fp3, alpha: &[Fp3], fm: &[Fp3]) -> Option<Fp3> {
        let pre = alpha.len();
        if pre > n {
            return None;
        }
        let ix = self.index(pre)?;
        if fm.len() << pre != 1usize << (n + super::CBITS) {
            return None;
        }
        let ea = eq_table(alpha);
        // a slot's term: eq(α, row_lo)·Σ coef·f_M(x_hi)
        let slot = |cells: &[u16], row: u16| -> Fp3 {
            let s = cells.iter().fold(Fp3::ZERO, |a, &c| a + apply_tag(c & 3, fm[(c >> 2) as usize]));
            s * ea[row as usize]
        };
        let writes = ix.cell_at.len() - 1;
        let sw: Vec<Fp3> = par_chunks(writes, |r| {
            r.map(|j| slot(&ix.wcell[ix.cell_at[j] as usize..ix.cell_at[j + 1] as usize], ix.wrow[j])).collect::<Vec<_>>()
        })
        .concat();
        // Σ_i λ^i·(S_read(i) − S_write(w(i))): Horner per chunk, scaled by λ^start
        // eight interleaved Horner chains in λ^8 (one chain is latency
        // bound: an Fp3 product's latency is ~3× its throughput)
        const H: usize = 8;
        let l8 = powers_at(lambda, H);
        let parts = par_chunks(self.reads, |r| {
            let start = r.start;
            let len = r.len();
            let mut acc = [Fp3::ZERO; H];
            let d = |i: usize| slot(&ix.rcell[ix.read_at[i] as usize..ix.read_at[i + 1] as usize], ix.rrow[i]) - sw[ix.read_write[i] as usize];
            for m in (0..len.div_ceil(H)).rev() {
                for (k, a) in acc.iter_mut().enumerate() {
                    let off = m * H + k;
                    let v = if off < len { d(start + off) } else { Fp3::ZERO };
                    *a = *a * l8 + v;
                }
            }
            // Σ_k λ^k·acc_k
            let mut tot = Fp3::ZERO;
            for a in acc.iter().rev() {
                tot = tot * lambda + *a;
            }
            (start, tot)
        });
        let mut total = Fp3::ZERO;
        for (start, acc) in parts {
            total += acc * powers_at(lambda, start);
        }
        Some(total)
    }
}

/// `λ^e`.
fn powers_at(lambda: Fp3, mut e: usize) -> Fp3 {
    let (mut acc, mut b) = (Fp3::ONE, lambda);
    while e > 0 {
        if e & 1 == 1 {
            acc *= b;
        }
        b *= b;
        e >>= 1;
    }
    acc
}

/// The batched wiring vector `u_λ` as a weight of the opening: every
/// read slot's value minus its write slot's, with powers of `λ`.
pub(crate) struct WiringWeight<'a> {
    pub k: &'a WrapKey,
    pub lambda: Fp3,
}

impl whir::NativeWeight for WiringWeight<'_> {
    fn closing(&self, alpha: &[Fp3], fm: &[Fp3]) -> Fp3 {
        let w = self.k.wiring.as_ref().expect("final mode");
        match w.closing(self.k.params.n, self.lambda, alpha, fm) {
            Some(v) => v,
            None => self.partial(alpha, fm.len().trailing_zeros() as usize).iter().zip(fm).fold(Fp3::ZERO, |s, (&p, &f)| s + p * f),
        }
    }
    fn table(&self) -> Vec<Fp3> {
        super::prove::wiring_table(self.k, self.lambda)
    }
    /// `u_λ(α, b)` for every `b`: the word's index `x = col·2^n + row`,
    /// `α` its low `ℓ − fv` bits, `b` the rest.
    fn partial(&self, alpha: &[Fp3], fv: usize) -> Vec<Fp3> {
        let w = self.k.wiring.as_ref().expect("final mode");
        let pre = alpha.len();
        let ea = eq_table(alpha);
        let mask = (1usize << pre) - 1;
        let lp = powers(self.lambda, w.reads);
        let writes = w.write_at.len() - 1;
        let ws: Vec<Fp3> = par_chunks(writes, |r| {
            r.map(|j| w.write_reads[w.write_at[j] as usize..w.write_at[j + 1] as usize].iter().fold(Fp3::ZERO, |a, &i| a + lp[i as usize]))
                .collect::<Vec<_>>()
        })
        .concat();
        let nr = w.read_cells.len();
        let parts = par_chunks(nr + w.write_cells.len(), |r| {
            let mut out = vec![Fp3::ZERO; 1 << fv];
            for e in r {
                if e < nr {
                    let (i, x, kc) = w.read_cells[e];
                    let x = x as usize;
                    out[x >> pre] += kc.apply(lp[i as usize] * ea[x & mask]);
                } else {
                    let (j, x, kc) = w.write_cells[e - nr];
                    let x = x as usize;
                    out[x >> pre] -= kc.apply(ws[j as usize] * ea[x & mask]);
                }
            }
            out
        });
        let mut out = vec![Fp3::ZERO; 1 << fv];
        for p in parts {
            for (o, v) in out.iter_mut().zip(p) {
                *o += v;
            }
        }
        out
    }
}

