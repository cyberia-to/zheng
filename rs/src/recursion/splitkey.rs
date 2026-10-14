//! An inner wrap level's key committed over the base field: every key
//! column with an Fp3 entry (the gates' `qa`, `qb`, `qc`, whose
//! coefficients come from Fp3 constants of the verifier) is split into its
//! three limbs, every other column kept, and the physical columns are
//! committed as base words of 64 columns under one tree. A leaf of base
//! words hashes 16 lanes a word instead of 48 an Fp3 word: the next
//! level's circuit opens the key group in 6 permutations instead of 11.
//!
//! ```text
//! physical  (c, 0) for every logical column c, then (c, 1), (c, 2) for
//!           every column with an Fp3 entry; word w holds 64w .. 64w + 63
//! claim     the prover sends every physical column at ρ; the verifier
//!           rebuilds the logical ones (c = p₀ + T·p₁ + T²·p₂) for the
//!           constraints and batches the physical ones over 8 variables
//!           (6 column, 2 word): Σ_p eq(γ, p)·P_p(ρ) = Σ_w eq(γ_hi, w)·v_w,
//!           v_w the w-th word at (ρ, γ_lo), opened with the batch
//! ```

use lens::rspcs::field::eq_table;
use lens::rspcs::whir::LeafLayout;
use nebu::{Fp3, Goldilocks};

use super::circuit::trace::Pre;
use super::decide::KeyWords;
use super::ops::{Arith, Ops};
use super::word::{Arity, Group, Word};

/// Columns of a committed word.
pub const WORD: usize = 64;
/// Variables batching the physical columns: 6 within a word, 2 for the
/// word (at most four words).
pub const BITS: usize = 8;

/// The physical columns `(logical column, limb)` of a key whose columns
/// `ext[c]` hold Fp3 entries.
pub fn columns(ext: &[bool]) -> Vec<(u16, u8)> {
    let mut out: Vec<(u16, u8)> = (0..ext.len()).map(|c| (c as u16, 0)).collect();
    for (c, &e) in ext.iter().enumerate() {
        if e {
            out.push((c as u16, 1));
            out.push((c as u16, 2));
        }
    }
    assert!(out.len() <= WORD << (BITS - 6), "split key: at most four words");
    out
}

/// Which key columns hold an Fp3 entry, from the sparse columns.
pub fn ext_columns(sparse: &[Vec<(u32, Fp3)>]) -> Vec<bool> {
    sparse.iter().map(|c| c.iter().any(|&(_, v)| v.c1 != Goldilocks::ZERO || v.c2 != Goldilocks::ZERO)).collect()
}

/// Words of `phys` physical columns.
pub fn words(phys: usize) -> usize {
    phys.div_ceil(WORD)
}

fn limb(v: Fp3, l: u8) -> Goldilocks {
    match l {
        0 => v.c0,
        1 => v.c1,
        _ => v.c2,
    }
}

/// Commit the physical columns as base words under one tree (streamed:
/// a key never holds codewords).
pub fn commit(layout: LeafLayout, n: usize, pre: &Pre, phys: &[(u16, u8)], arity: Arity) -> KeyWords {
    let rows = 1usize << n;
    let words: Vec<Word> = (0..words(phys.len()))
        .map(|w| {
            let mut t = vec![Goldilocks::ZERO; WORD * rows];
            for j in 0..WORD {
                if let Some(&(c, l)) = phys.get(WORD * w + j) {
                    for (r, &v) in pre.cols[c as usize].iter().enumerate() {
                        t[j * rows + r] = limb(v, l);
                    }
                }
            }
            Word::member_base_streamed(layout, &t)
        })
        .collect();
    let group = Group::new_cached(words, arity);
    let root = group.root();
    KeyWords { group, root }
}

/// Every physical column at `ρ` (`2^n` rows) from the sparse key.
pub fn at(sparse: &[Vec<(u32, Fp3)>], phys: &[(u16, u8)], rho: &[Fp3]) -> Vec<Fp3> {
    let e = eq_table(rho);
    phys.iter()
        .map(|&(c, l)| sparse[c as usize].iter().fold(Fp3::ZERO, |a, &(x, v)| a + lens::rspcs::field::mul_base(e[x as usize], limb(v, l))))
        .collect()
}

/// The logical key columns from the physical ones: `p₀ + T·p₁ + T²·p₂`.
pub fn logical<O: Ops>(o: &mut O, phys: &[(u16, u8)], vals: &[O::V], count: usize) -> Vec<O::V> {
    let t = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
    let mut out: Vec<Option<O::V>> = vec![None; count];
    for (&(c, l), &v) in phys.iter().zip(vals) {
        let c = c as usize;
        out[c] = Some(match (out[c], l) {
            (None, 0) => v,
            (Some(acc), 1) => o.scale_add(t, v, acc),
            (Some(acc), _) => o.scale_add(t * t, v, acc),
            _ => panic!("split key: limb 0 first"),
        });
    }
    out.into_iter().map(|v| v.expect("every logical column")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::ops::Native;

    #[test]
    fn physical_columns_rebuild_the_logical_key_at_any_point() {
        let rows = 1usize << 4;
        let fp = |a: u64, b: u64, c: u64| Fp3::new(Goldilocks::new(a), Goldilocks::new(b), Goldilocks::new(c));
        let pre = Pre { cols: (0..70u64).map(|c| (0..rows as u64).map(|r| if c % 7 == 3 { fp(c + r, r * 3 + 1, c ^ r) } else { fp(c * r + 2, 0, 0) }).collect()).collect() };
        let sparse: Vec<Vec<(u32, Fp3)>> = pre.cols.iter().map(|c| c.iter().enumerate().filter(|(_, v)| **v != Fp3::ZERO).map(|(i, &v)| (i as u32, v)).collect()).collect();
        let phys = columns(&ext_columns(&sparse));
        assert_eq!(phys.len(), 70 + 2 * 10);
        let rho: Vec<Fp3> = (0..4u64).map(|i| fp(i + 5, 2 * i + 1, 7)).collect();
        let pv = at(&sparse, &phys, &rho);
        let mut o = Native::new();
        let logical = logical(&mut o, &phys, &pv, 70);
        let e = eq_table(&rho);
        for (c, col) in pre.cols.iter().enumerate() {
            let want = col.iter().zip(&e).fold(Fp3::ZERO, |a, (&v, &w)| a + v * w);
            assert_eq!(logical[c], want, "column {c}");
        }
    }
}
