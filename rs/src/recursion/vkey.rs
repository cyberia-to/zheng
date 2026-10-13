//! Key layouts: the part of a recursion key that is expensive to derive,
//! as canonical bytes, so a verifier can rebuild the key without running
//! the circuit that fixes it (`specs/recursion.md` § key layouts).
//!
//! A key is a function of its parameters and the circuit's layout — the
//! fixed columns `Pre` (which cell holds which gate, slot, block), the row
//! carrying the public input and, for keys whose columns are committed,
//! the root of that commitment. Everything else (configs, the constraint
//! graph, sparse columns, wiring) is rebuilt from these in milliseconds.
//!
//! ```text
//! pre    rows 2^n given by the key; pre::COUNT columns, each: entry count,
//!        then per nonzero entry (row delta, c0, c1, c2) — the first delta
//!        is the row, the next ones row − previous − 1; values < p
//! ```
//!
//! A layout is trusted only as far as its digest: a verifier rebuilds a key
//! from bytes whose [`digest`] equals one compiled into zheng
//! (`envelope::keys`), so a cached or shipped layout is as good as a
//! derivation and a tampered one is refused before it is parsed.

use nebu::{Fp3, Goldilocks};

use super::circuit::layout::pre as pc;
use super::circuit::trace::Pre;
use crate::envelope::codec::{Reader, Writer};

/// Domain of a key layout's digest.
const DOMAIN: &[u8] = b"zheng-recursion-key-layout-v1";

/// The hemera digest of a layout's bytes.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = hemera::Hasher::new();
    h.update(DOMAIN);
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    *h.finalize().as_bytes()
}

pub(crate) fn write_fp3(w: &mut Writer, v: Fp3) {
    for c in [v.c0, v.c1, v.c2] {
        w.varint(c.as_u64());
    }
}

pub(crate) fn read_fp3(r: &mut Reader) -> Result<Fp3, String> {
    let mut c = [Goldilocks::ZERO; 3];
    for x in &mut c {
        *x = Goldilocks::new(r.field().map_err(|e| e.to_string())?);
    }
    Ok(Fp3 { c0: c[0], c1: c[1], c2: c[2] })
}

pub(crate) fn write_digest(w: &mut Writer, d: &[Goldilocks; 4]) {
    for v in d {
        w.varint(v.as_u64());
    }
}

pub(crate) fn read_digest(r: &mut Reader) -> Result<[Goldilocks; 4], String> {
    let mut d = [Goldilocks::ZERO; 4];
    for x in &mut d {
        *x = Goldilocks::new(r.field().map_err(|e| e.to_string())?);
    }
    Ok(d)
}

pub(crate) fn write_pre(w: &mut Writer, pre: &Pre) {
    for col in &pre.cols {
        let nz: Vec<(usize, Fp3)> = col.iter().copied().enumerate().filter(|(_, v)| *v != Fp3::ZERO).collect();
        w.len(nz.len());
        let mut next = 0;
        for (row, v) in nz {
            w.varint((row - next) as u64);
            next = row + 1;
            write_fp3(w, v);
        }
    }
}

pub(crate) fn read_pre(r: &mut Reader, rows: usize) -> Result<Pre, String> {
    let e = |e: crate::envelope::EnvelopeError| e.to_string();
    let mut cols = vec![vec![Fp3::ZERO; rows]; pc::COUNT];
    for col in &mut cols {
        let n = r.len(rows, 4).map_err(e)?;
        let mut next = 0usize;
        for _ in 0..n {
            let row = usize::try_from(r.varint().map_err(e)?)
                .ok()
                .and_then(|d| next.checked_add(d))
                .filter(|&row| row < rows)
                .ok_or("key layout: row out of range")?;
            let v = read_fp3(r)?;
            if v == Fp3::ZERO {
                return Err("key layout: a zero entry".into());
            }
            col[row] = v;
            next = row + 1;
        }
    }
    Ok(Pre { cols })
}

/// The key's nonzero entries per column.
pub(crate) fn sparse(pre: &Pre) -> Vec<Vec<(u32, Fp3)>> {
    pre.cols
        .iter()
        .map(|c| c.iter().enumerate().filter(|(_, v)| **v != Fp3::ZERO).map(|(i, &v)| (i as u32, v)).collect())
        .collect()
}

/// Whether a key entry leaves the base field.
pub(crate) fn ext(pre: &Pre) -> bool {
    pre.cols.iter().flatten().any(|v| v.c1 != Goldilocks::ZERO || v.c2 != Goldilocks::ZERO)
}
