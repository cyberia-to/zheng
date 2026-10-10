//! Canonical bytes of wrap proofs. Every shape is fixed by the wrap key.
//!
//! ```text
//! wrap   roots (2 digests) · OOD answers · zerocheck (n × 9 Fp3) · W1, W2
//!        columns at ρ and at its successor · key columns at ρ (committed
//!        mode) · shift (2n Fp3) · two values · key split (committed) ·
//!        the batched opening (`whir::wire`)
//! final  the deferred nox-public claim (point, value) · wrap
//! ```

use lens::PcsError;
use lens::rspcs::wire::{Reader, Writer};

use super::{DEGREE, FinalProof, WrapKey, WrapProof};
use crate::recursion::circuit::layout::pre;
use crate::recursion::state::ClaimV;
use crate::recursion::whir;
use crate::recursion::wire::{digest, exts, read_digest, read_exts};

type R<T> = Result<T, PcsError>;

pub fn write(w: &mut Writer, k: &WrapKey, p: &WrapProof) {
    for d in &p.roots {
        digest(w, d);
    }
    for a in &p.ood {
        exts(w, a);
    }
    for m in &p.zerocheck {
        exts(w, m);
    }
    for v in [&p.local, &p.next, &p.key, &p.shift] {
        exts(w, v);
    }
    exts(w, &p.vals);
    exts(w, &p.kv);
    whir::wire::write(w, &k.cfg, &k.exts(), &p.whir);
}

pub fn read(r: &mut Reader<'_>, k: &WrapKey) -> R<WrapProof> {
    let n = k.params.n;
    let inner = k.inner();
    let words = k.trace_words();
    let roots = (0..words).map(|_| read_digest(r)).collect::<R<_>>()?;
    let ood = (0..words).map(|_| read_exts(r, k.fresh)).collect::<R<_>>()?;
    let zerocheck = (0..n).map(|_| read_exts(r, DEGREE + 1)).collect::<R<_>>()?;
    let local = read_exts(r, k.cols())?;
    let next = read_exts(r, k.next_cols.len())?;
    let key = read_exts(r, if inner { pre::COUNT } else { 0 })?;
    let shift = read_exts(r, if inner { 2 * n } else { 0 })?;
    let vals = read_exts(r, if inner { words } else { 0 })?;
    let kv = read_exts(r, if inner { 2 } else { 0 })?;
    let whir = whir::wire::read(r, &k.cfg, &k.exts())?;
    Ok(WrapProof { roots, ood, zerocheck, local, next, key, shift, vals, kv, whir })
}

impl WrapProof {
    pub fn to_bytes(&self, k: &WrapKey) -> Vec<u8> {
        let mut w = Writer::default();
        write(&mut w, k, self);
        w.buf
    }
    pub fn from_bytes(bytes: &[u8], k: &WrapKey) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let p = read(&mut r, k).map_err(|e| format!("wrap proof: {e}"))?;
        r.finish().map_err(|e| format!("wrap proof: {e}"))?;
        Ok(p)
    }
}

impl FinalProof {
    pub fn to_bytes(&self, k: &WrapKey) -> Vec<u8> {
        let mut w = Writer::default();
        exts(&mut w, &self.pn.point);
        w.ext(self.pn.value);
        write(&mut w, k, &self.wrap);
        w.buf
    }
    pub fn from_bytes(bytes: &[u8], k: &WrapKey) -> Result<Self, String> {
        let e = |e: PcsError| format!("final proof: {e}");
        let mut r = Reader::new(bytes);
        let point = read_exts(&mut r, k.pn).map_err(e)?;
        let value = r.ext().map_err(e)?;
        let wrap = read(&mut r, k).map_err(e)?;
        r.finish().map_err(e)?;
        Ok(Self { pn: ClaimV { point, value }, wrap })
    }
    /// Bytes of each part: the nox-public claim, the AIR messages, the
    /// opening.
    pub fn sizes(&self, k: &WrapKey) -> [(&'static str, usize); 3] {
        let mut w = Writer::default();
        whir::wire::write(&mut w, &k.cfg, &k.exts(), &self.wrap.whir);
        let opening = w.buf.len();
        let all = self.to_bytes(k).len();
        let pn = 24 * (self.pn.point.len() + 1);
        [("nox-public claim", pn), ("air", all - pn - opening), ("opening", opening)]
    }
}
