//! Canonical bytes of accumulation objects (lens wire conventions: LE,
//! canonical field limbs and digests, u32 counts, no trailing bytes).
//!
//! ```text
//! Claim        exts point · ext value
//! Instance     32 B root · u8 ext · u32 n · n × Claim
//! AccProof     exts sumcheck · exts evals · u64s comb_nonce · 32 B root
//!              · exts ood · u64s query_nonce · u32 m · m × (u8 ext · Opening)
//! DeciderProof exts sumcheck · ext value · u8 ext · u32 n · n B WHIR proof
//! ```

use lens::rspcs::WhirProof;
use lens::rspcs::whir::Opening;
use lens::rspcs::wire::{Reader, Writer};
use lens::{Commitment, PcsError};

use super::{AccProof, Claim, DeciderProof, Instance};

type R<T> = Result<T, PcsError>;

fn nonce(w: &mut Writer, n: Option<u64>) {
    w.u64s(&n.into_iter().collect::<Vec<_>>());
}

fn read_nonce(r: &mut Reader<'_>) -> R<Option<u64>> {
    match r.u64s()?.as_slice() {
        [] => Ok(None),
        [n] => Ok(Some(*n)),
        _ => Err(PcsError::Malformed),
    }
}

fn bytes_field(w: &mut Writer, b: &[u8]) {
    w.u32(b.len());
    w.buf.extend_from_slice(b);
}

fn read_bytes_field(r: &mut Reader<'_>) -> R<Vec<u8>> {
    let n = r.count(1)?;
    (0..n).map(|_| r.u8()).collect()
}

impl Instance {
    pub fn write(&self, w: &mut Writer) {
        w.digest(&self.root.0);
        w.u8(u8::from(self.ext));
        w.u32(self.claims.len());
        for c in &self.claims {
            w.exts(&c.point);
            w.ext(c.value);
        }
    }
    pub fn read(r: &mut Reader<'_>) -> R<Self> {
        let root = Commitment(r.digest()?);
        let ext = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(PcsError::Malformed),
        };
        let n = r.count(28)?;
        let claims = (0..n)
            .map(|_| {
                Ok(Claim {
                    point: r.exts()?,
                    value: r.ext()?,
                })
            })
            .collect::<R<_>>()?;
        Ok(Self { root, ext, claims })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.write(&mut w);
        w.buf
    }
    pub fn from_bytes(b: &[u8]) -> R<Self> {
        let mut r = Reader::new(b);
        let v = Self::read(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

impl AccProof {
    pub fn write(&self, w: &mut Writer) {
        w.exts(&self.sumcheck);
        w.exts(&self.evals);
        nonce(w, self.comb_nonce);
        w.digest(&self.root.0);
        w.exts(&self.ood);
        nonce(w, self.query_nonce);
        w.u32(self.openings.len());
        for o in &self.openings {
            w.u8(u8::from(matches!(o.symbols, lens::rspcs::wire::Symbols::Ext(_))));
            bytes_field(w, &o.to_bytes());
        }
    }
    /// Read a proof whose input words have the given symbol types.
    pub fn read(r: &mut Reader<'_>) -> R<Self> {
        let sumcheck = r.exts()?;
        let evals = r.exts()?;
        let comb_nonce = read_nonce(r)?;
        let root = Commitment(r.digest()?);
        let ood = r.exts()?;
        let query_nonce = read_nonce(r)?;
        let m = r.count(5)?;
        let openings = (0..m)
            .map(|_| {
                let ext = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(PcsError::Malformed),
                };
                Opening::from_bytes(&read_bytes_field(r)?, ext)
            })
            .collect::<R<_>>()?;
        Ok(Self {
            sumcheck,
            evals,
            comb_nonce,
            root,
            ood,
            query_nonce,
            openings,
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.write(&mut w);
        w.buf
    }
    pub fn from_bytes(b: &[u8]) -> R<Self> {
        let mut r = Reader::new(b);
        let v = Self::read(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

impl DeciderProof {
    /// `ext`: whether the decided word has Fp3 symbols (an accumulator).
    pub fn write(&self, w: &mut Writer, ext: bool) {
        w.exts(&self.sumcheck);
        w.ext(self.value);
        w.u8(u8::from(ext));
        bytes_field(w, &self.whir.to_bytes());
    }
    pub fn read(r: &mut Reader<'_>) -> R<(Self, bool)> {
        let sumcheck = r.exts()?;
        let value = r.ext()?;
        let ext = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(PcsError::Malformed),
        };
        let whir = WhirProof::from_bytes_with(&read_bytes_field(r)?, ext)?;
        Ok((
            Self {
                sumcheck,
                value,
                whir,
            },
            ext,
        ))
    }
}
