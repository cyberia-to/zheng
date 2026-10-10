//! Canonical bytes of an AIR proof (lens wire conventions).
//!
//! ```text
//! u32 S · S × 32 B roots1 · S × 32 B roots2 · S × exts ood1 · S × exts ood2
//! · S × segment
//! segment: u32 w + w × u64 boundary · u32 R · R × exts round
//!          · exts local · exts next · exts shift · ext v1 · ext v2
//! ```

use lens::rspcs::wire::{Reader, Writer};
use lens::{Commitment, PcsError};

use super::{AirProof, SegmentProof};

impl SegmentProof {
    fn write(&self, w: &mut Writer) {
        w.u32(self.boundary.len());
        for &b in &self.boundary {
            w.base(b);
        }
        w.u32(self.zerocheck.len());
        for r in &self.zerocheck {
            w.exts(r);
        }
        w.exts(&self.local);
        w.exts(&self.next);
        w.exts(&self.shift);
        w.ext(self.v1);
        w.ext(self.v2);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, PcsError> {
        let nb = r.count(8)?;
        let boundary = (0..nb).map(|_| r.base()).collect::<Result<_, _>>()?;
        let n = r.count(4)?;
        let zerocheck = (0..n).map(|_| r.exts()).collect::<Result<_, _>>()?;
        Ok(Self {
            boundary,
            zerocheck,
            local: r.exts()?,
            next: r.exts()?,
            shift: r.exts()?,
            v1: r.ext()?,
            v2: r.ext()?,
        })
    }
}

impl AirProof {
    pub fn write(&self, w: &mut Writer) {
        w.u32(self.segments.len());
        for r in self.roots1.iter().chain(&self.roots2) {
            w.digest(&r.0);
        }
        for a in self.ood1.iter().chain(&self.ood2) {
            w.exts(a);
        }
        for s in &self.segments {
            s.write(w);
        }
    }
    pub fn read(r: &mut Reader<'_>) -> Result<Self, PcsError> {
        let s = r.count(64)?;
        let roots1 = (0..s).map(|_| r.digest().map(Commitment)).collect::<Result<_, _>>()?;
        let roots2 = (0..s).map(|_| r.digest().map(Commitment)).collect::<Result<_, _>>()?;
        let ood1 = (0..s).map(|_| r.exts()).collect::<Result<_, _>>()?;
        let ood2 = (0..s).map(|_| r.exts()).collect::<Result<_, _>>()?;
        let segments = (0..s).map(|_| SegmentProof::read(r)).collect::<Result<_, _>>()?;
        Ok(Self {
            roots1,
            roots2,
            ood1,
            ood2,
            segments,
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.write(&mut w);
        w.buf
    }
}
