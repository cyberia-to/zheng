//! The opening proof and its canonical bytes.
//!
//! ```text
//! header     5 B      HidingParams::header
//! mu         Fp3
//! row_test   K × Fp3          (K from the verifier's shape)
//! linear     (K + k − 1) × Fp3
//! pow_nonce  u64              (present iff pow_bits > 0)
//! opened     u32 s            distinct opened columns
//! columns    s × T × u64      T = data rows + 3
//! salts      s × 4 × u64
//! siblings   u32 d, d × 32 B
//! ```
//!
//! Every length but the opened count and the sibling count is fixed by the
//! verifier's shape; values must be canonical. An Fp3 is three canonical
//! u64 limbs.

use hemera::Hash;
use nebu::{Fp3, Goldilocks};

use super::{Config, HidingParams, SALT};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HidingProof {
    pub params: HidingParams,
    pub mu: Fp3,
    pub row_test: Vec<Fp3>,
    pub linear: Vec<Fp3>,
    pub pow_nonce: Option<u64>,
    pub columns: Vec<Goldilocks>,
    pub salts: Vec<Goldilocks>,
    pub siblings: Vec<Hash>,
}

fn ext(out: &mut Vec<u8>, x: Fp3) {
    for l in [x.c0, x.c1, x.c2] {
        out.extend_from_slice(&l.as_u64().to_le_bytes());
    }
}

pub(crate) struct Cursor<'a> {
    pub bytes: &'a [u8],
}

impl Cursor<'_> {
    pub fn take(&mut self, n: usize) -> Result<&[u8], String> {
        if self.bytes.len() < n {
            return Err("veil: truncated".into());
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }
    pub fn u32(&mut self) -> Result<usize, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")) as usize)
    }
    pub fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }
    pub fn base(&mut self) -> Result<Goldilocks, String> {
        let v = self.u64()?;
        if v >= nebu::field::P {
            return Err("veil: noncanonical field element".into());
        }
        Ok(Goldilocks::new(v))
    }
    pub fn ext(&mut self) -> Result<Fp3, String> {
        Ok(Fp3::new(self.base()?, self.base()?, self.base()?))
    }
    pub fn exts(&mut self, n: usize) -> Result<Vec<Fp3>, String> {
        (0..n).map(|_| self.ext()).collect()
    }
}

pub(crate) fn write_ext(out: &mut Vec<u8>, x: Fp3) {
    ext(out, x);
}

impl HidingProof {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.params.header());
        ext(out, self.mu);
        self.row_test.iter().for_each(|&x| ext(out, x));
        self.linear.iter().for_each(|&x| ext(out, x));
        if let Some(n) = self.pow_nonce {
            out.extend_from_slice(&n.to_le_bytes());
        }
        let opened = self.salts.len() / SALT;
        out.extend_from_slice(&(opened as u32).to_le_bytes());
        for v in self.columns.iter().chain(&self.salts) {
            out.extend_from_slice(&v.as_u64().to_le_bytes());
        }
        out.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for h in &self.siblings {
            out.extend_from_slice(h.as_bytes());
        }
    }

    /// Read a proof for a commitment of `entries` values; the shape comes
    /// from the parameters in the header, never from the bytes.
    pub fn read(r: &mut Cursor<'_>, entries: usize) -> Result<Self, String> {
        let params = HidingParams::from_header(r.take(HidingParams::HEADER)?)
            .ok_or("veil: hiding header")?;
        let cfg = Config::derive(&params, entries)?;
        let mu = r.ext()?;
        let row_test = r.exts(cfg.big_k())?;
        let linear = r.exts(cfg.big_k() + cfg.k - 1)?;
        let pow_nonce = if cfg.pow_bits > 0 { Some(r.u64()?) } else { None };
        let opened = r.u32()?;
        if opened == 0 || opened > cfg.queries {
            return Err("veil: opened column count".into());
        }
        let columns = (0..opened * cfg.total_rows())
            .map(|_| r.base())
            .collect::<Result<Vec<_>, _>>()?;
        let salts = (0..opened * SALT).map(|_| r.base()).collect::<Result<Vec<_>, _>>()?;
        let d = r.u32()?;
        if d > opened * cfg.log_n as usize {
            return Err("veil: sibling count".into());
        }
        let siblings = (0..d)
            .map(|_| {
                let b: [u8; 32] = r.take(32)?.try_into().expect("32");
                Ok(Hash::from_bytes(b))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            params,
            mu,
            row_test,
            linear,
            pow_nonce,
            columns,
            salts,
            siblings,
        })
    }
}
