//! The zk proof's bytes.
//!
//! ```text
//! magic     8 B   "ZHVEIL01"
//! root      32 B  the hiding commitment
//! g1        Fp3   Σ of the outer mask
//! outer     log m rounds × d Fp3   round polynomials without c_1 (d = CCS degree + 1)
//! evals     t × Fp3                M̃_i(ρ_x), t matrices
//! g2        Fp3   Σ of the inner mask
//! inner     ℓ rounds × 2 Fp3       without c_1
//! opening   the hiding opening (`hiding::proof`)
//! ```
//!
//! Every count is the verifier's, derived from the relation; a proof is
//! parsed only against that shape and must be consumed exactly.

use lens::Commitment;
use nebu::Fp3;

use super::hiding::HidingProof;
use super::hiding::proof::{Cursor, write_ext};
use crate::spartan::reduce::CompressedRounds;

pub const MAGIC: &[u8; 8] = b"ZHVEIL01";
/// Upper bound on a proof's bytes.
pub const MAX_BYTES: usize = 64 << 20;

/// Parsed proof fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parsed {
    pub root: Commitment,
    pub g1: Fp3,
    pub outer: CompressedRounds<Fp3>,
    pub evals: Vec<Fp3>,
    pub g2: Fp3,
    pub inner: CompressedRounds<Fp3>,
    pub opening: HidingProof,
}

/// The counts a proof is parsed against.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Shape {
    pub log_m: usize,
    pub degree: usize,
    pub matrices: usize,
    pub vars: usize,
    pub entries: usize,
}

impl Parsed {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(self.root.as_bytes());
        write_ext(&mut out, self.g1);
        self.outer.rounds.iter().flatten().for_each(|&x| write_ext(&mut out, x));
        self.evals.iter().for_each(|&x| write_ext(&mut out, x));
        write_ext(&mut out, self.g2);
        self.inner.rounds.iter().flatten().for_each(|&x| write_ext(&mut out, x));
        self.opening.write(&mut out);
        out
    }

    pub fn from_bytes(bytes: &[u8], shape: Shape) -> Result<Self, String> {
        if bytes.len() > MAX_BYTES {
            return Err("veil: proof too large".into());
        }
        let mut r = Cursor { bytes };
        if r.take(8)? != MAGIC {
            return Err("veil: magic".into());
        }
        let root = Commitment(hemera::Hash::from_bytes(r.take(32)?.try_into().expect("32")));
        let g1 = r.ext()?;
        let outer = CompressedRounds {
            rounds: (0..shape.log_m)
                .map(|_| r.exts(shape.degree))
                .collect::<Result<_, _>>()?,
        };
        let evals = r.exts(shape.matrices)?;
        let g2 = r.ext()?;
        let inner = CompressedRounds {
            rounds: (0..shape.vars).map(|_| r.exts(2)).collect::<Result<_, _>>()?,
        };
        let opening = HidingProof::read(&mut r, shape.entries)?;
        if !r.bytes.is_empty() {
            return Err("veil: trailing bytes".into());
        }
        Ok(Self {
            root,
            g1,
            outer,
            evals,
            g2,
            inner,
            opening,
        })
    }
}
