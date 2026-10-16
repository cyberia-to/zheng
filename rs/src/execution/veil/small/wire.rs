//! veil-W proof bytes.
//!
//! ```text
//! magic     8 B   "ZHVEILW1"
//! header    8 B   WHIR parameters (lens `WhirParams::header`)
//! root      32 B  the round-0 commitment (c, G, salts)
//! g1        Fp3   Σ of the outer mask
//! outer     log m rounds × d Fp3   round polynomials without c_1
//! evals     t × Fp3
//! g2        Fp3   Σ of the inner mask
//! inner     ℓ rounds × 2 Fp3
//! u_psi     Fp3   Ψ(c)
//! u         Fp3   Λ(g)
//! nonce     u64   grinding before β (0 without)
//! opening   lens WhirProof bytes after its 8-byte header
//! ```
//!
//! Counts come from the relation the verifier derives; the opening is
//! parsed by lens and must end the input exactly.

use lens::Commitment;
use lens::rspcs::WhirProof;
use lens::rspcs::whir::zk::ZkValues;
use lens::WhirParams;

use super::super::hiding::proof::{Cursor, write_ext};
use super::super::wire::Shape;
use super::protocol::{Parts, SpartanMsgsWire};
use crate::spartan::reduce::CompressedRounds;

pub const MAGIC: &[u8; 8] = b"ZHVEILW1";
/// Upper bound on a proof's bytes.
pub const MAX_BYTES: usize = 8 << 20;

impl Parts {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.params.header());
        out.extend_from_slice(self.root.as_bytes());
        let s = &self.spartan;
        write_ext(&mut out, s.g1);
        s.outer.rounds.iter().flatten().for_each(|&x| write_ext(&mut out, x));
        s.evals.iter().for_each(|&x| write_ext(&mut out, x));
        write_ext(&mut out, s.g2);
        s.inner.rounds.iter().flatten().for_each(|&x| write_ext(&mut out, x));
        write_ext(&mut out, self.u_psi);
        write_ext(&mut out, self.vals.u);
        out.extend_from_slice(&self.vals.nonce.to_le_bytes());
        out.extend_from_slice(&self.opening.to_bytes()[8..]);
        out
    }

    /// Parse against the relation's shape; `v` is the verifier's to fill.
    pub fn from_bytes(bytes: &[u8], shape: Shape) -> Result<Self, String> {
        if bytes.len() > MAX_BYTES {
            return Err("veil-W: proof too large".into());
        }
        let mut r = Cursor { bytes };
        if r.take(8)? != MAGIC {
            return Err("veil-W: magic".into());
        }
        let header: [u8; 8] = r.take(8)?.try_into().expect("8");
        let params = WhirParams::from_header(header).map_err(|e| format!("veil-W: header: {e:?}"))?;
        if params.header() != header {
            return Err("veil-W: header encoding".into());
        }
        let root = Commitment(hemera::Hash::from_bytes(r.take(32)?.try_into().expect("32")));
        let g1 = r.ext()?;
        let outer = CompressedRounds {
            rounds: (0..shape.log_m).map(|_| r.exts(shape.degree)).collect::<Result<_, _>>()?,
        };
        let evals = r.exts(shape.matrices)?;
        let g2 = r.ext()?;
        let inner = CompressedRounds {
            rounds: (0..shape.vars).map(|_| r.exts(2)).collect::<Result<_, _>>()?,
        };
        let u_psi = r.ext()?;
        let u = r.ext()?;
        let nonce = r.u64()?;
        let mut whir = header.to_vec();
        whir.extend_from_slice(r.bytes);
        let opening = WhirProof::from_bytes(&whir).map_err(|e| format!("veil-W: opening bytes: {e:?}"))?;
        Ok(Self {
            params,
            root,
            spartan: SpartanMsgsWire { g1, outer, evals, g2, inner },
            u_psi,
            // `v` is never on the wire: the verifier recomputes it and
            // compares; the parser leaves the prover's claim unset
            vals: ZkValues { v: nebu::Fp3::ZERO, u, nonce },
            opening,
        })
    }
}
