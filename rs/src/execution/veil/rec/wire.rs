//! veil-r proof bytes. Every count is fixed by the key; values are
//! canonical little-endian limbs.
//!
//! ```text
//! magic     8 B "ZHVEILR1"
//! root      4 limbs
//! g1        Fp3 · outer log m × d Fp3 · evals t Fp3
//! g2        Fp3 · inner ℓ × 2 Fp3
//! mu        Fp3 · row test K Fp3 · linear (K + k − 1) Fp3
//! nonce     1 limb
//! queries × (T + 4 symbols, path of 4-limb siblings)
//! ```

use lens::rspcs::wire::{Reader, Writer};
use nebu::Fp3;

use super::{ARITY, RecKey, RecProof};
use crate::execution::veil::hiding::SALT;
use crate::recursion::wire::{bases, digest, exts, read_bases, read_digest, read_exts};
use crate::recursion::word::LeafOpening;

pub const MAGIC: &[u8; 8] = b"ZHVEILR1";

fn shape(key: &RecKey) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
    let s = &key.pk.setup;
    let c = &key.cfg;
    (s.log_m, s.degree, s.instance.matrices.len(), s.layout.vars, c.big_k(), c.k, c.total_rows() + SALT, ARITY.path_len(c.log_n as usize))
}

/// The proof's counts under `key`.
pub(crate) fn check_shape(key: &RecKey, p: &RecProof) -> Result<(), String> {
    let (log_m, d, t, vars, big_k, k, leaf, path) = shape(key);
    let ok = p.outer.len() == log_m
        && p.outer.iter().all(|m| m.len() == d)
        && p.evals.len() == t
        && p.inner.len() == vars
        && p.inner.iter().all(|m| m.len() == 2)
        && p.row_test.len() == big_k
        && p.linear.len() == big_k + k - 1
        && p.nonce < nebu::field::P
        && p.openings.len() == key.cfg.queries
        && p.openings.iter().all(|o| o.symbols.len() == leaf && o.path.len() == path && o.symbols.iter().all(|s| s.c1 == nebu::Goldilocks::ZERO && s.c2 == nebu::Goldilocks::ZERO));
    if ok { Ok(()) } else { Err("veil-r: proof shape".into()) }
}

pub(crate) fn write(key: &RecKey, p: &RecProof) -> Vec<u8> {
    let mut w = Writer::default();
    w.buf.extend_from_slice(MAGIC);
    digest(&mut w, &p.root);
    w.ext(p.g1);
    p.outer.iter().for_each(|m| exts(&mut w, m));
    exts(&mut w, &p.evals);
    w.ext(p.g2);
    p.inner.iter().for_each(|m| exts(&mut w, m));
    w.ext(p.mu);
    exts(&mut w, &p.row_test);
    exts(&mut w, &p.linear);
    w.base(nebu::Goldilocks::new(p.nonce));
    for o in &p.openings {
        bases(&mut w, &o.symbols.iter().map(|s| s.c0).collect::<Vec<_>>());
        o.path.iter().for_each(|d| digest(&mut w, d));
    }
    let _ = key;
    w.buf
}

pub(crate) fn read(bytes: &[u8], key: &RecKey) -> Result<RecProof, String> {
    let e = |e: lens::PcsError| format!("veil-r proof: {e}");
    if bytes.len() < 8 || &bytes[..8] != MAGIC {
        return Err("veil-r proof: magic".into());
    }
    let (log_m, d, t, vars, big_k, k, leaf, path) = shape(key);
    let mut r = Reader::new(&bytes[8..]);
    let root = read_digest(&mut r).map_err(e)?;
    let g1 = r.ext().map_err(e)?;
    let outer = (0..log_m).map(|_| read_exts(&mut r, d)).collect::<Result<_, _>>().map_err(e)?;
    let evals = read_exts(&mut r, t).map_err(e)?;
    let g2 = r.ext().map_err(e)?;
    let inner = (0..vars).map(|_| read_exts(&mut r, 2)).collect::<Result<_, _>>().map_err(e)?;
    let mu = r.ext().map_err(e)?;
    let row_test = read_exts(&mut r, big_k).map_err(e)?;
    let linear = read_exts(&mut r, big_k + k - 1).map_err(e)?;
    let nonce = r.base().map_err(e)?.as_u64();
    let mut openings = Vec::with_capacity(key.cfg.queries);
    for _ in 0..key.cfg.queries {
        let symbols = read_bases(&mut r, leaf).map_err(e)?.into_iter().map(Fp3::from_base).collect();
        let path = (0..path).map(|_| read_digest(&mut r)).collect::<Result<_, _>>().map_err(e)?;
        openings.push(LeafOpening { symbols, path, leaf: None });
    }
    r.finish().map_err(e)?;
    Ok(RecProof { root, g1, outer, evals, g2, inner, mu, row_test, linear, nonce, openings })
}
