//! Committed key trees on disk (`ZHENG_KEY_CACHE=<dir>`): a prover's key
//! words — the IVC key's and the inner wrap levels' — are committed once
//! per machine, not once per process. A tree is stored under a digest of
//! everything that fixes it (the members' coefficients, the layout, the
//! fan-in); a loaded tree is used as committed — a damaged file makes the
//! prover's proofs fail verification (and an inner level's root is still
//! checked against `envelope::wrapped::INNER_ROOTS`, an IVC key's against
//! `envelope::recursive::KEY_ROOTS`), never a verifier accept.

use std::path::{Path, PathBuf};

use nebu::Goldilocks;

use super::word::Digest;

const MAGIC: &[u8; 8] = b"ZHTREE01";

/// The cache directory (`ZHENG_KEY_CACHE`), if any.
pub fn dir() -> Option<PathBuf> {
    std::env::var_os("ZHENG_KEY_CACHE").map(PathBuf::from)
}

fn path(dir: &Path, id: [u64; 2]) -> PathBuf {
    dir.join(format!("tree-{:016x}{:016x}.bin", id[0], id[1]))
}

/// A 128-bit identifier of `words` (two independent SipHash runs).
pub fn id(words: impl Fn(&mut dyn std::hash::Hasher)) -> [u64; 2] {
    use std::hash::Hasher;
    let mut out = [0u64; 2];
    for (k, o) in out.iter_mut().enumerate() {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        h.write_u64(0x5a48_5452_4545_0000 + k as u64);
        words(&mut h);
        *o = h.finish();
    }
    out
}

/// The tree levels stored under `id`, if any.
pub fn load(dir: &Path, id: [u64; 2]) -> Option<Vec<Vec<Digest>>> {
    let b = std::fs::read(path(dir, id)).ok()?;
    let mut at = 0usize;
    let mut u64s = |n: usize| -> Option<Vec<u64>> {
        let s = b.get(at..at + 8 * n)?;
        at += 8 * n;
        Some(s.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().expect("8"))).collect())
    };
    let head = u64s(2)?;
    if head[0] != u64::from_le_bytes(*MAGIC) {
        return None;
    }
    let mut levels = Vec::with_capacity(head[1] as usize);
    for _ in 0..head[1] {
        let n = u64s(1)?[0] as usize;
        let v = u64s(4 * n)?;
        if v.iter().any(|&x| x >= nebu::field::P) {
            return None;
        }
        levels.push(v.chunks_exact(4).map(|d| core::array::from_fn(|i| Goldilocks::new(d[i]))).collect());
    }
    (at == b.len()).then_some(levels)
}

/// Store the tree levels under `id` (best effort: a cache).
pub fn store(dir: &Path, id: [u64; 2], levels: &[Vec<Digest>]) {
    let p = path(dir, id);
    let mut b = Vec::new();
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&(levels.len() as u64).to_le_bytes());
    for l in levels {
        b.extend_from_slice(&(l.len() as u64).to_le_bytes());
        for d in l {
            for x in d {
                b.extend_from_slice(&x.as_u64().to_le_bytes());
            }
        }
    }
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, &b).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}
