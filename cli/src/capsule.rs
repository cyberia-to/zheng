// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Program capsule: a nox program serialized as one [[tape]] chunk.
//!
//! A raw execution trace has no public reconstruction path (`TraceRow` columns
//! are crate-private), so the capsule stores the *program* — formula text,
//! object, budget. Re-executing it deterministically reproduces the trace.
//!
//! Encoding: `(sigil::BAR, render::STRUCT)` chunk whose payload is
//! `encode_nested` of `kv` pairs in fixed order (formula, object, budget).

use tape::{encode_nested, kv, read_kv, render, sigil, Chunk, Reader};

/// A nox program: what to run and with how much budget.
pub struct Program {
    pub formula: String,
    pub object: u64,
    pub budget: u64,
}

/// Serialize a program to capsule bytes (one tape chunk frame).
pub fn encode(p: &Program) -> Vec<u8> {
    let payload = encode_nested(&[
        kv("formula", Chunk::text(&p.formula)),
        kv("object", Chunk::text(&p.object.to_string())),
        kv("budget", Chunk::text(&p.budget.to_string())),
    ]);
    Chunk::new(sigil::BAR, render::STRUCT, payload).encode()
}

/// Parse capsule bytes back into a program.
pub fn decode(bytes: &[u8]) -> Result<Program, String> {
    let chunks = Reader::read_all(bytes).map_err(|e| format!("malformed capsule: {e}"))?;
    let top = chunks.into_iter().next().ok_or("empty capsule")?;
    let map = read_kv(&top.payload);

    let get = |k: &str| -> Result<String, String> {
        map.get(k)
            .map(|c| String::from_utf8_lossy(&c.payload).into_owned())
            .ok_or_else(|| format!("capsule missing key '{k}'"))
    };

    let formula = get("formula")?;
    let object = get("object")?.parse::<u64>().map_err(|e| format!("bad object: {e}"))?;
    let budget = get("budget")?.parse::<u64>().map_err(|e| format!("bad budget: {e}"))?;
    Ok(Program { formula, object, budget })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_roundtrips() {
        let p = Program { formula: "[15 [1 42]]".to_string(), object: 0, budget: 1000 };
        let bytes = encode(&p);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.formula, p.formula);
        assert_eq!(back.object, p.object);
        assert_eq!(back.budget, p.budget);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode(b"not a tape frame at all").is_err() || decode(b"").is_err());
    }
}
