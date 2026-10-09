//! Verifying keys: the relation a statement's program compiles to, with its
//! digest, cached so a verifier compiles each program once.
//!
//! `program_key` is a hash of what the relation depends on — the program
//! tokens, the subject shape (input count, state root in the subject) and
//! the kind of statement — and is cheap to compute from any statement. A
//! [`VerifyingKey`] is only ever *derived* by the verifier from a statement
//! (no constructor from parts, no deserialisation): it holds the compiled
//! relation and `digest` = the hemera tree root of `program_key ‖
//! canonical relation encoding`. A verifier handed a key checks `key.program_key ==
//! program_key(statement)` and otherwise rejects; a key for another program
//! or shape is never used. Transcript-bearing profiles absorb the digest,
//! so a proof is bound to the relation it was made for, whichever compiler
//! produced it.

use super::relation::ExecutionRelation;
use super::state::StateStatement;
use super::statement::{ExecutionStatement, NounToken};

const KEY_DOMAIN: &[u8] = b"zheng-vk-program-v1";
const DIGEST_DOMAIN: &[u8] = b"zheng-vk-relation-v1";

/// The shape of statement a key is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementKind {
    Execution,
    State { root_in_subject: bool },
}

/// The key of a statement: what its relation depends on, hashed.
pub fn program_key(program: &[NounToken], inputs: usize, kind: StatementKind) -> [u8; 32] {
    let mut h = hemera::Hasher::new();
    h.update(KEY_DOMAIN);
    h.update(&match kind {
        StatementKind::Execution => [0u8, 0],
        StatementKind::State { root_in_subject } => [1u8, u8::from(root_in_subject)],
    });
    h.update(&(inputs as u64).to_le_bytes());
    h.update(&(program.len() as u64).to_le_bytes());
    let mut buf = Vec::with_capacity(program.len() * 9);
    for token in program {
        match token {
            NounToken::Atom(v) => {
                buf.push(0);
                buf.extend_from_slice(&v.to_le_bytes());
            }
            NounToken::Pair => buf.push(1),
        }
    }
    h.update(&buf);
    *h.finalize().as_bytes()
}

/// A compiled relation and its digest, derived by the verifier.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    program_key: [u8; 32],
    digest: [u8; 32],
    relation: ExecutionRelation,
}

impl VerifyingKey {
    /// Compile the relation of a public execution statement.
    pub fn for_execution(statement: &ExecutionStatement) -> Result<Self, String> {
        let relation = statement.relation()?;
        Ok(Self::new(statement.program_key(), relation))
    }

    /// Compile the relation of a state statement.
    pub fn for_state(statement: &StateStatement) -> Result<Self, String> {
        let relation = statement.relation()?;
        Ok(Self::new(statement.program_key(), relation))
    }

    pub(crate) fn new(program_key: [u8; 32], relation: ExecutionRelation) -> Self {
        let digest = relation_digest(&program_key, &relation);
        Self {
            program_key,
            digest,
            relation,
        }
    }

    pub fn program_key(&self) -> [u8; 32] {
        self.program_key
    }

    /// The hemera tree root of `domain ‖ program_key ‖ canonical relation encoding`.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn relation(&self) -> &ExecutionRelation {
        &self.relation
    }

    /// This key, if it was derived for `key`; an error otherwise.
    pub(crate) fn check(&self, key: [u8; 32]) -> Result<&Self, String> {
        if self.program_key != key {
            return Err("verifying key was derived for another program or shape".into());
        }
        Ok(self)
    }
}

/// The canonical relation encoding: dimensions, every matrix row by row
/// (entry count, then `(column, coefficient)` pairs), the multisets and
/// coefficients, then the public wiring (inputs, outputs, cost, the cost
/// bound and every lookup's coordinates), after the domain and the program
/// key; hashed by [`tree_digest`]. Integers are LEB128; a coefficient `c`
/// is written as the zigzag of its centred representative (`c` or
/// `c − p`), so `±1` and small constants take one byte. The encoding is
/// produced, never parsed: it needs to be injective, and is.
fn relation_digest(program_key: &[u8; 32], r: &ExecutionRelation) -> [u8; 32] {
    fn put(buf: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            buf.push((v as u8) | 0x80);
            v >>= 7;
        }
        buf.push(v as u8);
    }
    fn coeff(buf: &mut Vec<u8>, c: nebu::Goldilocks) {
        let c = c.as_u64();
        let p = nebu::field::P;
        // zigzag of the centred value: c ≤ p/2 → 2c, else 2(p − c) − 1
        put(buf, if c <= p / 2 { c << 1 } else { ((p - c) << 1) - 1 });
    }
    let i = &r.instance;
    let nnz: usize = i.matrices.iter().flat_map(|m| m.entries.iter().map(Vec::len)).sum();
    let mut buf: Vec<u8> = Vec::with_capacity(DIGEST_DOMAIN.len() + 64 + 8 * nnz);
    buf.extend_from_slice(DIGEST_DOMAIN);
    buf.extend_from_slice(program_key);
    for v in [i.num_rows, i.num_cols, i.matrices.len()] {
        put(&mut buf, v as u64);
    }
    for m in &i.matrices {
        put(&mut buf, m.rows as u64);
        put(&mut buf, m.cols as u64);
        put(&mut buf, m.entries.len() as u64);
        for row in &m.entries {
            put(&mut buf, row.len() as u64);
            for &(c, v) in row {
                put(&mut buf, c as u64);
                coeff(&mut buf, v);
            }
        }
    }
    put(&mut buf, i.multisets.len() as u64);
    for set in &i.multisets {
        put(&mut buf, set.len() as u64);
        for &m in set {
            put(&mut buf, m as u64);
        }
    }
    put(&mut buf, i.coeffs.len() as u64);
    for &c in &i.coeffs {
        coeff(&mut buf, c);
    }
    for list in [&r.input_indices, &r.output_indices] {
        put(&mut buf, list.len() as u64);
        for &x in list {
            put(&mut buf, x as u64);
        }
    }
    put(&mut buf, r.cost_index as u64);
    put(&mut buf, r.max_cost);
    put(&mut buf, r.lookups.len() as u64);
    for l in &r.lookups {
        for x in [l.active, l.root[0], l.root[1], l.root[2], l.root[3], l.namespace, l.key, l.value] {
            put(&mut buf, x as u64);
        }
    }
    tree_digest(&buf)
}

/// Bytes per leaf of the digest tree.
const LEAF_BYTES: usize = 1024;

/// A hemera Merkle root over `LEAF_BYTES` chunks: leaves (chunk flag,
/// counter) and nodes (parent flag, root flag at the top) hash in 16-lane
/// batches. Leaves are padded to a power of two with empty chunks; the
/// encoding starts with its own dimensions, so the padding is unambiguous.
fn tree_digest(bytes: &[u8]) -> [u8; 32] {
    use hemera::Hash;
    use hemera::tree::{hash_leaf_batch, hash_node_batch};
    let chunks = bytes.len().div_ceil(LEAF_BYTES).max(1);
    let count = chunks.next_power_of_two();
    let leaves: Vec<(&[u8], u64)> = (0..count)
        .map(|i| {
            let start = (i * LEAF_BYTES).min(bytes.len());
            let end = ((i + 1) * LEAF_BYTES).min(bytes.len());
            (&bytes[start..end], i as u64)
        })
        .collect();
    let mut level = vec![Hash::from_bytes([0; 32]); count];
    hash_leaf_batch(&leaves, count == 1, &mut level);
    while level.len() > 1 {
        let pairs: Vec<(Hash, Hash)> = level.chunks_exact(2).map(|p| (p[0], p[1])).collect();
        let mut next = vec![Hash::from_bytes([0; 32]); pairs.len()];
        hash_node_batch(&pairs, pairs.len() == 1, &mut next);
        level = next;
    }
    *level[0].as_bytes()
}

#[cfg(test)]
#[path = "vk_tests.rs"]
mod tests;
