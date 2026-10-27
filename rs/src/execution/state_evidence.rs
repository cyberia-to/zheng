//! State evidence: what authenticates every read of a state statement,
//! checked inside zheng against the statement's own root.
//!
//! The authenticated state is the BBG layout (bbg `root.rs`,
//! `certificate.rs`), restated here so that no verifier depends on a caller
//! to authenticate reads:
//!
//! - a table is the complete field vector of one public dimension: header
//!   `[TABLE_VERSION, len, entries]`, then the entries; its leaf is the
//!   lens Brakedown commitment of the fields zero-padded to a power of two,
//!   as four little-endian limbs (`len` in the header makes the padding
//!   unambiguous: a table with appended zeros has another header);
//! - the root is the left fold of `compress4` — the first four elements of
//!   the hemera permutation over `[acc ‖ leaf ‖ 0⁸]` — over 14 leaves (11
//!   dimensions, A, N, statistics) from the IV `[ROOT_TAG, 0, 0, 0]`;
//! - a read `(namespace, key)` is the table field at index `key`.
//!
//! A state statement verifies only together with evidence whose root is
//! the statement's `state_root` and which carries the table of every
//! namespace an active read names. bbg's `StateCertificate` converts into
//! this type; `root_matches_the_bbg_frozen_vectors` pins the layout to
//! bbg's frozen values.

use hemera::field::Goldilocks as HGold;
use hemera::permutation::permute;
use lens::brakedown::Brakedown;
use lens::{Lens, MultilinearPoly};
use nebu::Goldilocks;

/// Version word in field 0 of every table.
pub const TABLE_VERSION: u64 = 2;
/// Header fields: version, length, entry count.
pub const HEADER_FIELDS: usize = 3;
/// Bound on the fields one evidence may carry.
pub const MAX_FIELDS: usize = 1 << 20;
/// Namespaces 0..=10 are public dimensions.
pub const MAX_NAMESPACE: u64 = 10;
/// Root leaves: 11 dimensions, A, N, statistics.
pub const LEAVES: usize = 14;
/// `"bbg-root"` as a little-endian u64: the root chain's domain tag.
pub const ROOT_TAG: u64 = u64::from_le_bytes(*b"bbg-root");

/// The complete fields of one public dimension.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateTable {
    pub namespace: u64,
    pub fields: Vec<u64>,
}

/// The root leaves and the tables a statement's reads come from.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateEvidence {
    pub leaves: [[u64; 4]; LEAVES],
    /// Namespaces strictly increasing, each at most once.
    pub tables: Vec<StateTable>,
}

/// Evidence checked against one root; only this type answers reads.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedState<'a> {
    evidence: &'a StateEvidence,
}

fn canonical(v: u64) -> bool {
    v < nebu::field::P
}

/// One hemera compression: the first four elements of `P([a ‖ b ‖ 0⁸])`.
fn compress4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut state = [HGold::ZERO; 16];
    for i in 0..4 {
        state[i] = HGold::new(a[i]);
        state[4 + i] = HGold::new(b[i]);
    }
    permute(&mut state);
    core::array::from_fn(|i| state[i].as_canonical_u64())
}

/// The state root of `leaves`: the left fold of `compress4` from the IV.
pub fn state_root_of(leaves: &[[u64; 4]; LEAVES]) -> [u64; 4] {
    leaves
        .iter()
        .fold([ROOT_TAG, 0, 0, 0], |acc, leaf| compress4(&acc, leaf))
}

/// The leaf of a table: its Brakedown commitment as four limbs.
pub fn table_leaf(fields: &[u64]) -> [u64; 4] {
    let mut padded: Vec<Goldilocks> = fields.iter().map(|&v| Goldilocks::new(v)).collect();
    padded.resize(padded.len().next_power_of_two(), Goldilocks::ZERO);
    let commitment = Brakedown::commit(&MultilinearPoly::new(padded));
    core::array::from_fn(|i| {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&commitment.as_bytes()[8 * i..8 * i + 8]);
        u64::from_le_bytes(limb)
    })
}

impl StateTable {
    /// A table with a well-formed header around `body`. The header's entry
    /// count is 0: zheng reads fields by index and never interprets
    /// entries (bbg tables carry their own count).
    pub fn with_body(namespace: u64, body: &[u64]) -> Self {
        let mut fields = vec![TABLE_VERSION, (HEADER_FIELDS + body.len()) as u64, 0];
        fields.extend_from_slice(body);
        Self { namespace, fields }
    }

    fn well_formed(&self) -> bool {
        let n = self.fields.len();
        self.namespace <= MAX_NAMESPACE
            && (HEADER_FIELDS..=MAX_FIELDS).contains(&n)
            && self.fields[0] == TABLE_VERSION
            && self.fields[1] == n as u64
            && self.fields.iter().all(|&v| canonical(v))
    }
}

impl StateEvidence {
    /// Evidence for a state holding `tables`, every other leaf zero.
    pub fn with_tables(tables: Vec<StateTable>) -> Self {
        let mut leaves = [[0u64; 4]; LEAVES];
        for t in &tables {
            if let Some(leaf) = leaves.get_mut(t.namespace as usize) {
                *leaf = table_leaf(&t.fields);
            }
        }
        Self { leaves, tables }
    }

    /// Check the shape, every table against its leaf, and return the root
    /// the evidence authenticates.
    pub fn root(&self) -> Result<[u64; 4], String> {
        if self.leaves.iter().flatten().any(|&v| !canonical(v)) {
            return Err("state evidence: noncanonical root leaf".into());
        }
        if self.tables.len() > (MAX_NAMESPACE + 1) as usize
            || self.tables.windows(2).any(|t| t[0].namespace >= t[1].namespace)
        {
            return Err("state evidence: namespaces must be unique and increasing".into());
        }
        let total = self.tables.iter().map(|t| t.fields.len()).sum::<usize>();
        if total > MAX_FIELDS || self.tables.iter().any(|t| !t.well_formed()) {
            return Err("state evidence: malformed table".into());
        }
        for table in &self.tables {
            if table_leaf(&table.fields) != self.leaves[table.namespace as usize] {
                return Err(format!(
                    "state evidence: table {} does not match its leaf",
                    table.namespace
                ));
            }
        }
        Ok(state_root_of(&self.leaves))
    }

    /// Authenticate the evidence under `root`.
    pub fn authenticate(&self, root: [u64; 4]) -> Result<AuthenticatedState<'_>, String> {
        if root.iter().any(|&v| !canonical(v)) {
            return Err("state evidence: noncanonical root".into());
        }
        if self.root()? != root {
            return Err("state evidence: root mismatch".into());
        }
        Ok(AuthenticatedState { evidence: self })
    }
}

/// Namespaces a private state relation selects from (all public tables a
/// hidden query may name).
pub const PRIVATE_NAMESPACES: u64 = 10;
/// Bound on the fields the private relation embeds as constants.
pub const PRIVATE_MAX_FIELDS: usize = 2048;

impl StateEvidence {
    /// Authenticate under `root` and return the ten tables a private state
    /// relation embeds: the evidence must carry namespaces `0..10`.
    pub fn private_tables(
        &self,
        root: [u64; 4],
    ) -> Result<super::relation::PublicStateTables, String> {
        let state = self.authenticate(root)?;
        let mut dimensions: [Vec<Goldilocks>; PRIVATE_NAMESPACES as usize] = Default::default();
        let mut total = 0usize;
        for (ns, slot) in dimensions.iter_mut().enumerate() {
            let table = state
                .evidence
                .tables
                .iter()
                .find(|t| t.namespace == ns as u64)
                .ok_or_else(|| format!("state evidence: private state needs table {ns}"))?;
            total += table.fields.len();
            *slot = table.fields.iter().map(|&v| Goldilocks::new(v)).collect();
        }
        if total > PRIVATE_MAX_FIELDS {
            return Err("state evidence: private state tables exceed 2048 fields".into());
        }
        Ok(super::relation::PublicStateTables {
            root: root.map(Goldilocks::new),
            dimensions,
        })
    }
}

impl AuthenticatedState<'_> {
    /// The field at index `key` of table `namespace`, if the evidence
    /// carries that table and the index exists.
    pub fn cell(&self, namespace: u64, key: u64) -> Option<u64> {
        let table = self
            .evidence
            .tables
            .iter()
            .find(|t| t.namespace == namespace)?;
        table.fields.get(usize::try_from(key).ok()?).copied()
    }

    /// The root this evidence was authenticated under.
    pub fn root(&self) -> [u64; 4] {
        state_root_of(&self.evidence.leaves)
    }
}

#[cfg(test)]
#[path = "state_evidence_tests.rs"]
pub(crate) mod tests;
