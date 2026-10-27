// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Fiat-Shamir transcript for zheng.
//!
//! Wraps a hemera hasher in sponge mode: absorb prover messages,
//! squeeze verifier challenges. Each proof phase has a unique domain
//! separator to prevent cross-phase attacks.
//!
//! hemera is modelled as a random oracle. The production profiles
//! (succinct, veil) draw every challenge in Fp3 (`squeeze_fp3`, a set of
//! p³ ≈ 2^192 elements); Goldilocks challenges (`new_v1`) serve only
//! retired artifacts and the legacy path. Bounds: `specs/soundness.md`.

use hemera::Hasher;
use nebu::{field::P, Fp3, Goldilocks};

use lens::Commitment;

#[cfg(feature = "legacy")]
use crate::types::Statement;
use crate::field::ChallengeField;
use crate::types::SumcheckPoly;

// ── domain separators ─────────────────────────────────────────────
// absorbed before the corresponding phase message. unique per phase.

const DOM_INIT: &[u8]      = b"\x01zheng-transcript-v1";
const DOM_SQUEEZE_WIDE: &[u8] = b"\x09squeeze-wide";
const DOM_COMMIT: &[u8]    = b"\x02commit";
const DOM_SUMCHECK: u8     = 0x03;
const DOM_EVAL: &[u8]      = b"\x04eval";
const DOM_PCS_OPEN: &[u8]  = b"\x05pcs-open";
#[cfg(feature = "legacy")]
const DOM_RECURSE: &[u8]   = b"\x06recurse";
#[cfg(feature = "legacy")]
const DOM_STATEMENT: &[u8] = b"\x07statement";
#[cfg(feature = "legacy")]
const DOM_LINKAGE: &[u8]   = b"\x08linkage";

// ── transcript ───────────────────────────────────────────────────

/// How a transcript maps hemera output to Goldilocks challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChallengeRule {
    /// Reduce 24 XOF bytes (three output limbs) per challenge limb modulo p.
    Wide,
    /// The 0.4.0 rule: the first 8 bytes of one 32-byte squeeze. Kept only
    /// to read retired artifacts (public v2, state v1) and the legacy path.
    V1FirstLimb,
}

/// Fiat-Shamir transcript: absorb → squeeze → absorb → squeeze …
///
/// After each squeeze the hasher is re-seeded with a chaining value,
/// chaining the state forward. Clone the transcript at any point to
/// branch for parallel sub-protocols.
///
/// Challenge distribution. hemera's output bytes are canonical Goldilocks
/// limbs (each < p, little-endian), so under the sponge-as-random-oracle
/// model one limb is exactly uniform in F_p. The wide rule does not depend
/// on that encoding: each challenge limb is a 192-bit integer
/// (three output limbs) reduced mod p. For a uniform 192-bit input the
/// statistical distance from uniform on F_p is at most p / 2^192 < 2^-128;
/// for canonical-limb output the lowest limb alone is uniform and
/// independent, so the reduction is exactly uniform. Either way the bias
/// per limb is below 2^-128. (The 0.4.0 rule documented a 2^-32 bias under
/// a uniform-bytes model; see `ChallengeRule::V1FirstLimb`.)
#[derive(Clone)]
pub struct Transcript {
    hasher: Hasher,
    rule: ChallengeRule,
}

impl Transcript {
    /// Create a new transcript, domain-separated for zheng proofs, with
    /// wide challenges.
    pub fn new() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(DOM_INIT);
        Self { hasher, rule: ChallengeRule::Wide }
    }

    /// A transcript that reproduces the 0.4.0 challenge rule, for verifying
    /// retired artifacts (direct public v2 / state v1 proofs, the legacy
    /// path) for one release. New proofs use [`Transcript::new`].
    pub fn new_v1() -> Self {
        Self { rule: ChallengeRule::V1FirstLimb, ..Self::new() }
    }

    /// Create a transcript for recursive (inner) proofs. Legacy only;
    /// reproduces the 0.4.0 challenge rule.
    #[cfg(feature = "legacy")]
    pub fn new_recursive() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(DOM_RECURSE);
        Self { hasher, rule: ChallengeRule::V1FirstLimb }
    }

    /// Absorb arbitrary bytes into the transcript.
    pub fn absorb(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Squeeze a 32-byte hash, then re-seed for forward security.
    pub fn squeeze_hash(&mut self) -> [u8; 32] {
        let hash = self.hasher.finalize();
        self.hasher = Hasher::new();
        self.hasher.update(hash.as_bytes());
        *hash.as_bytes()
    }

    /// Squeeze a Goldilocks challenge under this transcript's rule.
    pub fn squeeze_challenge(&mut self) -> Goldilocks {
        match self.rule {
            ChallengeRule::Wide => self.squeeze_limbs::<1>()[0],
            ChallengeRule::V1FirstLimb => {
                let hash = self.squeeze_hash();
                let mut limb = [0u8; 8];
                limb.copy_from_slice(&hash[..8]);
                Goldilocks::new(u64::from_le_bytes(limb)).canonicalize()
            }
        }
    }

    /// Squeeze `n` independent Goldilocks challenges.
    ///
    /// Each challenge re-seeds the hasher, so they are independent.
    pub fn squeeze_challenges(&mut self, n: usize) -> Vec<Goldilocks> {
        (0..n).map(|_| self.squeeze_challenge()).collect()
    }

    /// Squeeze a challenge in the cubic extension Fp3 = F_p[t]/(t³ − t − 1):
    /// three limbs, each drawn by the wide rule (bias < 2^-128 per limb), so
    /// the element is within 3 · 2^-128 of uniform on a set of p³ ≈ 2^192.
    /// Always wide, whatever the transcript's base-field rule.
    pub fn squeeze_fp3(&mut self) -> Fp3 {
        let [c0, c1, c2] = self.squeeze_limbs::<3>();
        Fp3::new(c0, c1, c2)
    }

    /// One XOF read: a 32-byte chaining value, then 24 bytes per limb.
    fn squeeze_limbs<const N: usize>(&mut self) -> [Goldilocks; N] {
        self.hasher.update(DOM_SQUEEZE_WIDE);
        self.hasher.update(&[N as u8]);
        let mut xof = self.hasher.finalize_xof();
        let mut chain = [0u8; 32];
        xof.fill(&mut chain);
        let limbs = core::array::from_fn(|_| {
            let mut wide = [0u8; 24];
            xof.fill(&mut wide);
            reduce_192(&wide)
        });
        self.hasher = Hasher::new();
        self.hasher.update(&chain);
        limbs
    }

    // ── phase absorbers ──────────────────────────────────────────

    /// Absorb a PCS commitment — a hemera Merkle root (domain-separated).
    pub fn absorb_commitment(&mut self, c: &Commitment) {
        self.absorb(DOM_COMMIT);
        self.absorb(c.as_bytes());
    }

    /// Absorb a sumcheck round polynomial (domain-separated).
    /// Goldilocks coefficients encode as 8 bytes, Fp3 as 24 (three limbs).
    pub fn absorb_sumcheck_poly<F: ChallengeField>(&mut self, round: usize, poly: &SumcheckPoly<F>) {
        self.absorb(&[DOM_SUMCHECK]);
        self.absorb(&(round as u64).to_le_bytes());
        self.absorb(&[poly.degree]);
        let mut bytes = Vec::with_capacity(poly.coeffs.len() * 8 * F::LIMBS);
        for &coeff in &poly.coeffs {
            coeff.encode(&mut bytes);
        }
        self.absorb(&bytes);
    }

    /// Absorb the evaluation claim after sumcheck (domain-separated).
    pub fn absorb_eval<F: ChallengeField>(&mut self, v: F) {
        self.absorb(DOM_EVAL);
        let mut bytes = Vec::with_capacity(8 * F::LIMBS);
        v.encode(&mut bytes);
        self.absorb(&bytes);
    }

    /// Absorb a domain separator before the PCS opening phase.
    pub fn absorb_pcs_open_domain(&mut self) {
        self.absorb(DOM_PCS_OPEN);
    }

    /// Absorb a Statement into the transcript (domain-separated).
    ///
    /// Must be called at the same point in both prover and verifier transcripts
    /// to bind the proof to a specific program/input/output identity.
    #[cfg(feature = "legacy")]
    pub fn absorb_statement(&mut self, s: &Statement) {
        self.absorb(DOM_STATEMENT);
        self.absorb(&s.program_hash);
        self.absorb(&s.input_hash);
        self.absorb(&s.output_hash);
        self.absorb(&s.focus_bound.to_le_bytes());
        self.absorb(&s.bbg_root);
    }

    /// Absorb the cross-group linkage digest (domain-separated).
    ///
    /// The digest commits to the witness commitments of every accumulator
    /// group in a TraceProof, binding the groups to each other (option A
    /// linkage of the axis design): a group spliced in from another proof
    /// changes the digest and breaks every group's Fiat-Shamir chain.
    #[cfg(feature = "legacy")]
    pub fn absorb_linkage(&mut self, digest: &[u8; 32]) {
        self.absorb(DOM_LINKAGE);
        self.absorb(digest);
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

/// The integer `b[0..8] + 2^64·b[8..16] + 2^128·b[16..24]` (little-endian
/// limbs) reduced modulo p, exactly.
fn reduce_192(bytes: &[u8; 24]) -> Goldilocks {
    let limb = |i: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        u64::from_le_bytes(b) as u128
    };
    let p = P as u128;
    let mut r = limb(2) % p;
    r = ((r << 64) | limb(1)) % p;
    r = ((r << 64) | limb(0)) % p;
    Goldilocks::new(r as u64)
}

// ── wire encoding ─────────────────────────────────────────────────

/// Encode a Goldilocks element as 8 bytes, little-endian canonical form.
pub fn encode_field(f: Goldilocks) -> [u8; 8] {
    f.as_u64().to_le_bytes()
}

/// Decode 8 bytes as a canonical Goldilocks element.
///
/// Returns None if bytes represent a value >= p (non-canonical).
pub fn decode_field(bytes: &[u8]) -> Option<Goldilocks> {
    let arr: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    let v = u64::from_le_bytes(arr);
    if v >= P {
        return None;
    }
    Some(Goldilocks::new(v))
}

/// Encode n field elements contiguously.
pub fn encode_fields(elems: &[Goldilocks]) -> Vec<u8> {
    let mut out = Vec::with_capacity(elems.len() * 8);
    for &f in elems {
        out.extend_from_slice(&encode_field(f));
    }
    out
}

/// Decode n field elements from a byte slice.
///
/// Returns None if slice length is not a multiple of 8, or any element
/// is non-canonical.
pub fn decode_fields(bytes: &[u8]) -> Option<Vec<Goldilocks>> {
    if !bytes.len().is_multiple_of(8) {
        return None;
    }
    bytes.chunks_exact(8).map(decode_field).collect()
}

/// Encode a SumcheckPoly: 1-byte degree + (degree+1) field elements.
pub fn encode_sumcheck_poly(poly: &SumcheckPoly) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + (poly.degree as usize + 1) * 8);
    out.push(poly.degree);
    for &c in &poly.coeffs {
        out.extend_from_slice(&encode_field(c));
    }
    out
}

/// Decode a SumcheckPoly from a byte slice. Returns (poly, bytes_consumed).
pub fn decode_sumcheck_poly(bytes: &[u8]) -> Option<(SumcheckPoly, usize)> {
    let degree = *bytes.first()?;
    let n = degree as usize + 1;
    let end = 1 + n * 8;
    if bytes.len() < end {
        return None;
    }
    let coeffs = bytes[1..end].chunks_exact(8)
        .map(decode_field)
        .collect::<Option<Vec<_>>>()?;
    Some((SumcheckPoly { degree, coeffs }, end))
}

// ── tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "transcript_tests.rs"]
mod tests;
