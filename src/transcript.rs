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

use hemera::Hasher;
use nebu::{field::P, Goldilocks};

use lens::Commitment;

use crate::types::{Statement, SumcheckPoly};

// ── domain separators ─────────────────────────────────────────────
// absorbed before the corresponding phase message. unique per phase.

const DOM_INIT: &[u8]      = b"\x01zheng-transcript-v1";
const DOM_COMMIT: &[u8]    = b"\x02commit";
const DOM_SUMCHECK: u8     = 0x03;
const DOM_EVAL: &[u8]      = b"\x04eval";
const DOM_PCS_OPEN: &[u8]  = b"\x05pcs-open";
const DOM_RECURSE: &[u8]   = b"\x06recurse";
const DOM_STATEMENT: &[u8] = b"\x07statement";

// ── transcript ───────────────────────────────────────────────────

/// Fiat-Shamir transcript: absorb → squeeze → absorb → squeeze …
///
/// After each squeeze the hasher is re-seeded with the output hash,
/// chaining the state forward. Clone the transcript at any point to
/// branch for parallel sub-protocols.
#[derive(Clone)]
pub struct Transcript {
    hasher: Hasher,
}

impl Transcript {
    /// Create a new transcript, domain-separated for zheng proofs.
    pub fn new() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(DOM_INIT);
        Self { hasher }
    }

    /// Create a transcript for recursive (inner) proofs.
    pub fn new_recursive() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(DOM_RECURSE);
        Self { hasher }
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

    /// Squeeze a Goldilocks challenge.
    ///
    /// Takes the first 8 bytes of the hash as a little-endian u64 and
    /// canonicalizes into [0, p). Bias is (2^64 - p) / 2^64 ≈ 2^-32 —
    /// negligible at 128-bit security.
    pub fn squeeze_challenge(&mut self) -> Goldilocks {
        let hash = self.squeeze_hash();
        let raw = u64::from_le_bytes(hash[..8].try_into().unwrap());
        Goldilocks::new(raw).canonicalize()
    }

    /// Squeeze `n` independent Goldilocks challenges.
    ///
    /// Each challenge re-seeds the hasher, so they are independent.
    pub fn squeeze_challenges(&mut self, n: usize) -> Vec<Goldilocks> {
        (0..n).map(|_| self.squeeze_challenge()).collect()
    }

    // ── phase absorbers ──────────────────────────────────────────

    /// Absorb a Brakedown commitment (domain-separated).
    pub fn absorb_commitment(&mut self, c: &Commitment) {
        self.absorb(DOM_COMMIT);
        self.absorb(c.as_bytes());
    }

    /// Absorb a sumcheck round polynomial (domain-separated).
    pub fn absorb_sumcheck_poly(&mut self, round: usize, poly: &SumcheckPoly) {
        self.absorb(&[DOM_SUMCHECK]);
        self.absorb(&round.to_le_bytes());
        self.absorb(&[poly.degree]);
        for coeff in &poly.coeffs {
            self.absorb(&encode_field(*coeff));
        }
    }

    /// Absorb the evaluation claim after sumcheck (domain-separated).
    pub fn absorb_eval(&mut self, v: Goldilocks) {
        self.absorb(DOM_EVAL);
        self.absorb(&encode_field(v));
    }

    /// Absorb a domain separator before the PCS opening phase.
    pub fn absorb_pcs_open_domain(&mut self) {
        self.absorb(DOM_PCS_OPEN);
    }

    /// Absorb a Statement into the transcript (domain-separated).
    ///
    /// Must be called at the same point in both prover and verifier transcripts
    /// to bind the proof to a specific program/input/output identity.
    pub fn absorb_statement(&mut self, s: &Statement) {
        self.absorb(DOM_STATEMENT);
        self.absorb(&s.program_hash);
        self.absorb(&s.input_hash);
        self.absorb(&s.output_hash);
        self.absorb(&s.focus_bound.to_le_bytes());
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
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
    if bytes.len() % 8 != 0 {
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
mod tests {
    use super::*;

    #[test]
    fn same_messages_same_challenge() {
        let mut t1 = Transcript::new();
        t1.absorb(b"hello");
        let c1 = t1.squeeze_challenge();

        let mut t2 = Transcript::new();
        t2.absorb(b"hello");
        let c2 = t2.squeeze_challenge();

        assert_eq!(c1.as_u64(), c2.as_u64());
    }

    #[test]
    fn different_messages_different_challenges() {
        let mut t1 = Transcript::new();
        t1.absorb(b"hello");
        let c1 = t1.squeeze_challenge();

        let mut t2 = Transcript::new();
        t2.absorb(b"world");
        let c2 = t2.squeeze_challenge();

        assert_ne!(c1.as_u64(), c2.as_u64());
    }

    #[test]
    fn different_domains_different_challenges() {
        let mut t1 = Transcript::new();
        t1.absorb(b"same");
        let c1 = t1.squeeze_challenge();

        let mut t2 = Transcript::new_recursive();
        t2.absorb(b"same");
        let c2 = t2.squeeze_challenge();

        assert_ne!(c1.as_u64(), c2.as_u64());
    }

    #[test]
    fn multiple_squeezes_are_independent() {
        let mut t = Transcript::new();
        t.absorb(b"test");
        let c1 = t.squeeze_challenge();
        let c2 = t.squeeze_challenge();
        assert_ne!(c1.as_u64(), c2.as_u64());
    }

    #[test]
    fn encode_decode_field_roundtrip() {
        let f = Goldilocks::new(12345678);
        let bytes = encode_field(f);
        let decoded = decode_field(&bytes).unwrap();
        assert_eq!(f.as_u64(), decoded.as_u64());
    }

    #[test]
    fn decode_field_rejects_noncanonical() {
        // P = 0xFFFF_FFFF_0000_0001 is non-canonical (>= p)
        let bytes = P.to_le_bytes();
        assert!(decode_field(&bytes).is_none());

        // P + 1 is also non-canonical
        let bytes2 = (P + 1).to_le_bytes();
        assert!(decode_field(&bytes2).is_none());
    }

    #[test]
    fn decode_field_accepts_p_minus_1() {
        let bytes = (P - 1).to_le_bytes();
        let f = decode_field(&bytes).unwrap();
        assert_eq!(f.as_u64(), P - 1);
    }

    #[test]
    fn encode_decode_fields_roundtrip() {
        let elems: Vec<Goldilocks> = (0u64..8).map(Goldilocks::new).collect();
        let bytes = encode_fields(&elems);
        let decoded = decode_fields(&bytes).unwrap();
        for (a, b) in elems.iter().zip(decoded.iter()) {
            assert_eq!(a.as_u64(), b.as_u64());
        }
    }

    #[test]
    fn decode_fields_rejects_odd_length() {
        assert!(decode_fields(&[0u8; 7]).is_none());
        assert!(decode_fields(&[0u8; 9]).is_none());
    }

    #[test]
    fn sumcheck_poly_encode_decode_roundtrip() {
        let poly = SumcheckPoly {
            degree: 3,
            coeffs: vec![
                Goldilocks::new(1),
                Goldilocks::new(2),
                Goldilocks::new(3),
                Goldilocks::new(4),
            ],
        };
        let bytes = encode_sumcheck_poly(&poly);
        let (decoded, consumed) = decode_sumcheck_poly(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.degree, poly.degree);
        for (a, b) in poly.coeffs.iter().zip(decoded.coeffs.iter()) {
            assert_eq!(a.as_u64(), b.as_u64());
        }
    }

    #[test]
    fn commitment_domain_separation() {
        use lens::{brakedown::Brakedown, Lens, MultilinearPoly};

        // build a real commitment via lens so both sides use the same hemera version
        let poly = MultilinearPoly::new(vec![
            Goldilocks::new(1), Goldilocks::new(2),
            Goldilocks::new(3), Goldilocks::new(4),
        ]);
        let c = Brakedown::commit(&poly);

        let mut t1 = Transcript::new();
        t1.absorb_commitment(&c);
        let ch1 = t1.squeeze_challenge();

        // same bytes, no domain separator
        let mut t2 = Transcript::new();
        t2.absorb(c.as_bytes());
        let ch2 = t2.squeeze_challenge();

        assert_ne!(ch1.as_u64(), ch2.as_u64());
    }
}
