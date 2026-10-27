//! Transcript tests: determinism, domain separation, wire codecs and the
//! wide / v1 / Fp3 challenge rules.
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

#[cfg(feature = "legacy")]
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

#[test]
fn v1_rule_reproduces_the_first_limb_of_one_squeeze() {
    let mut a = Transcript::new_v1();
    a.absorb(b"compat");
    let mut b = a.clone();
    let hash = b.squeeze_hash();
    let mut limb = [0u8; 8];
    limb.copy_from_slice(&hash[..8]);
    assert_eq!(a.squeeze_challenge().as_u64(), u64::from_le_bytes(limb));
    let mut wide = Transcript::new();
    wide.absorb(b"compat");
    let mut v1 = Transcript::new_v1();
    v1.absorb(b"compat");
    assert_ne!(wide.squeeze_challenge(), v1.squeeze_challenge());
}

#[test]
fn reduce_192_is_the_integer_modulo_p() {
    let shift = Goldilocks::new(1 << 32) * Goldilocks::new(1 << 32); // 2^64 mod p
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let edge = [0, 1, P - 1, P, P + 1, u64::MAX];
    for i in 0..2000 {
        let limbs = if i < 216 {
            [edge[i % 6], edge[(i / 6) % 6], edge[(i / 36) % 6]]
        } else {
            [next(), next(), next()]
        };
        let mut bytes = [0u8; 24];
        for (k, l) in limbs.iter().enumerate() {
            bytes[8 * k..8 * k + 8].copy_from_slice(&l.to_le_bytes());
        }
        let expect = Goldilocks::new(limbs[0]).canonicalize()
            + Goldilocks::new(limbs[1]).canonicalize() * shift
            + Goldilocks::new(limbs[2]).canonicalize() * shift * shift;
        let got = reduce_192(&bytes);
        assert!(got.as_u64() < P);
        assert_eq!(got, expect, "{limbs:?}");
    }
    // the documented bias bound p / 2^192 < 2^-128 needs only p < 2^64
    assert!((P as u128) < 1u128 << 64);
}

#[test]
fn hemera_output_limbs_are_canonical() {
    let mut h = Hasher::new();
    h.update(b"limb-encoding");
    let mut xof = h.finalize_xof();
    for _ in 0..4096 {
        let mut limb = [0u8; 8];
        xof.fill(&mut limb);
        assert!(u64::from_le_bytes(limb) < P);
    }
}

#[test]
fn fp3_challenges_are_deterministic_chained_and_extension_valued() {
    let mut a = Transcript::new();
    a.absorb(b"fp3");
    let mut b = a.clone();
    let x = a.squeeze_fp3();
    assert_eq!(x, b.squeeze_fp3());
    let y = a.squeeze_fp3();
    assert_ne!(x, y);
    assert!(x.c1 != Goldilocks::ZERO || x.c2 != Goldilocks::ZERO);
    // the v1 base rule does not change the extension squeeze
    let mut c = Transcript::new_v1();
    c.absorb(b"fp3");
    assert_eq!(c.squeeze_fp3(), x);
}
