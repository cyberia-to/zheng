//! The commitment schemes the succinct profile can carry, and the policy a
//! verifier applies to the parameters a proof names.
//!
//! Every scheme is a [`lens::MultilinearPcs`] over Goldilocks opened at an
//! Fp3 point. On the wire a scheme is one id byte followed by its fixed-size
//! parameter header; the opening proof follows without repeating that
//! header (lens proofs start with it; the codec strips it on write and puts
//! it back on read, so the bytes the verifier checks are the bytes lens
//! defines).
//!
//! Policy: a proof is admitted only if the verifier itself computes
//! `security_bits(params, num_vars) ≥ 128` (proven round-by-round bound,
//! grinding included — lens never counts a conjecture), the parameters ask
//! for a target of at least 128 bits, and every parameter lies in the range
//! below (so a hostile header cannot make the verifier allocate or loop
//! without bound).

use lens::{MultilinearPcs, PcsError, TensorRs, TensorRsParams, Whir, WhirParams};
#[cfg(test)]
use lens::rspcs::whir::Decoding;

/// Bits a succinct proof must carry: proven, never conjectured.
pub const MIN_SECURITY_BITS: f64 = 128.0;

/// A multilinear PCS the succinct profile can name on the wire.
pub trait SuccinctPcs: MultilinearPcs<Params: Copy + Eq, Proof: Eq> + Clone + core::fmt::Debug {
    /// Wire id (0 is never used).
    const ID: u8;
    /// Bytes of the parameter header.
    const HEADER: usize;
    fn header(params: &Self::Params) -> Vec<u8>;
    fn params_from_header(bytes: &[u8]) -> Result<Self::Params, PcsError>;
    /// The opening proof's bytes after its parameter header.
    fn proof_body(proof: &Self::Proof) -> Vec<u8>;
    /// Parse a proof body written under `params`; canonical, exact.
    fn proof_from_body(params: &Self::Params, body: &[u8]) -> Result<Self::Proof, PcsError>;
    /// Parameters inside the ranges the verifier will run.
    fn in_range(params: &Self::Params) -> bool;
}

/// Admit `params` for a witness of `num_vars` variables, or say why not.
pub fn admit<P: SuccinctPcs>(params: &P::Params, num_vars: usize) -> Result<f64, String> {
    if !P::in_range(params) {
        return Err(format!("{}: parameters outside the verifier's range", P::NAME));
    }
    let bits = P::security_bits(params, num_vars);
    if bits < MIN_SECURITY_BITS {
        return Err(format!(
            "{}: {bits:.2} proven bits at 2^{num_vars}, policy requires {MIN_SECURITY_BITS}",
            P::NAME
        ));
    }
    Ok(bits)
}

fn with_header(header: Vec<u8>, body: &[u8]) -> Vec<u8> {
    let mut bytes = header;
    bytes.extend_from_slice(body);
    bytes
}

impl SuccinctPcs for Whir {
    const ID: u8 = 1;
    const HEADER: usize = 8;
    fn header(params: &WhirParams) -> Vec<u8> {
        params.header().to_vec()
    }
    fn params_from_header(bytes: &[u8]) -> Result<WhirParams, PcsError> {
        let h: [u8; 8] = bytes.try_into().map_err(|_| PcsError::Malformed)?;
        let params = WhirParams::from_header(h)?;
        // one encoding per value: the header must round-trip
        if params.header() != h {
            return Err(PcsError::Malformed);
        }
        Ok(params)
    }
    fn proof_body(proof: &Self::Proof) -> Vec<u8> {
        proof.to_bytes()[Self::HEADER..].to_vec()
    }
    fn proof_from_body(params: &WhirParams, body: &[u8]) -> Result<Self::Proof, PcsError> {
        lens::rspcs::WhirProof::from_bytes(&with_header(Self::header(params), body))
    }
    fn in_range(p: &WhirParams) -> bool {
        (1..=6).contains(&p.log_inv_rate)
            && (1..=6).contains(&p.folding_factor)
            && p.pow_bits <= 32
            && (128..=256).contains(&p.security_target)
            && p.max_final_vars <= 16
    }
}

impl SuccinctPcs for TensorRs {
    const ID: u8 = 2;
    const HEADER: usize = 6;
    fn header(params: &TensorRsParams) -> Vec<u8> {
        params.header().to_vec()
    }
    fn params_from_header(bytes: &[u8]) -> Result<TensorRsParams, PcsError> {
        let h: [u8; 6] = bytes.try_into().map_err(|_| PcsError::Malformed)?;
        let params = TensorRsParams::from_header(h)?;
        if params.header() != h {
            return Err(PcsError::Malformed);
        }
        Ok(params)
    }
    fn proof_body(proof: &Self::Proof) -> Vec<u8> {
        proof.to_bytes()[Self::HEADER..].to_vec()
    }
    fn proof_from_body(params: &TensorRsParams, body: &[u8]) -> Result<Self::Proof, PcsError> {
        lens::rspcs::TensorRsProof::from_bytes(&with_header(Self::header(params), body))
    }
    fn in_range(p: &TensorRsParams) -> bool {
        (1..=6).contains(&p.log_inv_rate)
            && p.pow_bits <= 32
            && (128..=256).contains(&p.security_target)
            && p.row_vars.is_none_or(|r| r <= 30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_admitted_and_weak_parameters_are_not() {
        assert!(admit::<Whir>(&WhirParams::default(), 10).unwrap() >= 128.0);
        assert!(admit::<TensorRs>(&TensorRsParams::default(), 10).unwrap() >= 128.0);
        let weak = WhirParams {
            security_target: 100,
            ..WhirParams::default()
        };
        assert!(admit::<Whir>(&weak, 10).is_err());
        let unique = WhirParams {
            decoding: Decoding::Unique,
            ..WhirParams::default()
        };
        assert!(admit::<Whir>(&unique, 10).unwrap() >= 128.0, "unique decoding is proven too");
        let deep = WhirParams {
            folding_factor: 9,
            ..WhirParams::default()
        };
        assert!(admit::<Whir>(&deep, 10).is_err(), "outside the policy range");
        let wide = TensorRsParams {
            log_inv_rate: 9,
            ..TensorRsParams::default()
        };
        assert!(admit::<TensorRs>(&wide, 10).is_err());
    }

    #[test]
    fn headers_round_trip_and_reject_other_encodings() {
        let p = WhirParams::default();
        assert_eq!(Whir::params_from_header(&Whir::header(&p)).unwrap(), p);
        let mut h = Whir::header(&p);
        h[0] ^= 1;
        assert!(Whir::params_from_header(&h).is_err());
        let t = TensorRsParams::default();
        assert_eq!(TensorRs::params_from_header(&TensorRs::header(&t)).unwrap(), t);
        assert!(TensorRs::params_from_header(&[1, 2, 3]).is_err());
    }
}
