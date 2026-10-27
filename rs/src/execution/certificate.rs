//! Public execution certificate, profile v3: the statement plus the free
//! witness positions, checked exactly.
//!
//! The verifier derives the whole relation from the program, places every
//! pinned coordinate itself (z[0] = 1, inputs, outputs, cost), fills the
//! remaining positions in index order from the certificate, pads with zeros,
//! and evaluates every CCS row. Acceptance is deterministic: there is no
//! commitment, no sumcheck and no challenge, so there is nothing to forge
//! except a satisfying assignment of the relation the verifier compiled
//! itself. Soundness rests on the relation compiler alone.
//!
//! Profile v2 (`DirectProof`: Spartan + PublicTensor) disclosed the same
//! witness and checked the same rows; its commitment, Merkle paths and
//! sumcheck added bytes and time and no soundness. v3 removes them.

use super::proof::{DirectError, validate};
use crate::types::{CCSInstance, CCSWitness};
use nebu::Goldilocks;
use nebu::field::P;

/// Identifies profile v3 inside an artifact.
pub const FORMAT: &str = "zheng-nox-public-execution-v3";

/// The witness values at every non-pinned position, in index order, with the
/// trailing zeros of the power-of-two padding removed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Certificate {
    pub free: Vec<u64>,
}

/// Pinned coordinates: z[0] = 1 followed by the strictly increasing public
/// coordinates the execution layer derived from the statement.
fn pins(public: &[(usize, Goldilocks)]) -> Vec<(usize, Goldilocks)> {
    core::iter::once((0, Goldilocks::ONE))
        .chain(public.iter().copied())
        .collect()
}

/// Build a certificate from a satisfying witness. Fails if the witness does
/// not satisfy the relation or disagrees with a pinned coordinate.
pub fn certify(
    instance: &CCSInstance,
    witness: &CCSWitness,
    public: &[(usize, Goldilocks)],
) -> Result<Certificate, DirectError> {
    validate(instance, public)?;
    let pins = pins(public);
    if witness.z.len() != instance.num_cols
        || pins.iter().any(|&(i, v)| witness.z[i] != v)
        || !instance.is_satisfied_by(witness)
    {
        return Err(DirectError::InvalidWitness);
    }
    let mut pinned = pins.iter().map(|&(i, _)| i).peekable();
    let mut free = Vec::with_capacity(instance.num_cols);
    for (i, value) in witness.z.iter().enumerate() {
        if pinned.peek() == Some(&i) {
            pinned.next();
            continue;
        }
        free.push(value.as_u64());
    }
    while free.last() == Some(&0) {
        free.pop();
    }
    Ok(Certificate { free })
}

/// Rebuild the full witness from pins and free values. Rejects noncanonical
/// values and certificates longer than the relation's free positions.
fn assemble(
    instance: &CCSInstance,
    certificate: &Certificate,
    public: &[(usize, Goldilocks)],
) -> Result<CCSWitness, DirectError> {
    let pins = pins(public);
    // Canonical encoding: no trailing zero, no value beyond the last column any
    // row reads (padding columns are zero by construction), every value < p.
    let referenced = instance
        .matrices
        .iter()
        .flat_map(|m| m.entries.iter().flatten())
        .filter(|&&(_, v)| v != Goldilocks::ZERO)
        .map(|&(c, _)| c + 1)
        .max()
        .unwrap_or(0);
    let pinned_below = pins.iter().filter(|&&(i, _)| i < referenced).count();
    let free_positions = referenced.saturating_sub(pinned_below);
    if certificate.free.len() > free_positions
        || certificate.free.last() == Some(&0)
        || certificate.free.iter().any(|&v| v >= P)
    {
        return Err(DirectError::InvalidProof);
    }
    let mut z = vec![Goldilocks::ZERO; instance.num_cols];
    let mut pinned = pins.iter().peekable();
    let mut values = certificate.free.iter();
    for (i, slot) in z.iter_mut().enumerate() {
        if let Some(&&(index, value)) = pinned.peek()
            && index == i
        {
            *slot = value;
            pinned.next();
            continue;
        }
        match values.next() {
            Some(&v) => *slot = Goldilocks::new(v),
            None => break,
        }
    }
    // pins after the last free value still need placing
    for &(index, value) in pinned {
        z[index] = value;
    }
    Ok(CCSWitness { z })
}

/// Verify a certificate against a relation the caller derived itself.
pub fn verify(
    instance: &CCSInstance,
    certificate: &Certificate,
    public: &[(usize, Goldilocks)],
) -> Result<(), DirectError> {
    validate(instance, public)?;
    let witness = assemble(instance, certificate, public)?;
    if !instance.is_satisfied_by(&witness) {
        return Err(DirectError::InvalidProof);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CCSInstance, CCSWitness, SparseMatrix};

    /// x * y = out with x, y free, out pinned public: z = [1, out, x, y]
    /// padded to 64 columns.
    fn product() -> (CCSInstance, Vec<(usize, Goldilocks)>, CCSWitness) {
        let n = 64;
        let m = 1;
        let row = |col: usize| SparseMatrix {
            rows: m,
            cols: n,
            entries: vec![vec![(col, Goldilocks::ONE)]],
        };
        let instance = CCSInstance {
            num_rows: m,
            num_cols: n,
            matrices: vec![row(2), row(3), row(1)],
            multisets: vec![vec![0, 1], vec![2]],
            coeffs: vec![Goldilocks::ONE, -Goldilocks::ONE],
        };
        let mut z = vec![Goldilocks::ZERO; n];
        z[0] = Goldilocks::ONE;
        z[1] = Goldilocks::new(42);
        z[2] = Goldilocks::new(6);
        z[3] = Goldilocks::new(7);
        (instance, vec![(1, Goldilocks::new(42))], CCSWitness { z })
    }

    #[test]
    fn honest_certificate_round_trips_and_trims_padding() {
        let (instance, public, witness) = product();
        let cert = certify(&instance, &witness, &public).unwrap();
        assert_eq!(cert.free, vec![6, 7]);
        verify(&instance, &cert, &public).unwrap();
    }

    #[test]
    fn wrong_public_output_is_rejected() {
        let (instance, _, witness) = product();
        let cert = certify(&instance, &witness, &[(1, Goldilocks::new(42))]).unwrap();
        assert!(verify(&instance, &cert, &[(1, Goldilocks::new(43))]).is_err());
    }

    #[test]
    fn tampered_free_value_is_rejected() {
        let (instance, public, witness) = product();
        let mut cert = certify(&instance, &witness, &public).unwrap();
        cert.free[1] = 8;
        assert!(verify(&instance, &cert, &public).is_err());
    }

    #[test]
    fn every_single_value_flip_is_rejected() {
        let (instance, public, witness) = product();
        let cert = certify(&instance, &witness, &public).unwrap();
        for i in 0..cert.free.len() {
            for delta in [1u64, 2, P - 1] {
                let mut bad = cert.clone();
                bad.free[i] = (bad.free[i] + delta) % P;
                assert!(
                    verify(&instance, &bad, &public).is_err(),
                    "flip {i}+{delta}"
                );
            }
        }
    }

    #[test]
    fn noncanonical_and_overlong_certificates_are_rejected() {
        let (instance, public, witness) = product();
        let cert = certify(&instance, &witness, &public).unwrap();
        let mut trailing_zero = cert.clone();
        trailing_zero.free.push(0);
        assert!(verify(&instance, &trailing_zero, &public).is_err());
        let mut padding = cert.clone();
        padding.free.push(5);
        assert!(verify(&instance, &padding, &public).is_err());
        let mut noncanonical = cert.clone();
        noncanonical.free[0] += P;
        assert!(verify(&instance, &noncanonical, &public).is_err());
        let overlong = Certificate {
            free: vec![0; instance.num_cols],
        };
        assert!(verify(&instance, &overlong, &public).is_err());
    }

    #[test]
    fn zeroed_constant_cannot_be_expressed() {
        // the constant is placed by the verifier; an all-zero certificate
        // still has z[0] = 1 and must satisfy the rows with it
        let (instance, public, _) = product();
        let empty = Certificate { free: vec![] };
        assert!(verify(&instance, &empty, &public).is_err());
    }

    #[test]
    fn unsatisfying_witness_cannot_be_certified() {
        let (instance, public, mut witness) = product();
        witness.z[3] = Goldilocks::new(8);
        assert!(certify(&instance, &witness, &public).is_err());
    }
}

#[cfg(test)]
pub(crate) mod malleability {
    //! Every free witness position must be either constrained (any change is
    //! rejected) or a factor of a product whose other factor is zero in the
    //! honest witness — a "don't care" wire whose value cannot reach any row
    //! result, hence cannot reach a public output.
    use super::super::{ExecutionNoun, certify_execution};
    use nebu::Goldilocks;

    pub(crate) fn parse(text: &str) -> ExecutionNoun {
        fn go(b: &[u8], p: &mut usize) -> ExecutionNoun {
            while b[*p].is_ascii_whitespace() {
                *p += 1;
            }
            if b[*p] == b'[' {
                *p += 1;
                let a = go(b, p);
                let c = go(b, p);
                while b[*p].is_ascii_whitespace() {
                    *p += 1;
                }
                *p += 1;
                ExecutionNoun::Pair(Box::new(a), Box::new(c))
            } else {
                let s = *p;
                while b[*p].is_ascii_digit() {
                    *p += 1;
                }
                ExecutionNoun::Atom(std::str::from_utf8(&b[s..*p]).unwrap().parse().unwrap())
            }
        }
        go(text.as_bytes(), &mut 0)
    }

    const HASH: &str = "[2 [[3 [[4 [[9 [[0 3] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [1 0]]] [1 [15 [3 [[0 2] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [1 0]]]]]]]]]]]]]]]]]]]]]]]]]]]";
    const ADD: &str = "[2 [[3 [[4 [[9 [[0 7] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [3 [[5 [[0 6] [1 0]]] [1 0]]]]] [1 [2 [[3 [[5 [[0 6] [0 2]]] [0 1]]] [1 [7 [[0 2] [0 14]]]]]]]]]]]]]]]";
    const LOOP: &str = "[2 [[3 [[0 2] [0 1]]] [1 [2 [[2 [[3 [[1 0] [0 1]]] [1 [2 [[3 [[0 2] [3 [[2 [[3 [[0 6] [1 0]]] [1 [5 [[0 2] [1 3]]]]]] [0 7]]]]] [1 [3 [[0 6] [3 [[0 14] [0 15]]]]]]]]]]] [1 [2 [[2 [[3 [[1 1] [0 1]]] [1 [2 [[3 [[0 2] [3 [[2 [[3 [[0 6] [1 0]]] [1 [5 [[0 2] [1 3]]]]]] [0 7]]]]] [1 [3 [[0 6] [3 [[0 14] [0 15]]]]]]]]]]] [1 [2 [[2 [[3 [[1 2] [0 1]]] [1 [2 [[3 [[0 2] [3 [[2 [[3 [[0 6] [1 0]]] [1 [5 [[0 2] [1 3]]]]]] [0 7]]]]] [1 [3 [[0 6] [3 [[0 14] [0 15]]]]]]]]]]] [1 [2 [[4 [[9 [[0 2] [1 13]]] [[2 [[3 [[5 [[0 2] [1 100]]] [0 3]]] [1 [0 1]]]] [2 [[3 [[7 [[0 2] [1 2]]] [0 3]]] [1 [0 1]]]]]]] [1 [0 2]]]]]]]]]]]]]]]]";

    /// value of a matrix row applied to z
    fn row_value(m: &crate::types::SparseMatrix, r: usize, z: &[Goldilocks]) -> Goldilocks {
        m.entries[r]
            .iter()
            .fold(Goldilocks::ZERO, |acc, &(c, v)| acc + v * z[c])
    }

    /// Change each free value by one; every change that still verifies must
    /// be a "don't care" wire: each product term reading it has another
    /// factor that is zero in the honest witness. Returns the movable count.
    pub(crate) fn movable_wires_only_multiply_zero(
        name: &str,
        instance: &crate::types::CCSInstance,
        cert: &super::Certificate,
        public: &[(usize, Goldilocks)],
    ) -> usize {
        let z = super::assemble(instance, cert, public).unwrap().z;
        let pins: Vec<usize> = core::iter::once(0).chain(public.iter().map(|p| p.0)).collect();
        let free_index: Vec<usize> = (0..instance.num_cols).filter(|i| !pins.contains(i)).collect();
        let mut movable = 0;
        for (k, &idx) in free_index.iter().enumerate().take(cert.free.len()) {
            let mut bad = cert.clone();
            bad.free[k] = (bad.free[k] + 1) % nebu::field::P;
            if super::verify(instance, &bad, public).is_err() {
                continue;
            }
            movable += 1;
            for r in 0..instance.num_rows {
                for set in &instance.multisets {
                    let reads = set.iter().any(|&mi| {
                        instance.matrices[mi].entries[r]
                            .iter()
                            .any(|&(c, v)| c == idx && v != Goldilocks::ZERO)
                    });
                    if !reads {
                        continue;
                    }
                    let zero_partner = set.iter().any(|&mi| {
                        !instance.matrices[mi].entries[r].iter().any(|&(c, _)| c == idx)
                            && row_value(&instance.matrices[mi], r, &z) == Goldilocks::ZERO
                    });
                    assert!(
                        zero_partner,
                        "{name}: z[{idx}] is movable and reaches row {r} through a nonzero product"
                    );
                }
            }
        }
        movable
    }

    #[test]
    fn every_movable_wire_only_multiplies_zero() {
        for (name, program, inputs) in [
            (
                "hash",
                HASH,
                vec![vec![7u64], vec![0], vec![nebu::field::P - 1]],
            ),
            (
                "add",
                ADD,
                vec![vec![7, 5], vec![0, 0], vec![1, nebu::field::P - 1]],
            ),
            ("loop", LOOP, vec![vec![4], vec![0], vec![10]]),
        ] {
            let program = parse(program);
            for input in inputs {
                let (statement, cert) = certify_execution(&program, &input, 1_000_000).unwrap();
                let relation = statement.relation().unwrap();
                let public = statement.bindings(&relation).unwrap();
                let movable =
                    movable_wires_only_multiply_zero(name, &relation.instance, &cert, &public);
                println!("{name} {input:?}: free {} movable {movable}", cert.free.len());
            }
        }
    }
}
