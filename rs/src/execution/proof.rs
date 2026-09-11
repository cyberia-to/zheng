//! Direct, zero-error CCS proofs with a verifier-pinned public witness prefix.
//!
//! The caller derives the relation and coordinates from the public execution
//! statement. No relation, error vector, or witness is accepted from a proof.
//! PublicTensor and this IOP disclose witness-dependent information: callers must
//! use public executions only. Full authenticated table validation checks the
//! exact CCS relation in addition to the Spartan consistency transcript.

use super::public;
use crate::{
    spartan::{prover::SpartanProver, verifier::SpartanVerifier},
    transcript::Transcript,
    types::{CCSInstance, CCSWitness, Proof, SumcheckPoly},
};
use core::fmt;
use lens::brakedown::PublicTensor;
use nebu::Goldilocks;

const MAX_DIMENSION: usize = 1 << 20;
const MAX_TERMS: usize = 1 << 20;
const MAX_DEGREE: usize = 16;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DirectProof {
    pub spartan: Proof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectError {
    InvalidRelation,
    InvalidPublicCoordinates,
    InvalidWitness,
    InvalidProof,
}
impl fmt::Display for DirectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "direct execution proof: {self:?}")
    }
}
impl std::error::Error for DirectError {}

fn validate(instance: &CCSInstance, public: &[(usize, Goldilocks)]) -> Result<usize, DirectError> {
    let (m, n) = (instance.num_rows, instance.num_cols);
    if !m.is_power_of_two()
        || !n.is_power_of_two()
        || n < 64
        || m > MAX_DIMENSION
        || n > MAX_DIMENSION
        || instance.matrices.is_empty()
        || instance.matrices.len() > MAX_TERMS
        || instance.multisets.is_empty()
        || instance.multisets.len() > MAX_TERMS
        || instance.multisets.len() != instance.coeffs.len()
    {
        return Err(DirectError::InvalidRelation);
    }
    let mut entries = 0usize;
    for matrix in &instance.matrices {
        if matrix.rows != m || matrix.cols != n || matrix.entries.len() != m {
            return Err(DirectError::InvalidRelation);
        }
        for row in &matrix.entries {
            entries = entries
                .checked_add(row.len())
                .ok_or(DirectError::InvalidRelation)?;
            if entries > MAX_TERMS || row.iter().any(|&(col, _)| col >= n) {
                return Err(DirectError::InvalidRelation);
            }
        }
    }
    let degree = instance.multisets.iter().map(Vec::len).max().unwrap_or(0);
    if degree > MAX_DEGREE
        || instance
            .multisets
            .iter()
            .flatten()
            .any(|&i| i >= instance.matrices.len())
    {
        return Err(DirectError::InvalidRelation);
    }
    let mut previous = 0;
    for &(index, _) in public {
        if index <= previous || index >= n {
            return Err(DirectError::InvalidPublicCoordinates);
        }
        previous = index;
    }
    Ok(degree + 1)
}

fn transcript(
    instance: &CCSInstance,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
) -> Transcript {
    let mut t = Transcript::new();
    t.absorb(b"zheng-direct-ccs-public-full-columns-v1");
    fn number(t: &mut Transcript, n: usize) {
        t.absorb(&(n as u64).to_le_bytes());
    }
    number(&mut t, statement.len());
    t.absorb(statement);
    number(&mut t, instance.num_rows);
    number(&mut t, instance.num_cols);
    number(&mut t, instance.matrices.len());
    for matrix in &instance.matrices {
        for row in &matrix.entries {
            number(&mut t, row.len());
            for &(column, coefficient) in row {
                number(&mut t, column);
                t.absorb_eval(coefficient);
            }
        }
    }
    number(&mut t, instance.multisets.len());
    for (set, &coefficient) in instance.multisets.iter().zip(&instance.coeffs) {
        number(&mut t, set.len());
        for &matrix in set {
            number(&mut t, matrix);
        }
        t.absorb_eval(coefficient);
    }
    number(&mut t, public.len());
    for &(index, value) in public {
        number(&mut t, index);
        t.absorb_eval(value);
    }
    t
}

fn coordinates(public: &[(usize, Goldilocks)]) -> Vec<(usize, Goldilocks)> {
    core::iter::once((0, Goldilocks::ONE))
        .chain(public.iter().copied())
        .collect()
}

/// Prove a caller-derived relation. Witness data must be permitted to be public.
/// Public coordinates are strictly increasing and exclude the mandatory z[0]=1.
pub fn prove(
    instance: &CCSInstance,
    witness: &CCSWitness,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
) -> Result<DirectProof, DirectError> {
    validate(instance, public)?;
    let coordinates = coordinates(public);
    if witness.z.len() != instance.num_cols
        || coordinates.iter().any(|&(i, v)| witness.z[i] != v)
        || !instance.is_satisfied_by(witness)
    {
        return Err(DirectError::InvalidWitness);
    }
    let mut transcript = transcript(instance, statement, public);
    let spartan = SpartanProver::prove_using::<PublicTensor>(instance, witness, &mut transcript);
    Ok(DirectProof { spartan })
}

fn valid_polynomials(polys: &[SumcheckPoly], rounds: usize, degree: usize) -> bool {
    polys.len() == rounds
        && polys
            .iter()
            .all(|p| p.degree as usize == degree && p.coeffs.len() == degree + 1)
}

/// Verify zero-error satisfaction plus constant and public coordinates under the
/// same commitment. The execution layer must independently derive `instance`.
pub fn verify(
    instance: &CCSInstance,
    proof: &DirectProof,
    statement: &[u8],
    public: &[(usize, Goldilocks)],
) -> Result<(), DirectError> {
    let degree = validate(instance, public)?;
    let variables = instance.num_cols.trailing_zeros() as usize;
    if !valid_polynomials(
        &proof.spartan.outer_sumcheck_polys,
        instance.num_rows.trailing_zeros() as usize,
        degree,
    ) || !valid_polynomials(&proof.spartan.sumcheck_polys, variables, 2)
        || !public::canonical(&proof.spartan.pcs_opening, variables)
    {
        return Err(DirectError::InvalidProof);
    }
    let mut transcript = transcript(instance, statement, public);
    let zero_error = vec![Goldilocks::ZERO; instance.num_rows];
    SpartanVerifier::verify_using::<PublicTensor>(
        instance,
        &proof.spartan,
        &zero_error,
        &mut transcript,
    )
    .map_err(|_| DirectError::InvalidProof)?;
    // The public PCS reveals the complete authenticated table. Check the
    // actual constraints and coordinates exactly; no small-field sumcheck
    // soundness assumption is needed for accepting the execution relation.
    let z = PublicTensor::authenticated_evaluations(
        &proof.spartan.commitment,
        variables,
        &proof.spartan.pcs_opening,
    )
    .ok_or(DirectError::InvalidProof)?;
    if coordinates(public)
        .iter()
        .any(|&(i, v)| z.get(i) != Some(&v))
        || !instance.is_satisfied_by(&CCSWitness { z })
    {
        return Err(DirectError::InvalidProof);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SparseMatrix;

    fn relation() -> (CCSInstance, CCSWitness, Vec<(usize, Goldilocks)>) {
        // The public output z[3] must equal public input z[1] times z[2].
        let mut a = SparseMatrix::new(4, 64);
        let mut b = a.clone();
        let mut c = a.clone();
        a.set(0, 1, Goldilocks::ONE);
        b.set(0, 2, Goldilocks::ONE);
        c.set(0, 3, Goldilocks::ONE);
        // Enforce z[2]=7 using the mandatory constant column.
        a.set(1, 2, Goldilocks::ONE);
        b.set(1, 0, Goldilocks::ONE);
        c.set(1, 0, Goldilocks::new(7));
        let instance = CCSInstance {
            matrices: vec![a, b, c],
            multisets: vec![vec![0, 1], vec![2]],
            coeffs: vec![Goldilocks::ONE, -Goldilocks::ONE],
            num_rows: 4,
            num_cols: 64,
        };
        let mut z = vec![Goldilocks::ZERO; 64];
        for (i, v) in [1, 6, 7, 42].into_iter().enumerate() {
            z[i] = Goldilocks::new(v);
        }
        (
            instance,
            CCSWitness { z },
            vec![(1, Goldilocks::new(6)), (3, Goldilocks::new(42))],
        )
    }

    #[test]
    fn binds_public_values_relation_and_statement() {
        let (instance, witness, public) = relation();
        let proof = prove(&instance, &witness, b"program-one", &public).unwrap();
        verify(&instance, &proof, b"program-one", &public).unwrap();
        assert!(verify(&instance, &proof, b"program-two", &public).is_err());
        for i in 0..public.len() {
            let mut changed = public.clone();
            changed[i].1 += Goldilocks::ONE;
            assert!(verify(&instance, &proof, b"program-one", &changed).is_err());
        }
        let mut changed = instance.clone();
        changed.coeffs[1] = Goldilocks::ONE;
        assert!(verify(&changed, &proof, b"program-one", &public).is_err());
    }

    #[test]
    fn verifier_rejects_unsatisfying_witness_without_prover_gate() {
        let (instance, mut witness, public) = relation();
        witness.z[2] = Goldilocks::new(8);
        let mut t = transcript(&instance, b"statement", &public);
        let spartan = SpartanProver::prove_using::<PublicTensor>(&instance, &witness, &mut t);
        let forged = DirectProof { spartan };
        assert!(verify(&instance, &forged, b"statement", &public).is_err());
    }

    #[test]
    fn verifier_pins_constant_even_when_zero_witness_satisfies_ccs() {
        let (instance, _, _) = relation();
        let witness = CCSWitness {
            z: vec![Goldilocks::ZERO; 64],
        };
        assert!(instance.is_satisfied_by(&witness));
        let mut t = transcript(&instance, b"statement", &[]);
        let spartan = SpartanProver::prove_using::<PublicTensor>(&instance, &witness, &mut t);
        let forged = DirectProof { spartan };
        assert!(verify(&instance, &forged, b"statement", &[]).is_err());
    }

    #[test]
    fn rejects_proof_shape_and_noncanonical_openings() {
        let (instance, witness, public) = relation();
        let proof = prove(&instance, &witness, b"statement", &public).unwrap();
        let mut wrong = proof.clone();
        wrong.spartan.sumcheck_polys.pop();
        assert!(verify(&instance, &wrong, b"statement", &public).is_err());
        let mut wrong = proof.clone();
        wrong.spartan.sumcheck_polys[0].degree = 3;
        wrong.spartan.sumcheck_polys[0]
            .coeffs
            .push(Goldilocks::ZERO);
        assert!(verify(&instance, &wrong, b"statement", &public).is_err());
        let mut wrong = proof.clone();
        if let lens::Opening::TensorMerkle { columns, .. } = &mut wrong.spartan.pcs_opening {
            columns.swap(0, 1);
        }
        assert!(verify(&instance, &wrong, b"statement", &public).is_err());
        let mut wrong = proof.clone();
        if let lens::Opening::TensorMerkle { columns, .. } = &mut wrong.spartan.pcs_opening {
            columns[0].column.push(0);
        }
        assert!(verify(&instance, &wrong, b"statement", &public).is_err());
        let mut wrong = proof;
        if let lens::Opening::TensorMerkle {
            row_combination, ..
        } = &mut wrong.spartan.pcs_opening
        {
            row_combination[..8].copy_from_slice(&nebu::field::P.to_le_bytes());
        }
        assert!(verify(&instance, &wrong, b"statement", &public).is_err());
    }

    #[test]
    fn rejects_invalid_relation_dimensions_and_public_indices() {
        let (mut instance, witness, public) = relation();
        assert!(prove(&instance, &witness, b"", &[(0, Goldilocks::ONE)]).is_err());
        assert!(
            prove(
                &instance,
                &witness,
                b"",
                &[(1, Goldilocks::ONE), (1, Goldilocks::ONE)]
            )
            .is_err()
        );
        instance.num_cols = 63;
        assert!(prove(&instance, &witness, b"", &public).is_err());
        instance.num_cols = 64;
        instance.matrices[0].entries[0][0].0 = 64;
        assert!(prove(&instance, &witness, b"", &public).is_err());
    }
}
