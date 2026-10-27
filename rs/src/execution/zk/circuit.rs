use super::{MAX_BYTES, PrivateError, REPETITIONS};
use crate::types::CCSInstance;
use hemera::Hasher;
use nebu::Goldilocks as F;

const MAX_DIMENSION: usize = 65_536;
const MAX_ENTRIES: usize = 1_048_576;
const MAX_DEGREE: usize = 16;

#[derive(Clone, Default)]
pub(super) struct Linear {
    pub terms: Vec<(usize, F)>,
    pub constant: F,
}
impl Linear {
    pub fn evaluate(&self, wires: &[F], party: usize) -> F {
        self.terms.iter().fold(
            if party == 0 { self.constant } else { F::ZERO },
            |sum, &(i, coefficient)| sum + coefficient * wires[i],
        )
    }
    fn zero(&self) -> bool {
        self.constant == F::ZERO && self.terms.is_empty()
    }
}

pub(super) struct Circuit {
    pub inputs: usize,
    pub products: Vec<(Linear, Linear)>,
    pub outputs: Vec<Linear>,
    pub digest: [u8; 32],
}

pub(super) fn number(hash: &mut Hasher, n: usize) {
    hash.update(&(n as u64).to_le_bytes());
}
pub(super) fn fields(hash: &mut Hasher, values: &[F]) {
    number(hash, values.len());
    for value in values {
        hash.update(&value.as_u64().to_le_bytes());
    }
}

impl Circuit {
    pub fn new(
        instance: &CCSInstance,
        statement: &[u8],
        public: &[(usize, F)],
    ) -> Result<Self, PrivateError> {
        let (m, n) = (instance.num_rows, instance.num_cols);
        if m == 0
            || n == 0
            || m > MAX_DIMENSION
            || n > MAX_DIMENSION
            || instance.matrices.is_empty()
            || instance.matrices.len() > 64
            || instance.multisets.is_empty()
            || instance.multisets.len() > 64
            || instance.multisets.len() != instance.coeffs.len()
            || m.checked_mul(instance.matrices.len())
                .is_none_or(|v| v > MAX_ENTRIES)
            || statement.len() > 16 * 1024 * 1024
            || public.len() >= n
        {
            return Err(PrivateError::InvalidRelation);
        }
        let mut entries = 0usize;
        for matrix in &instance.matrices {
            if matrix.rows != m || matrix.cols != n || matrix.entries.len() != m {
                return Err(PrivateError::InvalidRelation);
            }
            for row in &matrix.entries {
                entries = entries.checked_add(row.len()).ok_or(PrivateError::Limit)?;
                if entries > MAX_ENTRIES || row.iter().any(|&(i, _)| i >= n) {
                    return Err(PrivateError::InvalidRelation);
                }
            }
        }
        if instance
            .multisets
            .iter()
            .any(|set| set.len() > MAX_DEGREE || set.iter().any(|&i| i >= instance.matrices.len()))
        {
            return Err(PrivateError::InvalidRelation);
        }
        let mut previous = 0;
        for &(i, _) in public {
            if i <= previous || i >= n {
                return Err(PrivateError::InvalidPublicCoordinates);
            }
            previous = i;
        }

        let mut hash = Hasher::new();
        hash.update(b"zheng-ccs-mith-relation-v1");
        number(&mut hash, REPETITIONS);
        number(&mut hash, statement.len());
        hash.update(statement);
        number(&mut hash, m);
        number(&mut hash, n);
        number(&mut hash, instance.matrices.len());
        for matrix in &instance.matrices {
            for row in &matrix.entries {
                number(&mut hash, row.len());
                for &(i, coefficient) in row {
                    number(&mut hash, i);
                    hash.update(&coefficient.as_u64().to_le_bytes());
                }
            }
        }
        number(&mut hash, instance.multisets.len());
        for (set, coefficient) in instance.multisets.iter().zip(&instance.coeffs) {
            number(&mut hash, set.len());
            for &i in set {
                number(&mut hash, i);
            }
            hash.update(&coefficient.as_u64().to_le_bytes());
        }
        number(&mut hash, public.len());
        for &(i, value) in public {
            number(&mut hash, i);
            hash.update(&value.as_u64().to_le_bytes());
        }
        let mut circuit = Self {
            inputs: n,
            products: Vec::new(),
            outputs: Vec::new(),
            digest: *hash.finalize().as_bytes(),
        };
        let mut work = 0usize;
        for r in 0..m {
            let mut residual = Linear::default();
            for (set, &coefficient) in instance.multisets.iter().zip(&instance.coeffs) {
                if coefficient == F::ZERO {
                    continue;
                }
                let rows: Vec<_> = set
                    .iter()
                    .map(|&i| &instance.matrices[i].entries[r])
                    .collect();
                if rows
                    .iter()
                    .any(|row| row.iter().all(|(_, c)| *c == F::ZERO))
                {
                    continue;
                }
                // Bound expanded sparse work before copying any repeated factor.
                for row in &rows {
                    work = work.checked_add(row.len()).ok_or(PrivateError::Limit)?;
                }
                if work > MAX_ENTRIES {
                    return Err(PrivateError::Limit);
                }
                let factors: Vec<_> = rows
                    .into_iter()
                    .map(|row| Linear {
                        terms: row.iter().copied().filter(|(_, c)| *c != F::ZERO).collect(),
                        constant: F::ZERO,
                    })
                    .collect();
                let mut factors = factors.into_iter();
                let mut term = factors.next().unwrap_or(Linear {
                    constant: F::ONE,
                    terms: Vec::new(),
                });
                for factor in factors {
                    if circuit.products.len() == MAX_DIMENSION {
                        return Err(PrivateError::Limit);
                    }
                    let wire = n + circuit.products.len();
                    circuit.products.push((term, factor));
                    term = Linear {
                        terms: vec![(wire, F::ONE)],
                        constant: F::ZERO,
                    };
                }
                residual.constant += coefficient * term.constant;
                residual
                    .terms
                    .extend(term.terms.into_iter().map(|(i, c)| (i, coefficient * c)));
            }
            if !residual.zero() {
                circuit.outputs.push(residual);
            }
        }
        for (i, value) in core::iter::once((0, F::ONE)).chain(public.iter().copied()) {
            circuit.outputs.push(Linear {
                terms: vec![(i, F::ONE)],
                constant: -value,
            });
        }
        if circuit.max_proof_bytes()? > MAX_BYTES {
            return Err(PrivateError::Limit);
        }
        Ok(circuit)
    }

    pub fn max_proof_bytes(&self) -> Result<usize, PrivateError> {
        self.inputs
            .checked_add(self.products.len())
            .and_then(|v| v.checked_add(self.outputs.len()))
            .and_then(|v| v.checked_mul(8))
            .and_then(|v| v.checked_add(97)) // challenge, commitment, two seeds
            .and_then(|v| v.checked_mul(REPETITIONS))
            .and_then(|v| v.checked_add(20))
            .ok_or(PrivateError::Limit)
    }

    pub fn outputs(&self, wires: &[F], party: usize) -> Vec<F> {
        self.outputs
            .iter()
            .map(|o| o.evaluate(wires, party))
            .collect()
    }

    pub fn satisfied(&self, witness: &[F]) -> bool {
        if witness.len() != self.inputs {
            return false;
        }
        let mut wires = Vec::with_capacity(self.inputs + self.products.len());
        wires.extend_from_slice(witness);
        for (a, b) in &self.products {
            wires.push(a.evaluate(&wires, 0) * b.evaluate(&wires, 0));
        }
        let satisfied = self
            .outputs
            .iter()
            .all(|o| o.evaluate(&wires, 0) == F::ZERO);
        super::views::clear_fields(&mut wires);
        satisfied
    }
}
