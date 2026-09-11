//! Symbolic nox structural hashing. Every sponge lane is a constrained wire;
//! native Hemera functions below derive only public linear-layer coefficients.
use super::*;
use hemera::field::Goldilocks as H;
use std::sync::OnceLock;

type State = [Value; 16];
fn zero_state() -> State {
    core::array::from_fn(|_| Value::Constant(F::ZERO))
}

fn mds() -> &'static [[F; 16]; 16] {
    static MATRIX: OnceLock<[[F; 16]; 16]> = OnceLock::new();
    MATRIX.get_or_init(|| {
        let mut matrix = [[F::ZERO; 16]; 16];
        for column in 0..16 {
            let mut basis = [H::ZERO; 16];
            basis[column] = H::new(1);
            hemera::field::mds_light_permutation(&mut basis);
            for row in 0..16 {
                matrix[row][column] = F::new(basis[row].as_canonical_u64());
            }
        }
        matrix
    })
}

impl Builder {
    fn hash_mds(&mut self, state: &State, internal: bool) -> Result<State, RelationError> {
        let mut out = zero_state();
        for row in 0..16 {
            let mut terms = vec![];
            for column in 0..16 {
                let coefficient = if internal {
                    F::ONE
                        + if row == column {
                            F::new(hemera::field::MATRIX_DIAG_16[row].as_canonical_u64())
                        } else {
                            F::ZERO
                        }
                } else {
                    mds()[row][column]
                };
                terms.extend(
                    self.linear(&state[column])?
                        .into_iter()
                        .map(|(i, c)| (i, c * coefficient)),
                );
            }
            out[row] = self.alloc_linear(terms);
        }
        Ok(out)
    }

    fn hash_inv(&mut self, value: &Value) -> Result<Value, RelationError> {
        let source = self.linear(value)?;
        let index = self.wire(Op::Inverse(source.clone()));
        let inverse = Value::Wire(index);
        let nonzero = self.nonzero(value)?;
        self.rows
            .push((source, self.linear(&inverse)?, self.linear(&nonzero)?));
        let zero = self.add(&Value::Constant(F::ONE), &nonzero, true)?;
        // x=0 must select inv(0)=0, rather than an unconstrained inverse wire.
        self.rows
            .push((self.linear(&inverse)?, self.linear(&zero)?, vec![]));
        Ok(inverse)
    }

    fn hash_permute(&mut self, input: State) -> Result<State, RelationError> {
        if self.ops.len() > 32768 || self.rows.len() > 32768 {
            return Err(RelationError::Limit);
        }
        let mut state = self.hash_mds(&input, false)?;
        for round in 0..24 {
            let partial = (4..20).contains(&round);
            if partial {
                let rc = hemera::constants::ROUND_CONSTANTS_U64[128 + round - 4];
                let value = self.add(&state[0], &Value::Constant(F::new(rc)), false)?;
                state[0] = self.hash_inv(&value)?;
            } else {
                let offset = if round < 4 {
                    round * 16
                } else {
                    (round - 16) * 16
                };
                for lane in 0..16 {
                    let rc = hemera::constants::ROUND_CONSTANTS_U64[offset + lane];
                    let value = self.add(&state[lane], &Value::Constant(F::new(rc)), false)?;
                    let x = self.linear(&value)?;
                    let square = self.product(x.clone(), x.clone());
                    let square = self.linear(&square)?;
                    let cube = self.product(square.clone(), x);
                    let fourth = self.product(square.clone(), square);
                    state[lane] = self.product(self.linear(&cube)?, self.linear(&fourth)?);
                }
            }
            state = self.hash_mds(&state, partial)?;
        }
        Ok(state)
    }

    fn structural_digest(
        &mut self,
        value: &Value,
        depth: usize,
    ) -> Result<[Value; 4], RelationError> {
        if depth > MAX_DEPTH || self.ops.len() > 32768 || self.rows.len() > 32768 {
            return Err(RelationError::Limit);
        }
        let mut state = zero_state();
        match value {
            Value::Pair(left, right) => {
                let left = self.structural_digest(left, depth + 1)?;
                let right = self.structural_digest(right, depth + 1)?;
                state[..4].clone_from_slice(&left);
                state[4..8].clone_from_slice(&right);
                state[9] = Value::Constant(F::new(2)); // FLAG_PARENT, is_root=false
            }
            _ => {
                // hash_atom hashes canonical LE-u64 bytes. Hemera encodes seven
                // bytes per field lane; byte eight plus the padding byte 0x01
                // produce lane1 = high8 + 256. The length is eight bytes.
                let bits = self.bits(value, 64)?;
                state[0] = self.pack(&bits[..56])?;
                let high = self.pack(&bits[56..])?;
                state[1] = self.add(&high, &Value::Constant(F::new(256)), false)?;
                state[10] = Value::Constant(F::new(8));
                // DOMAIN_HASH in capacity11 is zero.
                let base = self.hash_permute(state)?;
                state = zero_state();
                state[..4].clone_from_slice(&base[..4]);
                state[9] = Value::Constant(F::new(4)); // FLAG_CHUNK, counter=0
            }
        }
        let state = self.hash_permute(state)?;
        Ok(core::array::from_fn(|i| state[i].clone()))
    }

    pub(super) fn axis_hash(&mut self, value: &Value) -> Result<Value, RelationError> {
        let out = self.structural_digest(value, 0)?;
        Ok(Value::Pair(
            Box::new(Value::Pair(
                Box::new(out[0].clone()),
                Box::new(out[1].clone()),
            )),
            Box::new(Value::Pair(
                Box::new(out[2].clone()),
                Box::new(out[3].clone()),
            )),
        ))
    }

    pub(super) fn hash(&mut self, value: &Value) -> Result<Value, RelationError> {
        let digest = self.structural_digest(value, 0)?;
        let mut state = zero_state();
        state[..4].clone_from_slice(&digest);
        // Pattern15 applies one plain StepSponge permutation after structural
        // identity hashing; all remaining rate and capacity lanes are zero.
        let out = self.hash_permute(state)?;
        Ok(Value::Pair(
            Box::new(Value::Pair(
                Box::new(out[0].clone()),
                Box::new(out[1].clone()),
            )),
            Box::new(Value::Pair(
                Box::new(out[2].clone()),
                Box::new(out[3].clone()),
            )),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn atom(value: u64) -> ExecutionNoun {
        ExecutionNoun::Atom(value)
    }
    fn pair(a: ExecutionNoun, b: ExecutionNoun) -> ExecutionNoun {
        ExecutionNoun::Pair(Box::new(a), Box::new(b))
    }
    fn native_hash(digest: [F; 4]) -> [F; 4] {
        let rate = digest.map(|v| H::new(v.as_u64()));
        let final_state = hemera::StepSponge::absorb(&rate).last().unwrap();
        core::array::from_fn(|i| F::new(final_state[i].as_canonical_u64()))
    }

    #[test]
    fn atom_hash_matches_native_at_byte_and_field_boundaries() {
        let program = pair(atom(15), pair(atom(0), atom(1)));
        let relation = compile_relation(&program, &SubjectShape::Atom).unwrap();
        assert_eq!(relation.max_cost, 26);
        for input in [0, 1, (1 << 56) - 1, 1 << 56, nebu::field::P - 1] {
            let input = F::new(input);
            let witness = relation.witness(&[input]).unwrap();
            assert!(relation.instance.is_satisfied_by(&witness));
            let actual: Vec<_> = relation
                .output_indices
                .iter()
                .map(|&i| witness.z[i])
                .collect();
            assert_eq!(actual, native_hash(nox::data::hash::hash_atom(input)));
        }
    }

    #[test]
    fn pair_hash_authenticates_children_and_round_wires() {
        let program = pair(atom(15), pair(atom(0), atom(1)));
        let shape = SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom));
        let relation = compile_relation(&program, &shape).unwrap();
        let inputs = [F::new(7), F::new(42)];
        let witness = relation.witness(&inputs).unwrap();
        assert!(relation.instance.is_satisfied_by(&witness));
        let digest = nox::data::hash::hash_pair(
            &nox::data::hash::hash_atom(inputs[0]),
            &nox::data::hash::hash_atom(inputs[1]),
        );
        let actual: Vec<_> = relation
            .output_indices
            .iter()
            .map(|&i| witness.z[i])
            .collect();
        assert_eq!(actual, native_hash(digest));
        // Fixed copies are shared column indices: neither a leaf, a round
        // intermediate nor a final output may be substituted independently.
        for index in [1, 2, 150, 600, relation.output_indices[0]] {
            let mut forged = witness.clone();
            forged.z[index] += F::ONE;
            assert!(!relation.instance.is_satisfied_by(&forged), "wire {index}");
        }
    }

    #[test]
    fn axis_zero_matches_structural_digest_without_extra_permutation() {
        let relation = compile_relation(&pair(atom(0), atom(0)), &SubjectShape::Atom).unwrap();
        let input = F::new(42);
        let witness = relation.witness(&[input]).unwrap();
        let actual: Vec<_> = relation
            .output_indices
            .iter()
            .map(|&i| witness.z[i])
            .collect();
        assert_eq!(actual, nox::data::hash::hash_atom(input));
        assert_eq!(relation.max_cost, 1);
        assert!(relation.instance.is_satisfied_by(&witness));
    }

    #[test]
    fn hash_output_is_authenticated_by_direct_proof() {
        let program = pair(atom(15), pair(atom(0), atom(1)));
        let relation = compile_relation(&program, &SubjectShape::Atom).unwrap();
        let witness = relation.witness(&[F::new(42)]).unwrap();
        let mut public: Vec<_> = relation
            .input_indices
            .iter()
            .chain(&relation.output_indices)
            .chain(core::iter::once(&relation.cost_index))
            .map(|&i| (i, witness.z[i]))
            .collect();
        public.sort_by_key(|&(i, _)| i);
        let proof =
            crate::execution::proof::prove(&relation.instance, &witness, b"hash test", &public)
                .unwrap();
        crate::execution::proof::verify(&relation.instance, &proof, b"hash test", &public).unwrap();
        let out = public
            .iter_mut()
            .find(|(i, _)| *i == relation.output_indices[0])
            .unwrap();
        out.1 += F::ONE;
        assert!(
            crate::execution::proof::verify(&relation.instance, &proof, b"hash test", &public)
                .is_err()
        );
    }

    #[test]
    fn partial_inverse_zero_is_constrained() {
        let mut builder = Builder {
            inputs: 1,
            ops: vec![],
            rows: vec![],
            calls: 0,
        };
        let inverse = builder.hash_inv(&Value::Wire(1)).unwrap();
        let Value::Wire(index) = inverse else {
            unreachable!()
        };
        let mut z = vec![F::ONE, F::ZERO];
        // Witness generation is shared with the relation; all inverse/selector
        // witnesses are zero, except the final one-minus-selector wire.
        z.resize(2 + builder.ops.len(), F::ZERO);
        *z.last_mut().unwrap() = F::ONE;
        let satisfies = |z: &[F]| {
            builder.rows.iter().all(|(a, b, c)| {
                let eval =
                    |terms: &Linear| terms.iter().fold(F::ZERO, |acc, &(i, k)| acc + z[i] * k);
                eval(a) * eval(b) == eval(c)
            })
        };
        assert!(satisfies(&z));
        z[index] = F::new(123);
        assert!(!satisfies(&z));
    }
}
