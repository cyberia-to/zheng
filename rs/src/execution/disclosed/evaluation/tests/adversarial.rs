use super::*;

#[test]
fn premise_keys_arity_order_and_prior_frontier_are_authenticated() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let other = atom(&mut ar, 1);
    let qa = quote(&mut ar, 7);
    let qb = quote(&mut ar, 9);
    let formula = binary(&mut ar, 5, qa, qb);
    let mut records = Vec::new();
    derive(&mut ar, object, formula, &mut records);
    let extra = derive(&mut ar, other, qa, &mut records);
    let memory = import(&ar);
    let mut evals = store(&memory);
    evals.append(records[0].candidate).unwrap();
    evals.append(records[1].candidate).unwrap();
    let foreign = evals.append(records[extra as usize].candidate).unwrap();
    let good = records[2].candidate;
    for premises in [
        Premises::None,
        Premises::One(0),
        Premises::Three([0, 1, 0]),
        Premises::Two([1, 0]),
        Premises::Two([foreign, 1]),
        Premises::Two([3, 1]),
        Premises::Two([4, 1]),
        Premises::Two([u32::MAX, 1]),
    ] {
        let before = evals.records.clone();
        assert!(evals.append(Candidate { premises, ..good }).is_err());
        assert_eq!(evals.records, before);
    }
    assert_eq!(evals.append(good), Ok(3));
}

#[test]
fn computed_continuation_binds_both_child_results_as_its_key() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let qa = quote(&mut ar, 7);
    let one = atom(&mut ar, 1);
    let identity = op(&mut ar, 0, one);
    let qf = op(&mut ar, 1, identity);
    let formula = binary(&mut ar, 2, qa, qf);
    let mut records = Vec::new();
    derive(&mut ar, object, formula, &mut records);
    let wrong = derive(&mut ar, object, identity, &mut records);
    let computed_object = records[0].candidate.result;
    let wrong_formula = derive(&mut ar, computed_object, qa, &mut records);
    let memory = import(&ar);
    let mut evals = verified(&memory, &records[..3]);
    let wrong_id = evals.append(records[wrong as usize].candidate).unwrap();
    let wrong_formula_id = evals
        .append(records[wrong_formula as usize].candidate)
        .unwrap();
    let good = records[3].candidate;
    assert_eq!(
        evals.append(Candidate {
            premises: Premises::Three([0, 1, wrong_id]),
            ..good
        }),
        Err(Error::Premise)
    );
    assert_eq!(
        evals.append(Candidate {
            premises: Premises::Three([0, 1, wrong_formula_id]),
            ..good
        }),
        Err(Error::Premise)
    );
    assert_eq!(evals.append(good), Ok(5));
}

#[test]
fn changing_the_selected_arm_rejects_even_when_the_forged_result_matches_it() {
    for condition in [0, 1, nebu::field::P - 1] {
        let mut ar = Arena::try_new_boxed().unwrap();
        let object = atom(&mut ar, 0);
        let test = quote(&mut ar, condition);
        let yes = quote(&mut ar, 7);
        let no = quote(&mut ar, 9);
        let formula = branch(&mut ar, test, yes, no);
        let mut records = Vec::new();
        derive(&mut ar, object, formula, &mut records);
        let unselected = if condition == 0 { no } else { yes };
        let wrong = derive(&mut ar, object, unselected, &mut records);
        let memory = import(&ar);
        let mut evals = verified(&memory, &records[..2]);
        let wrong_id = evals.append(records[wrong as usize].candidate).unwrap();
        let forged = Candidate {
            result: records[wrong as usize].candidate.result,
            premises: Premises::Two([0, wrong_id]),
            ..records[2].candidate
        };
        assert_eq!(evals.append(forged), Err(Error::Premise));
        assert_eq!(evals.len(), 3);
        assert_eq!(evals.append(records[2].candidate), Ok(3));
    }
}

#[test]
fn outputs_bind_ordered_topology_and_all_root_particle_limbs() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let qa = quote(&mut ar, 7);
    let qb = quote(&mut ar, 9);
    let f = binary(&mut ar, 3, qa, qb);
    let mut records = Vec::new();
    derive(&mut ar, object, f, &mut records);
    let a = records[0].candidate.result;
    let b = records[1].candidate.result;
    let reversed = ar.pair(b, a).unwrap();
    let memory = import(&ar);
    let mut evals = verified(&memory, &records[..2]);
    let good = records[2];
    for result in [a, reversed, u32::MAX] {
        assert!(
            evals
                .append(Candidate {
                    result,
                    ..good.candidate
                })
                .is_err()
        );
        assert_eq!(evals.len(), 2);
    }
    evals.append(good.candidate).unwrap();
    let expected = claim(&ar, good);
    for field in 0..3 {
        for limb in 0..4 {
            let mut changed = expected;
            match field {
                0 => changed.object[limb] ^= 1,
                1 => changed.formula[limb] ^= 1,
                _ => changed.result[limb] ^= 1,
            }
            assert_eq!(evals.bind_last(changed), Err(Error::Claim));
        }
    }
    for changed in [
        Claim {
            cost: good.cost + 1,
            ..expected
        },
        Claim {
            cost: good.cost ^ (1 << 32),
            ..expected
        },
        Claim {
            budget: good.cost - 1,
            ..expected
        },
        Claim {
            max_frames: good.peak - 1,
            ..expected
        },
        Claim {
            max_frames: limits().max_frames + 1,
            ..expected
        },
    ] {
        assert_eq!(evals.bind_last(changed), Err(Error::Claim));
    }
    assert_eq!(evals.bind_last(expected).unwrap().remaining(), 0);
    assert_eq!(
        evals
            .bind_last(Claim {
                budget: expected.budget + 1,
                ..expected
            })
            .unwrap()
            .remaining(),
        1
    );
    evals.append(records[0].candidate).unwrap();
    assert_eq!(evals.bind_last(expected), Err(Error::Claim));
}

#[test]
fn equality_and_premise_keys_use_particles_across_duplicate_occurrences() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let value = atom(&mut ar, 7);
    let q = op(&mut ar, 1, value);
    let f = binary(&mut ar, 9, q, q);
    let mut records = Vec::new();
    derive(&mut ar, object, f, &mut records);
    let mut memory = Memory::new(
        ar.count() + 3,
        (ar.count() as usize + 3) * size_of::<VerifiedNode>(),
    )
    .unwrap();
    let native = import(&ar);
    for i in 0..native.len() {
        let view = native.view(native.len()).unwrap();
        let n = view.get(i).unwrap();
        memory
            .append(Definition {
                value: n.value(),
                particle: n.particle(),
                cost: n.cost(),
            })
            .unwrap();
    }
    let duplicate = |id| {
        let view = native.view(native.len()).unwrap();
        let n = view.get(id).unwrap();
        Definition {
            value: n.value(),
            particle: n.particle(),
            cost: n.cost(),
        }
    };
    let object2 = memory.append(duplicate(object)).unwrap();
    let value2 = memory.append(duplicate(value)).unwrap();
    let q2 = memory.append(duplicate(q)).unwrap();
    let mut evals = store(&memory);
    evals.append(records[0].candidate).unwrap();
    let second = evals
        .append(Candidate {
            object: object2,
            formula: q2,
            result: value2,
            premises: Premises::None,
        })
        .unwrap();
    let root = Candidate {
        premises: Premises::Two([0, second]),
        ..records[2].candidate
    };
    assert_eq!(evals.append(root), Ok(2));
    assert_eq!(evals.particles(0).unwrap(), evals.particles(1).unwrap());
}

#[test]
fn malformed_formulas_invalid_types_and_inverse_zero_have_no_success_rule() {
    for tag in [0, 2, 4, 5, 8, 10, 11, 12, 13, 14, 16, 17, 99] {
        let mut ar = Arena::try_new_boxed().unwrap();
        let zero = atom(&mut ar, 0);
        let wide = atom(&mut ar, 1 << 32);
        let pair = ar.pair(zero, wide).unwrap();
        let value = if tag == 8 {
            zero
        } else if [11, 12, 13, 14].contains(&tag) {
            wide
        } else {
            pair
        };
        let q = op(&mut ar, 1, value);
        let mut records = Vec::new();
        derive(&mut ar, zero, q, &mut records);
        let formula = match tag {
            8 | 13 => op(&mut ar, tag, q),
            5 | 10 | 11 | 12 | 14 => binary(&mut ar, tag, q, q),
            _ => op(&mut ar, tag, pair),
        };
        let premises = match tag {
            8 | 13 => Premises::One(0),
            2 => Premises::Three([0, 0, 0]),
            0 | 16 | 17 | 99 => Premises::None,
            _ => Premises::Two([0, 0]),
        };
        let memory = import(&ar);
        let mut evals = verified(&memory, &records);
        assert!(
            evals
                .append(Candidate {
                    object: zero,
                    formula,
                    result: zero,
                    premises
                })
                .is_err(),
            "tag {tag}"
        );
        assert_eq!(evals.len(), 1);
        assert!(
            evals
                .append(Candidate {
                    object: zero,
                    formula: zero,
                    result: zero,
                    premises: Premises::None
                })
                .is_err()
        );
    }
}

#[test]
fn exact_and_one_below_resource_limits_fail_without_mutation() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let q = quote(&mut ar, 7);
    let f = binary(&mut ar, 3, q, q);
    let mut records = Vec::new();
    derive(&mut ar, object, f, &mut records);
    let memory = import(&ar);
    let exact = Limits {
        max_evaluations: 3,
        max_buffer_bytes: 3 * size_of::<VerifiedEvaluation>(),
        max_cost: 3,
        max_frames: 2,
        max_steps: 6,
    };
    assert!(
        Evaluations::new(
            memory.view(memory.len()).unwrap(),
            Limits {
                max_buffer_bytes: exact.max_buffer_bytes - 1,
                ..exact
            }
        )
        .is_err()
    );
    for limits in [
        exact,
        Limits {
            max_evaluations: 2,
            ..exact
        },
        Limits {
            max_cost: 2,
            ..exact
        },
        Limits {
            max_frames: 1,
            ..exact
        },
        Limits {
            max_steps: 5,
            ..exact
        },
    ] {
        let mut evals = Evaluations::new(memory.view(memory.len()).unwrap(), limits).unwrap();
        for record in &records[..2] {
            evals.append(record.candidate).unwrap();
        }
        let before = evals.records.clone();
        let got = evals.append(records[2].candidate);
        if limits.max_evaluations == 3
            && limits.max_cost == 3
            && limits.max_frames == 2
            && limits.max_steps == 6
        {
            assert_eq!(got, Ok(2));
            assert!(evals.buffer_bytes() <= exact.max_buffer_bytes);
        } else {
            assert_eq!(got, Err(Error::Limit));
            assert_eq!(evals.records, before);
        }
    }
    let mut empty = Evaluations::new(memory.view(0).unwrap(), limits()).unwrap();
    assert_eq!(empty.append(records[0].candidate), Err(Error::Noun));
    assert!(empty.bind_last(claim(&ar, records[0])).is_err());
}

#[test]
fn expanded_steps_and_exact_cost_overflow_reject_shared_derivations() {
    for tag in [3, 10] {
        let mut ar = Arena::try_new_boxed().unwrap();
        let object = atom(&mut ar, 0);
        let mut result = atom(&mut ar, 1);
        let mut formula = op(&mut ar, 1, result);
        let mut candidates = vec![Candidate {
            object,
            formula,
            result,
            premises: Premises::None,
        }];
        for i in 0..64 {
            formula = binary(&mut ar, tag, formula, formula);
            result = if tag == 3 {
                ar.pair(result, result).unwrap()
            } else {
                atom(&mut ar, 1)
            };
            candidates.push(Candidate {
                object,
                formula,
                result,
                premises: Premises::Two([i, i]),
            });
        }
        let memory = import(&ar);
        let mut evals = store(&memory);
        let mut failed = false;
        for candidate in candidates {
            let before = evals.records.clone();
            match evals.append(candidate) {
                Ok(_) => {}
                Err(error) => {
                    assert_eq!(error, Error::Limit);
                    assert_eq!(evals.records, before);
                    failed = true;
                    break;
                }
            }
        }
        assert!(failed);
    }
}
