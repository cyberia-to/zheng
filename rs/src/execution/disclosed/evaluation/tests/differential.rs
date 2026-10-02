use super::*;

#[test]
fn all_pure_patterns_match_native_values_costs_and_frame_boundaries() {
    for tag in 0..16 {
        for value in [0, 1, 7, u32::MAX as u64] {
            let mut ar = Arena::try_new_boxed().unwrap();
            let a = atom(&mut ar, value);
            let b = atom(&mut ar, 3);
            let object = ar.pair(a, b).unwrap();
            let qa = op(&mut ar, 1, a);
            let qb = op(&mut ar, 1, b);
            let formula = match tag {
                0 => op(&mut ar, 0, b),
                1 => op(&mut ar, 1, object),
                2 => {
                    let address = atom(&mut ar, 1);
                    let identity = op(&mut ar, 0, address);
                    let qf = op(&mut ar, 1, identity);
                    binary(&mut ar, 2, qa, qf)
                }
                4 => branch(&mut ar, qa, qb, qa),
                8 => op(&mut ar, 8, qb),
                13 | 15 => op(&mut ar, tag, qa),
                _ => binary(&mut ar, tag, qa, qb),
            };
            let mut records = Vec::new();
            let root = derive(&mut ar, object, formula, &mut records);
            let expected = records[root as usize];
            let mut wrong = atom(&mut ar, 0x12345678);
            if particle(&ar, wrong) == particle(&ar, expected.candidate.result) {
                wrong = atom(&mut ar, 0x12345679);
            }
            let memory = import(&ar);
            let checked = verified(&memory, &records);
            let mut forged = verified(&memory, &records[..root as usize]);
            assert_eq!(
                forged.append(Candidate {
                    result: wrong,
                    ..expected.candidate
                }),
                Err(Error::Result)
            );
            assert_eq!(
                checked.bind_last(claim(&ar, expected)).unwrap().remaining(),
                0
            );
            for budget in [expected.cost, expected.cost + 1, u64::MAX] {
                let actual = nox::sequential::reduce_cached(
                    &mut ar,
                    object,
                    formula,
                    budget,
                    nox::sequential::Limits {
                        max_frames: expected.peak,
                    },
                )
                .unwrap();
                let Outcome::Ok(result, remaining) = actual.outcome else {
                    panic!("{:?}", actual.outcome)
                };
                assert_eq!(
                    particle(&ar, result),
                    particle(&ar, expected.candidate.result)
                );
                assert_eq!(remaining, budget - expected.cost);
                assert_eq!(actual.peak_frames, expected.peak);
            }
            let below = nox::sequential::reduce_cached(
                &mut ar,
                object,
                formula,
                expected.cost - 1,
                nox::sequential::Limits {
                    max_frames: expected.peak,
                },
            )
            .unwrap();
            assert!(!matches!(below.outcome, Outcome::Ok(..)));
            assert_eq!(
                nox::sequential::reduce_cached(
                    &mut ar,
                    object,
                    formula,
                    expected.cost,
                    nox::sequential::Limits {
                        max_frames: expected.peak - 1
                    }
                )
                .unwrap_err(),
                nox::sequential::Error::Frames
            );
        }
    }
}

#[test]
fn canonical_field_boundaries_and_large_valid_word_shifts_match_native() {
    for tag in [5, 6, 7, 8, 9, 10, 14] {
        for (a, b) in [
            (1, nebu::field::P - 1),
            (nebu::field::P - 1, 1),
            (0, 0),
            (u32::MAX as u64, u32::MAX as u64),
            (1, 32),
        ] {
            if (tag == 8 && a == 0) || (tag == 14 && (a > u32::MAX as u64 || b > u32::MAX as u64)) {
                continue;
            }
            let mut ar = Arena::try_new_boxed().unwrap();
            let object = atom(&mut ar, 0);
            let qa = quote(&mut ar, a);
            let qb = quote(&mut ar, b);
            let formula = if tag == 8 {
                op(&mut ar, tag, qa)
            } else {
                binary(&mut ar, tag, qa, qb)
            };
            let mut records = Vec::new();
            derive(&mut ar, object, formula, &mut records);
            let memory = import(&ar);
            let evals = verified(&memory, &records);
            let last = *records.last().unwrap();
            assert_eq!(evals.bind_last(claim(&ar, last)).unwrap().remaining(), 0);
        }
    }
}

#[test]
fn axis_zero_and_hash_have_distinct_native_results_and_logical_step_counts() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 42);
    let zero = atom(&mut ar, 0);
    let axis = op(&mut ar, 0, zero);
    let quote = op(&mut ar, 1, object);
    let hash = op(&mut ar, 15, quote);
    let mut records = Vec::new();
    let a = derive(&mut ar, object, axis, &mut records);
    let h = derive(&mut ar, object, hash, &mut records);
    assert_ne!(
        particle(&ar, records[a as usize].candidate.result),
        particle(&ar, records[h as usize].candidate.result)
    );
    let memory = import(&ar);
    let evals = verified(&memory, &records);
    assert_eq!(
        (evals.get(a).unwrap().cost(), evals.get(a).unwrap().steps()),
        (1, 2)
    );
    assert_eq!(
        (evals.get(h).unwrap().cost(), evals.get(h).unwrap().steps()),
        (26, 4)
    );
}

#[test]
fn repeated_prior_premises_count_expanded_occurrences_and_match_observer() {
    use nox::sequential::{CompactionLimits, observe::*};
    struct Counter {
        enters: u64,
        steps: u64,
    }
    impl Observer for Counter {
        type Error = core::convert::Infallible;
        fn record(&mut self, event: Event) -> Result<(), Self::Error> {
            if let Event::Transition(t) = event {
                self.enters += u64::from(matches!(t.before, LogicalAction::Enter { .. }));
            }
            if let Event::Completed { steps, .. } = event {
                self.steps = steps;
            }
            Ok(())
        }
    }
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let q = quote(&mut ar, 7);
    let f = binary(&mut ar, 3, q, q);
    let mut records = Vec::new();
    derive(&mut ar, object, f, &mut records);
    let mut root = records[2];
    root.candidate.premises = Premises::Two([0, 0]);
    let memory = import(&ar);
    let evals = verified(&memory, &[records[0], root]);
    let got = evals.get(1).unwrap();
    assert_eq!(
        (
            got.cost(),
            got.occurrences(),
            got.peak_frames(),
            got.steps()
        ),
        (3, 3, 2, 6)
    );
    let mut counter = Counter {
        enters: 0,
        steps: 0,
    };
    let run = reduce_compacting_observed_controlled(
        &mut ar,
        object,
        f,
        3,
        CompactionLimits {
            max_frames: 2,
            max_total_allocations: 10_000,
            max_collection_work: 10_000_000,
        },
        CaptureLimits {
            max_events: 10_000,
            max_bytes: 1_000_000,
            max_work: 100_000,
        },
        &mut counter,
        &mut || false,
    )
    .unwrap();
    assert_eq!((counter.enters, counter.steps), (3, 6));
    assert_eq!(run.execution.stats.evaluator_checkpoints, 7);
}

#[test]
fn saturated_and_dynamic_unselected_metadata_preserves_cheap_execution() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let q0 = quote(&mut ar, 0);
    let q7 = quote(&mut ar, 7);
    let mut huge = q7;
    for _ in 0..64 {
        huge = binary(&mut ar, 3, huge, huge);
    }
    assert_eq!(
        ar.get(huge).unwrap().bound,
        nox::data::Cost::Exact(u64::MAX)
    );
    let dynamic = binary(&mut ar, 2, q0, q0);
    let service = op(&mut ar, 16, q0);
    for no in [huge, dynamic, service, object] {
        let cheap = branch(&mut ar, q0, q7, no);
        let f = binary(&mut ar, 5, cheap, cheap);
        let unary = op(&mut ar, 13, cheap);
        for formula in [f, unary] {
            let mut records = Vec::new();
            let root = derive(&mut ar, object, formula, &mut records);
            let expected = records[root as usize];
            let memory = import(&ar);
            let evals = verified(&memory, &records);
            assert_eq!(
                evals.bind_last(claim(&ar, expected)).unwrap().remaining(),
                0
            );
            for budget in [expected.cost, expected.cost + 1, u64::MAX] {
                let run = nox::sequential::reduce_cached(
                    &mut ar,
                    object,
                    formula,
                    budget,
                    nox::sequential::Limits {
                        max_frames: expected.peak,
                    },
                )
                .unwrap();
                assert!(matches!(run.outcome, Outcome::Ok(_, r) if r == budget - expected.cost));
            }
        }
    }
}
