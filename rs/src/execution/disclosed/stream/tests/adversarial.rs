use super::*;

fn fixture() -> (Box<Arena>, Vec<Native>) {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let qa = quote(&mut ar, 7);
    let qb = quote(&mut ar, 9);
    let formula = binary(&mut ar, 3, qa, qb);
    let mut records = Vec::new();
    derive(&mut ar, object, formula, &mut records);
    (ar, records)
}
fn fresh(ar: &Arena, records: &[Native], bounds: Limits) -> SemanticStream {
    let c = records.last().unwrap().candidate;
    SemanticStream::new(key(ar, c.object, c.formula), bounds).unwrap()
}
fn complete(ar: &Arena, records: &[Native]) -> SemanticStream {
    let mut stream = fresh(ar, records, limits());
    emit(&mut stream, ar, records, records.len() as u32 - 1, &mut 0);
    stream
}

#[test]
fn wrong_keys_outputs_truncation_and_extra_roots_poison_or_reject() {
    let (ar, records) = fixture();
    let root = records[2];
    let c = root.candidate;
    let mut stream = fresh(&ar, &records, limits());
    assert_eq!(
        enter(
            &mut stream,
            &ar,
            c.object,
            records[0].candidate.formula,
            &mut 0
        ),
        Err(Error::Key)
    );
    assert!(stream.is_poisoned());
    assert_eq!(stream.expected(), None);
    assert_eq!(
        enter(&mut stream, &ar, c.object, c.formula, &mut 0),
        Err(Error::Poisoned)
    );
    assert_eq!(stream.bind_terminal(claim(&ar, root)), Err(Error::Poisoned));
    let stream = fresh(&ar, &records, limits());
    assert_eq!(stream.bind_terminal(claim(&ar, root)), Err(Error::State));
    let mut stream = fresh(&ar, &records, limits());
    enter(&mut stream, &ar, c.object, c.formula, &mut 0).unwrap();
    assert_eq!(
        finish(&mut stream, &ar, c.result, None, &mut 0),
        Err(Error::State)
    );
    assert_eq!(stream.bind_terminal(claim(&ar, root)), Err(Error::Poisoned));
    let mut stream = complete(&ar, &records);
    assert_eq!(
        enter(&mut stream, &ar, c.object, c.formula, &mut 0),
        Err(Error::State)
    );
    assert_eq!(stream.bind_terminal(claim(&ar, root)), Err(Error::Poisoned));
}

#[test]
fn selected_branch_and_computed_continuation_keys_survive_reset_and_reject_changes() {
    for condition in [0, 1, nebu::field::P - 1] {
        let mut ar = Arena::try_new_boxed().unwrap();
        let object = atom(&mut ar, 0);
        let test = quote(&mut ar, condition);
        let yes = quote(&mut ar, 7);
        let no = quote(&mut ar, 9);
        let formula = branch(&mut ar, test, yes, no);
        let mut records = Vec::new();
        derive(&mut ar, object, formula, &mut records);
        let mut stream = fresh(&ar, &records, limits());
        enter(&mut stream, &ar, object, formula, &mut 0).unwrap();
        emit(&mut stream, &ar, &records, 0, &mut 0);
        let wrong = if condition == 0 { no } else { yes };
        assert_eq!(
            enter(&mut stream, &ar, object, wrong, &mut 0),
            Err(Error::Key)
        );
    }
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let q = quote(&mut ar, 7);
    let one = atom(&mut ar, 1);
    let identity = op(&mut ar, 0, one);
    let qf = op(&mut ar, 1, identity);
    let formula = binary(&mut ar, 2, q, qf);
    let mut records = Vec::new();
    derive(&mut ar, object, formula, &mut records);
    for (wrong_object, wrong_formula) in [(object, identity), (records[0].candidate.result, q)] {
        let mut stream = fresh(&ar, &records, limits());
        enter(&mut stream, &ar, object, formula, &mut 0).unwrap();
        emit(&mut stream, &ar, &records, 0, &mut 0);
        emit(&mut stream, &ar, &records, 1, &mut 0);
        assert_eq!(
            stream.expected(),
            Some(key(&ar, records[0].candidate.result, identity))
        );
        assert_eq!(
            enter(&mut stream, &ar, wrong_object, wrong_formula, &mut 0),
            Err(Error::Key)
        );
    }
}

#[test]
fn stale_generations_empty_slots_wrong_keys_and_generation_overflow_reject() {
    let (ar, records) = fixture();
    let c = records[2].candidate;
    let mut stream = fresh(&ar, &records, limits());
    assert_eq!(
        stream.reuse(CacheHandle {
            slot: 0,
            generation: 1
        }),
        Err(Error::Cache)
    );
    for attack in 0..4 {
        let mut stream = fresh(&ar, &records, limits());
        enter(&mut stream, &ar, c.object, c.formula, &mut 0).unwrap();
        enter(
            &mut stream,
            &ar,
            c.object,
            records[0].candidate.formula,
            &mut 0,
        )
        .unwrap();
        if attack == 3 {
            stream.cache[0].generation = u64::MAX;
        }
        let stored = finish(
            &mut stream,
            &ar,
            records[0].candidate.result,
            Some(0),
            &mut 0,
        );
        if attack == 3 {
            assert_eq!(stored, Err(Error::Limit));
            assert!(stream.is_poisoned());
            continue;
        }
        let mut handle = stored.unwrap().unwrap();
        let expected = match attack {
            0 => Error::Key,
            1 => {
                handle.generation += 1;
                Error::Cache
            }
            _ => {
                handle.slot = limits().max_cache_slots;
                Error::Cache
            }
        };
        assert_eq!(stream.reuse(handle), Err(expected));
        assert!(stream.cache(0).is_none());
    }
    // Overwrite slot 0 with a different child, then try its actual old handle.
    let mut stream = fresh(&ar, &records, limits());
    enter(&mut stream, &ar, c.object, c.formula, &mut 0).unwrap();
    enter(
        &mut stream,
        &ar,
        c.object,
        records[0].candidate.formula,
        &mut 0,
    )
    .unwrap();
    let stale = finish(
        &mut stream,
        &ar,
        records[0].candidate.result,
        Some(0),
        &mut 0,
    )
    .unwrap()
    .unwrap();
    enter(
        &mut stream,
        &ar,
        c.object,
        records[1].candidate.formula,
        &mut 0,
    )
    .unwrap();
    finish(
        &mut stream,
        &ar,
        records[1].candidate.result,
        Some(0),
        &mut 0,
    )
    .unwrap();
    assert_eq!(stream.reuse(stale), Err(Error::Cache));
}

#[test]
fn exact_resource_caps_and_one_below_are_enforced_with_full_cached_charge() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let q = quote(&mut ar, 7);
    let formula = binary(&mut ar, 3, q, q);
    let mut records = Vec::new();
    derive(&mut ar, object, formula, &mut records);
    let exact = Limits {
        max_frames: 2,
        max_cache_slots: 1,
        max_buffer_bytes: SemanticStream::storage_bytes(2, 1).unwrap(),
        max_cost: 3,
        max_steps: 6,
        max_events: 5,
    };
    assert!(matches!(
        SemanticStream::new(
            key(&ar, object, formula),
            Limits {
                max_buffer_bytes: exact.max_buffer_bytes - 1,
                ..exact
            }
        ),
        Err(Error::Limit)
    ));
    for change in 0..5 {
        let bounds = match change {
            1 => Limits {
                max_frames: 1,
                ..exact
            },
            2 => Limits {
                max_cost: 2,
                ..exact
            },
            3 => Limits {
                max_steps: 5,
                ..exact
            },
            4 => Limits {
                max_events: 4,
                ..exact
            },
            _ => exact,
        };
        let mut stream = fresh(&ar, &records, bounds);
        let run = (|| {
            enter(&mut stream, &ar, object, formula, &mut 0)?;
            enter(&mut stream, &ar, object, q, &mut 0)?;
            let handle = finish(
                &mut stream,
                &ar,
                records[0].candidate.result,
                Some(0),
                &mut 0,
            )?
            .unwrap();
            stream.reuse(handle)?;
            finish(&mut stream, &ar, records[2].candidate.result, None, &mut 0)?;
            Ok::<_, Error>(())
        })();
        if change == 0 {
            assert_eq!(run, Ok(()));
            assert_eq!(
                stream
                    .bind_terminal(claim(&ar, records[2]))
                    .unwrap()
                    .events(),
                5
            );
        } else {
            assert_eq!(run, Err(Error::Limit));
            assert!(stream.is_poisoned());
        }
    }
}

#[test]
fn terminal_checks_every_particle_limb_exact_cost_budget_and_frame_claim() {
    let (ar, records) = fixture();
    let expected = claim(&ar, records[2]);
    for field in 0..3 {
        for limb in 0..4 {
            let mut changed = expected;
            match field {
                0 => changed.object[limb] ^= 1,
                1 => changed.formula[limb] ^= 1,
                _ => changed.result[limb] ^= 1,
            }
            assert_eq!(
                complete(&ar, &records).bind_terminal(changed),
                Err(Error::Claim)
            );
        }
    }
    for changed in [
        Claim {
            cost: expected.cost ^ (1 << 32),
            ..expected
        },
        Claim {
            cost: expected.cost + 1,
            ..expected
        },
        Claim {
            budget: expected.cost - 1,
            ..expected
        },
        Claim {
            max_frames: expected.max_frames - 1,
            ..expected
        },
        Claim {
            max_frames: limits().max_frames + 1,
            ..expected
        },
    ] {
        assert_eq!(
            complete(&ar, &records).bind_terminal(changed),
            Err(Error::Claim)
        );
    }
    assert_eq!(
        complete(&ar, &records)
            .bind_terminal(Claim {
                budget: expected.cost + 1,
                ..expected
            })
            .unwrap()
            .remaining(),
        1
    );
}

#[test]
fn invalid_types_inverse_zero_and_service_invocations_poison() {
    for tag in [8, 13, 15, 16, 17, 99] {
        let mut ar = Arena::try_new_boxed().unwrap();
        let object = atom(&mut ar, 0);
        let value = if tag == 8 {
            object
        } else {
            atom(&mut ar, 1 << 32)
        };
        let q = op(&mut ar, 1, value);
        let formula = op(&mut ar, tag, q);
        let mut stream = SemanticStream::new(key(&ar, object, formula), limits()).unwrap();
        let start = enter(&mut stream, &ar, object, formula, &mut 0);
        if tag >= 16 {
            assert_eq!(start, Err(Error::UnsupportedOpcode));
            continue;
        }
        start.unwrap();
        enter(&mut stream, &ar, object, q, &mut 0).unwrap();
        let out = finish(&mut stream, &ar, value, None, &mut 0);
        if tag == 15 {
            out.unwrap();
            assert_eq!(
                finish(&mut stream, &ar, value, None, &mut 0),
                Err(Error::Output)
            );
        } else {
            assert_eq!(
                out,
                Err(if tag == 8 {
                    Error::InverseZero
                } else {
                    Error::Type
                })
            );
        }
        assert!(stream.is_poisoned());
    }
}

#[test]
fn checked_metric_overflow_rejects_exponentially_shared_evaluations() {
    fn expand(
        stream: &mut SemanticStream,
        ar: &Arena,
        object: u32,
        formulas: &[u32],
        results: &[u32],
        depth: usize,
    ) -> Result<CacheHandle, Error> {
        enter(stream, ar, object, formulas[depth], &mut 0)?;
        if depth > 0 {
            let child = expand(stream, ar, object, formulas, results, depth - 1)?;
            stream.reuse(child)?;
        }
        finish(stream, ar, results[depth], Some(depth as u32), &mut 0)?.ok_or(Error::Cache)
    }
    for tag in [3, 10] {
        let mut ar = Arena::try_new_boxed().unwrap();
        let object = atom(&mut ar, 0);
        let one = atom(&mut ar, 1);
        let mut formulas = vec![op(&mut ar, 1, one)];
        let mut results = vec![one];
        for depth in 0..64 {
            formulas.push(binary(&mut ar, tag, formulas[depth], formulas[depth]));
            results.push(if tag == 3 {
                ar.pair(results[depth], results[depth]).unwrap()
            } else {
                one
            });
        }
        let bounds = Limits {
            max_cache_slots: 65,
            max_buffer_bytes: SemanticStream::storage_bytes(128, 65).unwrap(),
            ..limits()
        };
        let mut stream = SemanticStream::new(key(&ar, object, formulas[64]), bounds).unwrap();
        assert_eq!(
            expand(&mut stream, &ar, object, &formulas, &results, 64),
            Err(Error::Limit)
        );
        assert!(stream.is_poisoned());
    }
}
