use super::*;

#[test]
fn all_native_rules_match_finite_dag_across_a_fresh_noun_table_per_event() {
    for tag in 0..16 {
        for value in [0, 1, 7, u32::MAX as u64] {
            let mut ar = Arena::try_new_boxed().unwrap();
            let a = atom(&mut ar, value);
            let b = atom(&mut ar, 3);
            let object = ar.pair(a, b).unwrap();
            let qa = op(&mut ar, 1, a);
            let qb = op(&mut ar, 1, b);
            let formula = match tag {
                0 => {
                    let address = atom(&mut ar, value % 4);
                    op(&mut ar, 0, address)
                }
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
            derive(&mut ar, object, formula, &mut records);
            let wrong = atom(&mut ar, 0x1234_5678);
            let c = records.last().unwrap().candidate;
            assert_ne!(particle(&ar, wrong), particle(&ar, c.result));
            let mut rejected = SemanticStream::new(key(&ar, object, formula), limits()).unwrap();
            enter(&mut rejected, &ar, object, formula, &mut 0).unwrap();
            for &child in c.premises.as_slice() {
                emit(&mut rejected, &ar, &records, child, &mut 0);
            }
            assert_eq!(
                finish(&mut rejected, &ar, wrong, None, &mut 0),
                Err(Error::Output)
            );
            assert!(rejected.is_poisoned());
            let root = *records.last().unwrap();
            let terminal = terminal(&ar, &records);
            let finite = finite(&ar, &records);
            let summary = terminal.summary();
            assert_eq!(summary.key(), key(&ar, object, formula));
            assert_eq!(
                summary.result().particle(),
                particle(&ar, root.candidate.result)
            );
            assert_eq!(summary.cost(), root.cost);
            assert_eq!(summary.peak_frames(), root.peak);
            assert_eq!(
                (
                    summary.cost(),
                    summary.occurrences(),
                    summary.peak_frames(),
                    summary.steps()
                ),
                (
                    finite.cost(),
                    finite.occurrences(),
                    finite.peak_frames(),
                    finite.steps()
                )
            );
            assert_eq!(terminal.events(), 2 * records.len() as u64);
            assert_eq!(terminal.remaining(), 0);
        }
    }
}

#[test]
fn cached_child_metrics_and_atom_facts_survive_noun_reset_and_slot_replacement() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let q = quote(&mut ar, 7);
    let formula = binary(&mut ar, 5, q, q);
    let mut records = Vec::new();
    derive(&mut ar, object, formula, &mut records);
    let mut stream = SemanticStream::new(key(&ar, object, formula), limits()).unwrap();
    let mut nonce = 0;
    enter(&mut stream, &ar, object, formula, &mut nonce).unwrap();
    enter(&mut stream, &ar, object, q, &mut nonce).unwrap();
    let handle = finish(
        &mut stream,
        &ar,
        records[0].candidate.result,
        Some(0),
        &mut nonce,
    )
    .unwrap()
    .unwrap();
    let (stored, summary) = stream.cache(0).unwrap();
    assert_eq!(stored, handle);
    assert_eq!(handle.generation, 1);
    assert_eq!(summary.result().value(), ResultValue::Atom(7));
    assert_eq!(
        (
            summary.cost(),
            summary.occurrences(),
            summary.peak_frames(),
            summary.steps()
        ),
        (1, 1, 1, 2)
    );
    stream.reuse(handle).unwrap();
    let root = *records.last().unwrap();
    let replacement = finish(&mut stream, &ar, root.candidate.result, Some(0), &mut nonce)
        .unwrap()
        .unwrap();
    assert_eq!(replacement.generation, 2);
    let terminal = stream.bind_terminal(claim(&ar, root)).unwrap();
    assert_eq!(
        (
            terminal.summary().cost(),
            terminal.summary().occurrences(),
            terminal.summary().steps(),
            terminal.events()
        ),
        (3, 3, 6, 5)
    );
}

#[test]
fn parent_keeps_left_header_when_right_child_evicts_its_summary() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let qa = quote(&mut ar, 7);
    let qb = quote(&mut ar, 9);
    let formula = binary(&mut ar, 3, qa, qb);
    let mut records = Vec::new();
    derive(&mut ar, object, formula, &mut records);
    let mut stream = SemanticStream::new(key(&ar, object, formula), limits()).unwrap();
    let mut nonce = 0;
    enter(&mut stream, &ar, object, formula, &mut nonce).unwrap();
    for record in &records[..2] {
        enter(
            &mut stream,
            &ar,
            object,
            record.candidate.formula,
            &mut nonce,
        )
        .unwrap();
        finish(
            &mut stream,
            &ar,
            record.candidate.result,
            Some(0),
            &mut nonce,
        )
        .unwrap();
    }
    let last = *records.last().unwrap();
    finish(&mut stream, &ar, last.candidate.result, None, &mut nonce).unwrap();
    let done = stream.bind_terminal(claim(&ar, last)).unwrap();
    assert_eq!(
        done.summary().result().value(),
        ResultValue::Pair {
            left: particle(&ar, records[0].candidate.result),
            right: particle(&ar, records[1].candidate.result)
        }
    );
}

#[test]
fn canonical_field_word_and_hash_boundaries_match_native() {
    for tag in [5, 6, 7, 8, 9, 10, 14, 15] {
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
            let formula = if [8, 15].contains(&tag) {
                op(&mut ar, tag, qa)
            } else {
                binary(&mut ar, tag, qa, qb)
            };
            let mut records = Vec::new();
            derive(&mut ar, object, formula, &mut records);
            let done = terminal(&ar, &records);
            let finite = finite(&ar, &records);
            assert_eq!(done.summary().cost(), finite.cost());
        }
    }
}

#[test]
fn saturated_unselected_dynamic_and_service_data_preserve_selected_derivation() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let q0 = quote(&mut ar, 0);
    let q7 = quote(&mut ar, 7);
    let mut huge = q7;
    for _ in 0..64 {
        huge = binary(&mut ar, 3, huge, huge);
    }
    let dynamic = binary(&mut ar, 2, q0, q0);
    let service = op(&mut ar, 16, q0);
    for no in [huge, dynamic, service, object] {
        let cheap = branch(&mut ar, q0, q7, no);
        let formula = binary(&mut ar, 5, cheap, cheap);
        let mut records = Vec::new();
        derive(&mut ar, object, formula, &mut records);
        let done = terminal(&ar, &records);
        assert_eq!(
            (
                done.summary().cost(),
                done.summary().occurrences(),
                done.summary().peak_frames()
            ),
            (7, 7, 3)
        );
    }
}
