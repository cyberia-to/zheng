use super::*;

#[test]
fn reused_summary_counts_its_entire_height_at_the_current_stack_depth() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let q = quote(&mut ar, 7);
    let child = binary(&mut ar, 3, q, q);
    let right = binary(&mut ar, 3, child, q);
    let formula = binary(&mut ar, 3, child, right);
    let mut records = Vec::new();
    derive(&mut ar, object, formula, &mut records);
    let result = records[2].candidate.result;
    for max_frames in [3, 4] {
        let mut stream = SemanticStream::new(
            key(&ar, object, formula),
            Limits {
                max_frames,
                ..limits()
            },
        )
        .unwrap();
        enter(&mut stream, &ar, object, formula, &mut 0).unwrap();
        enter(&mut stream, &ar, object, child, &mut 0).unwrap();
        emit(&mut stream, &ar, &records, 0, &mut 0);
        emit(&mut stream, &ar, &records, 1, &mut 0);
        let handle = finish(&mut stream, &ar, result, Some(0), &mut 0)
            .unwrap()
            .unwrap();
        enter(&mut stream, &ar, object, right, &mut 0).unwrap();
        assert_eq!(stream.active_frames(), 2);
        let reused = stream.reuse(handle);
        if max_frames == 3 {
            assert_eq!(reused, Err(Error::Limit));
            assert!(stream.is_poisoned());
        } else {
            reused.unwrap();
            emit(&mut stream, &ar, &records, 6, &mut 0);
            finish(&mut stream, &ar, records[7].candidate.result, None, &mut 0).unwrap();
            finish(&mut stream, &ar, records[8].candidate.result, None, &mut 0).unwrap();
            let done = stream.bind_terminal(claim(&ar, records[8])).unwrap();
            assert_eq!(
                (done.summary().occurrences(), done.summary().peak_frames()),
                (9, 4)
            );
        }
    }
}

#[test]
fn hash_outputs_require_all_limbs_and_exact_pair_of_pairs_topology() {
    for tag in [0, 15] {
        let mut ar = Arena::try_new_boxed().unwrap();
        let object = atom(&mut ar, 123);
        let body = if tag == 0 {
            atom(&mut ar, 0)
        } else {
            op(&mut ar, 1, object)
        };
        let formula = op(&mut ar, tag, body);
        let mut records = Vec::new();
        derive(&mut ar, object, formula, &mut records);
        let c = records.last().unwrap().candidate;
        let (left, right) = pair(&ar, c.result);
        let (h0, h1) = pair(&ar, left);
        let (h2, h3) = pair(&ar, right);
        let original = [h0, h1, h2, h3];
        let mut wrongs = vec![
            ar.pair(left, h2).unwrap(),
            ar.pair(h0, right).unwrap(),
            ar.pair(right, left).unwrap(),
        ];
        for limb in 0..4 {
            let mut changed = original;
            let changed_value = ar.atom_value(original[limb]).unwrap().as_u64() ^ 1;
            changed[limb] = atom(&mut ar, changed_value);
            let left = ar.pair(changed[0], changed[1]).unwrap();
            let right = ar.pair(changed[2], changed[3]).unwrap();
            wrongs.push(ar.pair(left, right).unwrap());
        }
        for wrong in wrongs {
            let mut stream = SemanticStream::new(key(&ar, object, formula), limits()).unwrap();
            enter(&mut stream, &ar, object, formula, &mut 0).unwrap();
            for &child in c.premises.as_slice() {
                emit(&mut stream, &ar, &records, child, &mut 0);
            }
            assert_eq!(
                finish(&mut stream, &ar, wrong, None, &mut 0),
                Err(Error::Output)
            );
        }
    }
}

#[test]
fn pair_arguments_and_wide_words_reject_at_the_primitive_boundary() {
    for tag in [4, 5, 6, 7, 8, 10, 11, 12, 13, 14] {
        for wide in [false, true] {
            if wide && ![11, 12, 13, 14].contains(&tag) {
                continue;
            }
            let mut ar = Arena::try_new_boxed().unwrap();
            let object = atom(&mut ar, 0);
            let value = if wide {
                atom(&mut ar, 1 << 32)
            } else {
                ar.pair(object, object).unwrap()
            };
            let bad = op(&mut ar, 1, value);
            let good = quote(&mut ar, 1);
            let formula = match tag {
                4 => branch(&mut ar, bad, good, good),
                8 | 13 => op(&mut ar, tag, bad),
                _ => binary(&mut ar, tag, good, bad),
            };
            let mut stream = SemanticStream::new(key(&ar, object, formula), limits()).unwrap();
            enter(&mut stream, &ar, object, formula, &mut 0).unwrap();
            if ![4, 8, 13].contains(&tag) {
                let (_, result) = pair(&ar, good);
                enter(&mut stream, &ar, object, good, &mut 0).unwrap();
                finish(&mut stream, &ar, result, None, &mut 0).unwrap();
            }
            enter(&mut stream, &ar, object, bad, &mut 0).unwrap();
            assert_eq!(
                finish(&mut stream, &ar, value, None, &mut 0),
                Err(Error::Type)
            );
            assert!(stream.is_poisoned());
        }
    }
}

#[test]
fn malformed_enter_noun_indices_and_noncanonical_root_reject() {
    let mut ar = Arena::try_new_boxed().unwrap();
    let object = atom(&mut ar, 0);
    let one = atom(&mut ar, 1);
    let pair_tag = ar.pair(object, one).unwrap();
    let address = atom(&mut ar, 2);
    for (formula, error) in [
        (object, Error::Shape),
        (op(&mut ar, 0, address), Error::Shape),
        (ar.pair(pair_tag, object).unwrap(), Error::Type),
        (op(&mut ar, 3, object), Error::Shape),
    ] {
        let mut stream = SemanticStream::new(key(&ar, object, formula), limits()).unwrap();
        assert_eq!(enter(&mut stream, &ar, object, formula, &mut 0), Err(error));
    }
    let q = quote(&mut ar, 7);
    let root = key(&ar, object, q);
    for field in 0..2 {
        for limb in 0..4 {
            let mut changed = root;
            if field == 0 {
                changed.object[limb] = nebu::field::P;
            } else {
                changed.formula[limb] = nebu::field::P;
            }
            assert!(matches!(
                SemanticStream::new(changed, limits()),
                Err(Error::Key)
            ));
        }
    }
    let (memory, ids) = snapshot(&ar, &[object, q], 0);
    let view = memory.view(memory.len()).unwrap();
    let mut stream = SemanticStream::new(root, limits()).unwrap();
    assert_eq!(stream.enter(&view, ids[0], memory.len()), Err(Error::Noun));
    let mut stream = SemanticStream::new(root, limits()).unwrap();
    stream.enter(&view, ids[0], ids[1]).unwrap();
    assert_eq!(stream.finish(&view, memory.len(), None), Err(Error::Noun));
}
