use super::*;

pub(crate) fn table(namespace: u64, body: &[u64]) -> StateTable {
    StateTable::with_body(namespace, body)
}

pub(crate) fn evidence(tables: Vec<StateTable>) -> StateEvidence {
    StateEvidence::with_tables(tables)
}

/// bbg `root.rs` frozen vectors (zheng 0.4 `ccs::root_from_leaves`).
#[test]
fn root_matches_the_bbg_frozen_vectors() {
    let mut sample = [[0u64; 4]; LEAVES];
    for (d, leaf) in sample.iter_mut().enumerate().take(11) {
        *leaf = core::array::from_fn(|k| (d * 4 + k + 1) as u64);
    }
    sample[11] = [101, 102, 103, 104];
    sample[12] = [201, 202, 203, 204];
    sample[13] = [301, 302, 303, 304];
    assert_eq!(
        state_root_of(&sample),
        [1839648704373557657, 16245063762079522430, 2767124943183982576, 17812001250628018905]
    );
    assert_eq!(
        state_root_of(&[[0; 4]; LEAVES]),
        [9231417576306038954, 11425091536555908058, 3672555888010110395, 14299998217756054807]
    );
}

#[test]
fn reads_answer_only_under_the_authenticated_root() {
    let e = evidence(vec![table(0, &[10, 11, 12]), table(2, &[42])]);
    let root = e.root().unwrap();
    let state = e.authenticate(root).unwrap();
    assert_eq!(state.cell(0, 4), Some(11));
    assert_eq!(state.cell(2, 3), Some(42));
    assert_eq!(state.cell(1, 0), None, "a table the evidence lacks");
    assert_eq!(state.cell(0, 6), None, "past the end");
    let mut other = root;
    other[0] = (other[0] + 1) % nebu::field::P;
    assert!(e.authenticate(other).is_err());
}

#[test]
fn every_forgery_of_the_evidence_is_rejected() {
    let honest = evidence(vec![table(0, &[10, 11, 12]), table(2, &[42])]);
    let root = honest.root().unwrap();
    type Edit = Box<dyn Fn(&mut StateEvidence)>;
    let forged: Vec<(&str, Edit)> = vec![
        ("value", Box::new(|e| e.tables[1].fields[3] = 43)),
        ("appended zero", Box::new(|e| e.tables[0].fields.push(0))),
        ("appended zero, header fixed", Box::new(|e| {
            e.tables[0].fields.push(0);
            e.tables[0].fields[1] += 1;
        })),
        ("version", Box::new(|e| e.tables[0].fields[0] = 3)),
        ("namespace moved", Box::new(|e| e.tables[1].namespace = 3)),
        ("leaf", Box::new(|e| e.leaves[13][0] += 1)),
        ("duplicate table", Box::new(|e| {
            let t = e.tables[0].clone();
            e.tables.insert(0, t);
        })),
        ("noncanonical leaf", Box::new(|e| e.leaves[5][0] = nebu::field::P)),
    ];
    for (name, edit) in forged {
        let mut e = honest.clone();
        edit(&mut e);
        assert!(e.authenticate(root).is_err(), "{name}");
    }
}
