use super::*;
use std::collections::BTreeMap;

fn bad_rows(component: &Component, w: &CCSWitness) -> Vec<usize> {
    let matrices = &component.parts.instance.matrices;
    let a = matrices[0].mul_vec(&w.z);
    let b = matrices[1].mul_vec(&w.z);
    let c = matrices[2].mul_vec(&w.z);
    (0..a.len()).filter(|&i| a[i] * b[i] != c[i]).collect()
}

// Adversarially re-evaluate downstream candidate wires after fixing selected
// auxiliary cells. Satisfaction is checked independently against CCS rows.
fn replay(component: &Component, w: &mut CCSWitness, overrides: &BTreeMap<Wire, F>) {
    for (offset, op) in component.parts.ops.iter().enumerate() {
        let wire = 2 + INPUT_FIELDS + offset;
        w.z[wire] = if let Some(&forced) = overrides.get(&wire) {
            forced
        } else {
            match op {
                Op::Linear(l) => l.iter().fold(F::ZERO, |sum, &(i, c)| sum + w.z[i] * c),
                Op::Product(a, b) => w.z[*a] * w.z[*b],
                Op::Bit(a, k) => F::new((w.z[*a].canonicalize().as_u64() >> k) & 1),
                Op::Inverse(a) => {
                    if w.z[*a] == F::ZERO {
                        F::ZERO
                    } else {
                        w.z[*a].inv()
                    }
                }
            }
        };
    }
}

#[test]
fn forged_input_with_updated_public_premise_still_violates_rows() {
    let component = build(MAX_GATES).unwrap();
    let mut ar = Reduction::<1024>::new();
    let q = quote(&mut ar, 42);
    let root = binary(&mut ar, 3, q, q);
    let good = inputs(&ar, root);
    valid(&component, &good);
    for index in [0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 1 + 18, 1 + 3 * 18] {
        let mut changed = good.clone();
        changed[index] = (changed[index] + 1) % nebu::field::P;
        let w = witness(&component, &changed);
        assert!(
            pins(&changed)
                .iter()
                .all(|&(i, expected)| w.z[i] == expected)
        );
        assert!(
            !component.parts.instance.is_satisfied_by(&w),
            "mutated input {index}"
        );
    }
}

#[test]
fn all_digest_limbs_padding_tags_and_disabled_mandatory_ports_are_constrained() {
    let c = build(MAX_GATES).unwrap();
    let mut ar = Reduction::<1024>::new();
    let test = quote(&mut ar, 0);
    let yes = quote(&mut ar, 10);
    let no = quote(&mut ar, 20);
    let root = branch(&mut ar, test, yes, no);
    let good = inputs(&ar, root);
    valid(&c, &good);
    for row in 0..7 {
        for field in [0, 1, 2, 3, 4, 5, 6, 15] {
            let mut bad = good.clone();
            let index = 1 + row * RECORD_FIELDS + field;
            bad[index] = if matches!(field, 0 | 1 | 15) {
                2
            } else {
                (bad[index] + 1) % nebu::field::P
            };
            assert!(
                !c.parts.instance.is_satisfied_by(&witness(&c, &bad)),
                "record{row} field{field}"
            );
        }
        for field in [16, 17] {
            let mut bad = good.clone();
            bad[1 + row * RECORD_FIELDS + field] = 1 << 32;
            assert!(
                !c.parts.instance.is_satisfied_by(&witness(&c, &bad)),
                "wide Cost limb record{row} field{field}"
            );
        }
    }
    for row in 1..7 {
        let mut bad = good.clone();
        bad[1 + row * RECORD_FIELDS..1 + (row + 1) * RECORD_FIELDS].fill(0);
        assert!(
            !c.parts.instance.is_satisfied_by(&witness(&c, &bad)),
            "disabled required port{row}"
        );
    }
    let mut reversed = good.clone();
    for i in 0..4 {
        reversed.swap(1 + 7 + i, 1 + 11 + i);
    }
    assert!(!c.parts.instance.is_satisfied_by(&witness(&c, &reversed)));
    let mut inactive = std::iter::once(VERSION).chain([0; 126]).collect::<Vec<_>>();
    for field in 0..RECORD_FIELDS {
        inactive[1 + 6 * RECORD_FIELDS + field] = 1;
        assert!(!c.parts.instance.is_satisfied_by(&witness(&c, &inactive)));
        inactive[1 + 6 * RECORD_FIELDS + field] = 0;
    }
}

#[test]
fn unused_pair_costs_remain_explicit_public_premises() {
    let c = build(MAX_GATES).unwrap();
    let mut ar = Reduction::<1024>::new();
    let q = quote(&mut ar, 42);
    let root = branch(&mut ar, q, q, q);
    let mut supplied = inputs(&ar, root);
    let original = supplied.clone();
    // R and B are read to obtain child particles/shapes; their cached Cost is
    // not an operand of branch's local Cost equation. A different public Cost
    // premise remains admissible until authenticated memory derives it.
    supplied[1 + 2 * RECORD_FIELDS + 16] += 7;
    supplied[1 + 4 * RECORD_FIELDS + 16] += 11;
    let w = valid(&c, &supplied);
    assert!(pins(&original).iter().any(|&(i, value)| w.z[i] != value));
}

#[test]
fn equal_particle_conflicting_cost_rejects_even_with_consistent_parent_arithmetic() {
    let c = build(MAX_GATES).unwrap();
    let mut ar = Reduction::<1024>::new();
    let q = quote(&mut ar, 42);
    let root = binary(&mut ar, 3, q, q);
    let mut supplied = inputs(&ar, root);
    supplied[1 + 3 * RECORD_FIELDS + 16] = 5; // A and B have the same valid header.
    supplied[1 + 16] = 7; // Correct local sum for the forged premises: 1+5+1.
    let forged = witness(&c, &supplied);
    assert!(pins(&supplied).iter().all(|&(i, v)| forged.z[i] == v));
    assert_eq!(
        bad_rows(&c, &forged).len(),
        1,
        "only the local coherence equation rejects"
    );
}

#[test]
fn forged_auxiliary_bits_inverse_and_requests_reject_with_public_inputs_unchanged() {
    let c = build(MAX_GATES).unwrap();
    let mut ar = Reduction::<1024>::new();
    let q = quote(&mut ar, 42);
    let root = binary(&mut ar, 3, q, q);
    let supplied = inputs(&ar, root);
    let w = valid(&c, &supplied);
    for read in c.pending.reads {
        for wire in read.requested_particle {
            let mut changed = w.clone();
            changed.z[wire] += F::ONE;
            assert!(!c.parts.instance.is_satisfied_by(&changed));
        }
    }
    for kind in 0..3 {
        let offset = c
            .parts
            .ops
            .iter()
            .position(|op| match (kind, op) {
                (0, Op::Bit(_, _)) | (2, Op::Product(_, _)) => true,
                (1, Op::Inverse(input)) => w.z[*input] == F::ZERO,
                _ => false,
            })
            .unwrap();
        let wire = 2 + INPUT_FIELDS + offset;
        let mut changed = w.clone();
        replay(
            &c,
            &mut changed,
            &BTreeMap::from([(wire, w.z[wire] + F::ONE)]),
        );
        assert!(pins(&supplied).iter().all(|&(i, v)| changed.z[i] == v));
        assert!(
            !c.parts.instance.is_satisfied_by(&changed),
            "forged auxiliary kind{kind}"
        );
    }
}

#[test]
fn noncanonical_atom_alias_rejects_after_forged_digest_and_public_premises_are_updated() {
    let c = build(MAX_GATES).unwrap();
    for value in [0, 1] {
        let mut ar = Reduction::<1024>::new();
        let root = atom(&mut ar, value);
        let supplied = inputs(&ar, root);
        let mut changed = valid(&c, &supplied);
        let alias = value + nebu::field::P;
        let value_wire = c.pending.candidate.value;
        let overrides: BTreeMap<_, _> = c
            .parts
            .ops
            .iter()
            .enumerate()
            .filter_map(|(offset, op)| {
                if let Op::Bit(input, bit) = op {
                    if *input == value_wire {
                        return Some((2 + INPUT_FIELDS + offset, F::new((alias >> bit) & 1)));
                    }
                }
                None
            })
            .collect();
        assert_eq!(overrides.len(), 64);
        replay(&c, &mut changed, &overrides);
        // Update all claimed digest limbs to the forged bit-representation
        // digest, then recompute everything. Hash/public mismatches cannot be
        // the reason this candidate rejects: the canonicality row must reject.
        for particle in c.pending.candidate.particle {
            let right = c.parts.instance.matrices[1]
                .entries
                .iter()
                .enumerate()
                .find_map(|(row, terms)| {
                    if terms.len() == 2
                        && terms[0] == (particle, F::ONE)
                        && terms[1].1 == -F::ONE
                        && c.parts.instance.matrices[0].entries[row] == vec![(ONE, F::ONE)]
                        && c.parts.instance.matrices[2].entries[row].is_empty()
                    {
                        Some(terms[1].0)
                    } else {
                        None
                    }
                })
                .unwrap();
            changed.z[particle] = changed.z[right];
        }
        replay(&c, &mut changed, &overrides);
        let updated: Vec<u64> = changed.z[2..2 + INPUT_FIELDS]
            .iter()
            .map(|x| x.as_u64())
            .collect();
        assert!(pins(&updated).iter().all(|&(i, v)| changed.z[i] == v));
        assert_eq!(
            bad_rows(&c, &changed).len(),
            1,
            "canonicality alone must reject x+p"
        );
    }
}
