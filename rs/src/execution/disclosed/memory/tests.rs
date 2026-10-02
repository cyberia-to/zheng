use super::*;
use nebu::Goldilocks as F;
use nox::{Order, Reduction, data::Data};

const N: usize = 2048;

fn memory(max: u32) -> Memory {
    Memory::new(max, max as usize * size_of::<VerifiedNode>()).unwrap()
}

fn native(ar: &Reduction<N>, index: Order) -> Definition {
    let node = ar.get(index).unwrap();
    Definition {
        value: match node.inner {
            Data::Atom { value } => Value::Atom(value.as_u64()),
            Data::Pair { left, right } => Value::Pair { left, right },
        },
        particle: node.hash.map(F::as_u64),
        cost: if node.bound.is_dynamic() {
            Cost::Dynamic(node.bound.value())
        } else {
            Cost::Exact(node.bound.value())
        },
    }
}

fn import(ar: &Reduction<N>) -> Memory {
    let mut table = memory(ar.count());
    for i in 0..ar.count() {
        assert_eq!(table.append(native(ar, i)), Ok(i));
    }
    table
}

fn atom(ar: &mut Reduction<N>, value: u64) -> Order {
    ar.atom(F::new(value)).unwrap()
}

fn op(ar: &mut Reduction<N>, tag: u64, body: Order) -> Order {
    let tag = atom(ar, tag);
    ar.pair(tag, body).unwrap()
}

fn binary(ar: &mut Reduction<N>, tag: u64, a: Order, b: Order) -> Order {
    let body = ar.pair(a, b).unwrap();
    op(ar, tag, body)
}

#[test]
fn canonical_atom_and_particle_domains_reject_aliases() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    for value in [0, 1, nebu::field::P - 1] {
        atom(&mut ar, value);
    }
    let table = import(&ar);
    assert_eq!(table.len(), 3);
    let mut table = memory(16);
    for value in [nebu::field::P, u64::MAX] {
        let invalid = Definition {
            value: Value::Atom(value),
            particle: [0; 4],
            cost: Cost::Exact(0),
        };
        assert_eq!(table.append(invalid), Err(Error::NonCanonical));
        assert!(table.is_empty());
    }
    for i in 0..4 {
        let mut invalid = native(&ar, 0);
        invalid.particle[i] = nebu::field::P;
        assert_eq!(table.append(invalid), Err(Error::NonCanonical));
        invalid.particle = native(&ar, 0).particle;
        invalid.particle[i] ^= 1;
        assert_eq!(table.append(invalid), Err(Error::Particle));
        assert!(table.is_empty());
    }
}

#[test]
fn native_headers_and_every_cost_case_are_derived_from_prior_records() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    let data = atom(&mut ar, 42);
    let quote = op(&mut ar, 1, data);
    let dyn_f = binary(&mut ar, 2, quote, quote);
    for tag in (0..20).chain([nebu::field::P - 1]) {
        op(&mut ar, tag, data); // malformed binary/branch bodies
        op(&mut ar, tag, quote);
        binary(&mut ar, tag, quote, quote);
        binary(&mut ar, tag, dyn_f, quote);
        binary(&mut ar, tag, quote, dyn_f);
        let arms = ar.pair(quote, dyn_f).unwrap();
        binary(&mut ar, tag, quote, arms);
        let arms = ar.pair(dyn_f, quote).unwrap();
        binary(&mut ar, tag, dyn_f, arms);
    }
    ar.pair(quote, data).unwrap(); // non-atom head
    let table = import(&ar);
    for index in 0..ar.count() {
        assert_eq!(
            table.view(table.len()).unwrap().get(index).unwrap().0,
            native(&ar, index)
        );
    }
}

#[test]
fn ordered_topology_and_strict_prior_references_are_checked_atomically() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    let a = atom(&mut ar, 42);
    let b = atom(&mut ar, 43);
    let pair = ar.pair(a, b).unwrap();
    let mut table = memory(16);
    table.append(native(&ar, a)).unwrap();
    table.append(native(&ar, b)).unwrap();
    let prior: Vec<_> = table.nodes.clone();
    let original = native(&ar, pair);
    for value in [
        Value::Pair { left: b, right: a },
        Value::Atom(42),
        Value::Pair {
            left: pair,
            right: a,
        },
        Value::Pair {
            left: a,
            right: pair + 1,
        },
        Value::Pair {
            left: u32::MAX,
            right: a,
        },
        Value::Pair {
            left: a,
            right: u32::MAX,
        },
    ] {
        assert!(table.append(Definition { value, ..original }).is_err());
        assert_eq!(table.nodes, prior);
    }
    assert_eq!(table.append(original), Ok(pair));
}

#[test]
fn all_cost_bits_and_dynamic_selector_are_authenticated_even_for_quoted_data() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    let data = atom(&mut ar, 42);
    let q = op(&mut ar, 1, data);
    let mut table = memory(256);
    for i in 0..q {
        table.append(native(&ar, i)).unwrap();
    }
    let correct = native(&ar, q);
    for cost in [
        Cost::Exact(0),
        Cost::Exact(2),
        Cost::Exact(1u64 << 32 | 1),
        Cost::Exact(u64::MAX),
        Cost::Dynamic(1),
    ] {
        assert_eq!(
            table.append(Definition { cost, ..correct }),
            Err(Error::Cost)
        );
        assert_eq!(table.len(), q);
    }
    table.append(correct).unwrap();
    let dynamic = binary(&mut ar, 2, q, q);
    for i in table.len()..dynamic {
        table.append(native(&ar, i)).unwrap();
    }
    let correct = native(&ar, dynamic);
    assert_eq!(
        table.append(Definition {
            cost: Cost::Exact(correct.cost.value()),
            ..correct
        }),
        Err(Error::Cost)
    );
    assert_eq!(table.append(correct), Ok(dynamic));
}

#[test]
fn saturated_u64_costs_do_not_wrap_or_reduce_in_the_field() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    let data = atom(&mut ar, 42);
    let mut f = op(&mut ar, 1, data);
    let mut crossed_field = false;
    let mut crossed_limb = false;
    for _ in 0..66 {
        f = binary(&mut ar, 3, f, f);
        let value = ar.get(f).unwrap().bound.value();
        crossed_limb |= value > u32::MAX as u64;
        crossed_field |= value >= nebu::field::P;
    }
    assert!(crossed_limb && crossed_field);
    assert_eq!(ar.get(f).unwrap().bound, nox::data::Cost::Exact(u64::MAX));
    let table = import(&ar);
    assert_eq!(table.node(f).unwrap().cost(), Cost::Exact(u64::MAX));
}

#[test]
fn duplicate_occurrences_preserve_content_identity_and_cost() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    let a = atom(&mut ar, 1);
    let b = atom(&mut ar, 42);
    let p = ar.pair(a, b).unwrap();
    let mut table = memory(16);
    for i in 0..ar.count() {
        table.append(native(&ar, i)).unwrap();
    }
    let a2 = table.append(native(&ar, a)).unwrap();
    let b2 = table.append(native(&ar, b)).unwrap();
    let p2 = table
        .append(Definition {
            value: Value::Pair {
                left: a2,
                right: b2,
            },
            ..native(&ar, p)
        })
        .unwrap();
    assert_ne!(p, p2);
    assert_eq!(
        table.node(p).unwrap().particle(),
        table.node(p2).unwrap().particle()
    );
    assert_eq!(
        table.node(p).unwrap().cost(),
        table.node(p2).unwrap().cost()
    );
    let forged = Definition {
        cost: Cost::Dynamic(1),
        ..native(&ar, p)
    };
    assert_eq!(table.append(forged), Err(Error::Cost));
}

#[test]
fn views_reject_future_reads_and_bind_every_expected_root_limb() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    let a = atom(&mut ar, 42);
    let b = atom(&mut ar, 43);
    let table = import(&ar);
    assert!(matches!(table.view(3), Err(Error::Reference)));
    let view = table.view(1).unwrap();
    assert_eq!(view.get(b), Err(Error::Reference));
    assert_eq!(view.get(u32::MAX), Err(Error::Reference));
    let expected = native(&ar, a).particle;
    assert!(view.bind(a, expected).is_ok());
    for i in 0..4 {
        let mut wrong = expected;
        wrong[i] ^= 1;
        assert_eq!(view.bind(a, wrong), Err(Error::Particle));
    }
    assert_eq!(table.view(0).unwrap().get(0), Err(Error::Reference));
}

#[test]
fn record_and_buffer_limits_accept_exact_capacity_and_fail_closed_below() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    for value in 0..65 {
        atom(&mut ar, value);
    }
    let bytes = 65 * size_of::<VerifiedNode>();
    assert!(matches!(Memory::new(65, bytes - 1), Err(Error::Limit)));
    let mut table = Memory::new(65, bytes).unwrap();
    for i in 0..65 {
        table.append(native(&ar, i)).unwrap();
        assert!(table.buffer_bytes() <= bytes);
    }
    let before = table.nodes.clone();
    assert_eq!(table.append(native(&ar, 0)), Err(Error::Limit));
    assert_eq!(table.nodes, before);
    let mut zero = Memory::new(0, 0).unwrap();
    assert_eq!(zero.append(native(&ar, 0)), Err(Error::Limit));
    assert_eq!(zero.buffer_bytes(), 0);
}

fn exact_bound(
    ar: &mut Reduction<N>,
    value: u64,
    cache: &mut std::collections::BTreeMap<u64, Order>,
) -> Order {
    if let Some(&id) = cache.get(&value) {
        return id;
    }
    let id = if value == 0 {
        atom(ar, 42)
    } else {
        let a = exact_bound(ar, value / 2, cache);
        let b = exact_bound(ar, (value - 1) / 2, cache);
        binary(ar, 3, a, b)
    };
    assert_eq!(ar.get(id).unwrap().bound, nox::data::Cost::Exact(value));
    cache.insert(value, id);
    id
}

#[test]
fn non_saturated_costs_above_the_field_keep_both_limbs_authenticated() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    let mut cache = std::collections::BTreeMap::new();
    for value in [
        1u64 << 32,
        nebu::field::P - 1,
        nebu::field::P,
        nebu::field::P + 17,
        u64::MAX - 1,
    ] {
        let id = exact_bound(&mut ar, value, &mut cache);
        let mut table = memory(ar.count() + 1);
        for i in 0..ar.count() {
            table.append(native(&ar, i)).unwrap();
        }
        let good = native(&ar, id);
        for cost in [
            Cost::Exact(value ^ 1),
            Cost::Exact(value ^ (1 << 32)),
            Cost::Exact(value % nebu::field::P),
            Cost::Dynamic(value),
        ] {
            // Reduction modulo p equals the original below p.
            if cost == good.cost {
                continue;
            }
            assert_eq!(table.append(Definition { cost, ..good }), Err(Error::Cost));
            assert_eq!(table.len(), ar.count());
        }
        assert_eq!(table.append(good), Ok(ar.count()));
    }
}

#[test]
fn dynamic_metadata_survives_smaller_branch_arms_and_saturation() {
    let mut ar = Reduction::<N>::try_new_boxed().unwrap();
    let mut cache = std::collections::BTreeMap::new();
    let zero = exact_bound(&mut ar, 0, &mut cache);
    let small = binary(&mut ar, 2, zero, zero);
    let large = exact_bound(&mut ar, 1000, &mut cache);
    for (yes, no) in [(small, large), (large, small)] {
        let arms = ar.pair(yes, no).unwrap();
        let branch = binary(&mut ar, 4, zero, arms);
        assert_eq!(
            ar.get(branch).unwrap().bound,
            nox::data::Cost::Dynamic(1001)
        );
    }
    let max = exact_bound(&mut ar, u64::MAX, &mut cache);
    let saturated = binary(&mut ar, 2, max, max);
    assert_eq!(
        ar.get(saturated).unwrap().bound,
        nox::data::Cost::Dynamic(u64::MAX)
    );
    let table = import(&ar);
    assert_eq!(
        table.node(saturated).unwrap().cost(),
        Cost::Dynamic(u64::MAX)
    );
}
