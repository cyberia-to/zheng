use super::super::uint64::U64;
use super::*;

fn limb_inputs(a: u64, b: u64) -> [u64; 4] {
    [a & u32::MAX as u64, a >> 32, b & u32::MAX as u64, b >> 32]
}

#[test]
fn limb_add_and_max_cross_field_modulus_and_saturate_exactly() {
    let mut builder = Builder::new(4);
    let a = U64 { lo: 2, hi: 3 };
    let b = U64 { lo: 4, hi: 5 };
    let sum = builder.saturating_u64_add(a, b).unwrap();
    let max = builder.max_u64(a, b).unwrap();
    let p = builder.component_parts();
    let values = [
        0,
        1,
        u32::MAX as u64,
        1 << 32,
        1 << 63,
        nebu::field::P - 1,
        nebu::field::P,
        nebu::field::P + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    for a in values {
        for b in values {
            let w = candidate_witness(&p.instance, 4, &p.ops, &limb_inputs(a, b)).unwrap();
            assert!(p.instance.is_satisfied_by(&w));
            let read = |value: U64| w.z[value.lo].as_u64() | (w.z[value.hi].as_u64() << 32);
            assert_eq!(read(sum), a.saturating_add(b));
            assert_eq!(read(max), a.max(b));
            for wire in [sum.lo, sum.hi, max.lo, max.hi] {
                let mut bad = w.clone();
                bad.z[wire] += F::ONE;
                assert!(!p.instance.is_satisfied_by(&bad));
            }
        }
    }
    let w = candidate_witness(&p.instance, 4, &p.ops, &limb_inputs(u64::MAX, 1)).unwrap();
    // Every arithmetic auxiliary wire must be constrained, including carry,
    // overflow and the comparison selector. No public-value check is involved.
    for wire in 6..6 + p.ops.len() {
        let mut bad = w.clone();
        bad.z[wire] += F::ONE;
        assert!(
            !p.instance.is_satisfied_by(&bad),
            "unconstrained arithmetic wire {wire}"
        );
    }
    let bad = candidate_witness(&p.instance, 4, &p.ops, &[1 << 32, 0, 0, 0]).unwrap();
    assert!(
        !p.instance.is_satisfied_by(&bad),
        "wide limb must reject algebraically"
    );
}

#[test]
fn branch_dynamic_propagates_from_smaller_arm_and_max_keeps_both_limbs() {
    let c = build(MAX_GATES).unwrap();
    let mut ar = Reduction::<1024>::new();
    let q = quote(&mut ar, 77);
    let dynamic = binary(&mut ar, 2, q, q);
    let mut large = q;
    for _ in 0..40 {
        large = binary(&mut ar, 3, large, large);
    }
    for (yes, no) in [(dynamic, large), (large, dynamic)] {
        let root = branch(&mut ar, q, yes, no);
        let mut supplied = inputs(&ar, root);
        assert_eq!(supplied[1 + 15], 1);
        valid(&c, &supplied);
        supplied[1 + 15] = 0;
        assert!(!c.parts.instance.is_satisfied_by(&witness(&c, &supplied)));
    }
}

#[test]
fn shared_native_dag_reaches_u64_saturation_without_tree_expansion() {
    let component = build(MAX_GATES).unwrap();
    let mut ar = Reduction::<1024>::new();
    let mut root = quote(&mut ar, 0);
    for depth in 1..=66 {
        root = binary(&mut ar, 3, root, root);
        valid(&component, &inputs(&ar, root));
        if depth >= 63 {
            assert_eq!(ar.get(root).unwrap().bound.value(), u64::MAX);
        }
    }
    assert!(ar.count() < 150);
}
