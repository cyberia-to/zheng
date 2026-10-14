use super::*;
use nebu::Goldilocks as F;

/// Native nox: reduce `formula` on `subject` with pure Layer-1 dispatch
/// (no jets); the output noun and the cycles spent.
pub(crate) fn nox_run(subject: &N, formula: &N) -> Result<(N, u64), String> {
    const BUDGET: u64 = 1 << 40;
    fn into<const S: usize>(r: &mut nox::Reduction<S>, n: &N) -> nox::Order {
        match n {
            N::Atom(v) => r.atom(F::new(*v)).expect("arena"),
            N::Pair(a, b) => {
                let (a, b) = (into(r, a), into(r, b));
                r.pair(a, b).expect("arena")
            }
        }
    }
    fn out<const S: usize>(r: &nox::Reduction<S>, o: nox::Order) -> N {
        match r.get(o).expect("noun").inner {
            nox::data::Data::Pair { left, right } => pr(out(r, left), out(r, right)),
            _ => N::Atom(r.atom_value(o).expect("atom").as_u64()),
        }
    }
    let (subject, formula) = (subject.clone(), formula.clone());
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            let mut r = Box::new(nox::Reduction::<{ 1 << 20 }>::new());
            let s = into(&mut r, &subject);
            let f = into(&mut r, &formula);
            match nox::reduce(
                &mut r,
                s,
                f,
                BUDGET,
                &nox::call::NullCalls,
                &mut nox::trace::NoTrace,
            ) {
                nox::Outcome::Ok(o, left) => Ok((out(&r, o), BUDGET - left)),
                other => Err(format!("{other:?}")),
            }
        })
        .expect("thread")
        .join()
        .expect("nox run")
}

/// A splitmix stream of field elements.
pub(crate) fn limbs(seed: &mut u64) -> [u64; 4] {
    core::array::from_fn(|_| {
        *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) % nebu::field::P
    })
}

fn subject(l: [u64; 4], r: [u64; 4], flags: u64) -> N {
    pr(pr(digest_noun(l), digest_noun(r)), at(flags))
}

#[test]
fn native_node_is_hemera_hash_node() {
    let mut seed = 1;
    for _ in 0..8 {
        let (l, r) = (limbs(&mut seed), limbs(&mut seed));
        let bytes = |d: [u64; 4]| {
            let mut b = [0u8; 32];
            for i in 0..4 {
                b[8 * i..8 * i + 8].copy_from_slice(&d[i].to_le_bytes());
            }
            hemera::Hash::from_bytes(b)
        };
        for (flags, root) in [(FLAGS_NODE, false), (FLAGS_ROOT, true)] {
            let h = hemera::tree::hash_node(&bytes(l), &bytes(r), root);
            let want: [u64; 4] = core::array::from_fn(|i| {
                u64::from_le_bytes(h.as_bytes()[8 * i..8 * i + 8].try_into().unwrap())
            });
            assert_eq!(native(l, r, flags), want);
        }
        let lg = l.map(F::new);
        let rg = r.map(F::new);
        assert_eq!(
            native(l, r, FLAGS_NODE),
            nox::data::hash::hash_pair(&lg, &rg).map(|v| v.as_u64())
        );
    }
}

#[test]
fn the_formula_is_the_node_and_its_cost_is_constant() {
    let mut seed = 7;
    let mut cases = vec![
        ([0; 4], [0; 4], FLAGS_NODE),
        ([nebu::field::P - 1; 4], [1, 0, 0, 0], FLAGS_ROOT),
    ];
    for k in 0..4 {
        cases.push((
            limbs(&mut seed),
            limbs(&mut seed),
            if k % 2 == 0 { FLAGS_NODE } else { FLAGS_ROOT },
        ));
    }
    for (l, r, flags) in cases {
        let (output, cost) =
            nox_run(&subject(l, r, flags), formula()).expect("node formula reduces");
        assert_eq!(
            output,
            digest_noun(native(l, r, flags)),
            "{l:?} {r:?} {flags}"
        );
        assert_eq!(cost, COST, "cycles");
    }
}

#[test]
fn the_formula_fits_a_program() {
    let tokens = crate::execution::ExecutionStatement::encode_program(formula()).unwrap();
    println!("node formula {} nodes", tokens.len());
    // 2,235 nodes: room for a depth-32 path and its program under 4,096
    assert!(tokens.len() <= 2_240, "{} nodes", tokens.len());
}

#[test]
fn the_formula_nests_shallowly_enough_for_a_program() {
    fn depth(n: &N) -> usize {
        match n {
            N::Atom(_) => 0,
            N::Pair(a, b) => 1 + depth(a).max(depth(b)),
        }
    }
    let d = depth(formula());
    // the statement admits 128; a program holds the formula a few levels down
    assert!(d <= 48, "{d}");
    println!("node formula depth {d}");
}
