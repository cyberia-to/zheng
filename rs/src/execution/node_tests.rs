use super::*;
use nebu::Goldilocks as F;

/// Native nox: reduce `formula` on `subject` with pure Layer-1 dispatch
/// (no jets); the output noun and the cycles spent.
pub(crate) fn nox_run(subject: &N, formula: &N) -> Result<(N, u64), String> {
    nox_run_jets(subject, formula, false)
}

/// [`nox_run`], with the node jet registered when `jets`.
pub(crate) fn nox_run_jets(subject: &N, formula: &N, jets: bool) -> Result<(N, u64), String> {
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

#[test]
fn the_nox_jet_equals_the_formula_and_declines_off_shape() {
    let mut seed = 11;
    for flags in [FLAGS_NODE, FLAGS_ROOT, 0, nebu::field::P - 1] {
        let s = subject(limbs(&mut seed), limbs(&mut seed), flags);
        assert_eq!(nox_run_jets(&s, formula(), true), nox_run(&s, formula()));
    }
    // under a program: compose the node twice, jetted and pure agree
    let once = compose(ax(1), q(formula().clone()));
    let twice = compose(cons(cons(once.clone(), once), ax(3)), q(formula().clone()));
    let s = subject([1, 2, 3, 4], [5, 6, 7, 8], FLAGS_NODE);
    assert_eq!(nox_run_jets(&s, &twice, true), nox_run(&s, &twice));
    // off shape: the jet declines and pure dispatch fails the same way
    for bad in [
        pr(pr(at(1), digest_noun([1, 2, 3, 4])), at(2)),
        pr(
            pr(digest_noun([1, 2, 3, 4]), digest_noun([5, 6, 7, 8])),
            pr(at(2), at(2)),
        ),
        pr(
            pr(
                digest_noun([1, 2, 3, 4]),
                pr(digest_noun([5, 6, 7, 8]), at(0)),
            ),
            at(2),
        ),
    ] {
        let pure = nox_run(&bad, formula());
        assert!(pure.is_err());
        assert_eq!(nox_run_jets(&bad, formula(), true), pure);
    }
}

#[test]
fn the_nox_jet_fires() {
    // a 4,096-slot arena holds the jetted node; the pure formula needs
    // tens of thousands of nouns and runs out
    fn run(jets: bool) -> Option<u64> {
        let f = formula().clone();
        std::thread::Builder::new()
            .stack_size(1 << 26)
            .spawn(move || {
                let mut r = Box::new(nox::Reduction::<{ 1 << 12 }>::new());
                fn into<const S: usize>(r: &mut nox::Reduction<S>, n: &N) -> nox::Order {
                    match n {
                        N::Atom(v) => r.atom(F::new(*v)).expect("arena"),
                        N::Pair(a, b) => {
                            let (a, b) = (into(r, a), into(r, b));
                            r.pair(a, b).expect("arena")
                        }
                    }
                }
                let s = into(&mut r, &subject([1, 2, 3, 4], [5, 6, 7, 8], FLAGS_ROOT));
                let f = into(&mut r, &f);
                let mut registry = nox::JetRegistry::empty();
                if jets {
                    jet::register(&mut registry);
                }
                let calls = nox::call::NullCalls;
                match nox::reduce_with_registry(
                    &mut r,
                    s,
                    f,
                    1 << 40,
                    &calls,
                    &mut nox::trace::NoTrace,
                    &registry,
                ) {
                    nox::Outcome::Ok(_, left) => Some((1 << 40) - left),
                    _ => None,
                }
            })
            .unwrap()
            .join()
            .unwrap()
    }
    assert_eq!(run(true), Some(COST));
    assert_eq!(run(false), None);
}
