//! Adversarial review of the IVC speed changes (`audit/ivc-speed-2026-10.md`):
//! every IVC tree 4-ary, profile 6's IVC at rate 1/16, the field-native WHIR
//! schedules rebalanced for grinding work.
//!
//! - 4-ary paths: a spot opening's siblings permuted within a node group,
//!   a sibling taken from another level, another leaf's opening at a
//!   query's position, a path one node short or long, the decider's
//!   4-ary openings of the accumulator and key words tampered — refused;
//! - the zero accumulator's root is the 4-ary root of the committed zero
//!   word, so the base step's dummy opening is the honest one;
//! - the rebalanced schedules keep lens's queries and reach 128 bits on
//!   every term at every level of the shipped chain and the IVC decider.

mod common;

use nebu::{Fp3, Goldilocks};
use zheng::machine::{self, MachineStatement};
use zheng::recursion::ivc::{self, IvcProof};
use zheng::recursion::params::ARITY;
use zheng::recursion::word::{Arity, Word};

fn whir() -> lens::WhirParams {
    let mut w = zheng::execution::succinct::params_for(20);
    w.log_inv_rate = ivc::SHIPPED_RATE;
    w.pow_bits = ivc::SHIPPED_POW;
    w
}

fn proof(two_steps: bool) -> (MachineStatement, IvcProof) {
    let (prog, input) = if two_steps {
        (common::tree_program(12), vec![3])
    } else {
        (common::parse(common::ADD), vec![7, 5])
    };
    let run = machine::execute_exact(&prog, &input, 1 << 40, 15).unwrap();
    assert_eq!(run.segments(), if two_steps { 2 } else { 1 });
    let p = ivc::prove_run(&run, &whir()).unwrap();
    (run.statement, p)
}

/// `p` is refused natively; and its wire encoding, when it decodes, is
/// refused unless the encoding normalised it back to the honest proof
/// (the wire carries a multi-opening's distinct siblings once: a path
/// tampered only in its length or in sibling copies re-encodes to the
/// honest bytes).
fn refused(st: &MachineStatement, honest: &IvcProof, p: &IvcProof, what: &str) {
    let w = whir();
    assert!(ivc::verify(st, p, &w).is_err(), "{what}: accepted");
    let k = ivc::key(&w, 15).unwrap();
    let Ok(b) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.to_bytes(&k))) else {
        return;
    };
    if let Ok(q) = IvcProof::from_bytes(&b, |lr| ivc::key(&w, lr as usize)) {
        if &q != honest {
            assert!(
                ivc::verify(st, &q, &w).is_err(),
                "{what}: accepted after the wire"
            );
        }
    }
}

#[test]
fn four_ary_paths_bind_their_leaves_and_positions() {
    assert_eq!(ARITY, Arity::Four);
    // one step (the zero accumulator) and two (a committed accumulator)
    for two in [false, true] {
        attacks(two);
    }
}

fn attacks(two: bool) {
    let (st, p) = proof(two);
    ivc::verify(&st, &p, &whir()).unwrap();
    let q = p.step.acc.openings.len();
    for word in 0..4 {
        // siblings of the first 4-ary level swapped
        let mut bad = p.clone();
        bad.step.acc.openings[0][word].path.swap(0, 1);
        if bad != p {
            refused(&st, &p, &bad, &format!("word {word}: siblings swapped"));
        }
        // a sibling from the next level
        let mut bad = p.clone();
        let path = &mut bad.step.acc.openings[1][word].path;
        path[0] = path[3];
        if bad != p {
            refused(
                &st,
                &p,
                &bad,
                &format!("word {word}: sibling from another level"),
            );
        }
        // another query's opening at this position (another leaf; the
        // base step's zero accumulator has the same symbols and path at
        // every leaf, so its substitution is the honest opening)
        let o0 = &p.step.acc.openings[0][word];
        if let Some(other) = (1..q).find(|&j| {
            let oj = &p.step.acc.openings[j][word];
            oj.symbols != o0.symbols || oj.path != o0.path
        }) {
            let mut bad = p.clone();
            bad.step.acc.openings[0][word] = p.step.acc.openings[other][word].clone();
            refused(
                &st,
                &p,
                &bad,
                &format!("word {word}: another leaf's opening"),
            );
        } else {
            assert!(
                word == 0 && !two,
                "only the zero accumulator opens alike everywhere"
            );
        }
        // a path one node short, one node long
        let mut bad = p.clone();
        bad.step.acc.openings[2][word].path.pop();
        refused(&st, &p, &bad, &format!("word {word}: short path"));
        let mut bad = p.clone();
        let extra = bad.step.acc.openings[2][word].path[0];
        bad.step.acc.openings[2][word].path.push(extra);
        refused(&st, &p, &bad, &format!("word {word}: long path"));
    }
    // the decider's 4-ary openings: round 1's queries into the round-0
    // trees (accumulator, key words), and the final queries
    let mut bad = p.clone();
    bad.decider.whir.rounds[0].open[0][0].path.swap(0, 2);
    refused(&st, &p, &bad, "decider: accumulator tree siblings swapped");
    let mut bad = p.clone();
    let last = bad.decider.whir.rounds[0].open[0].len() - 1;
    bad.decider.whir.rounds[0].open[0][last].path[1][0] += Goldilocks::ONE;
    refused(&st, &p, &bad, "decider: key-word tree sibling");
    let mut bad = p.clone();
    bad.decider.whir.final_open[0][0].path.swap(0, 1);
    refused(&st, &p, &bad, "decider: final opening siblings swapped");
    let mut bad = p.clone();
    bad.decider.whir.final_open[0][0].symbols[0] += Fp3::ONE;
    refused(&st, &p, &bad, "decider: final opening symbol");
}

#[test]
fn the_zero_accumulator_is_the_committed_zero_word() {
    let k = ivc::key(&whir(), 15).unwrap();
    let p = &k.params;
    let zero = Word::commit_ext_a(p.cfg.layout, &vec![Fp3::ZERO; 1 << p.vars], p.arity);
    assert_eq!(zero.root(), p.zero_root);
    let z = zheng::recursion::state::ZeroWord::new(&p.cfg.layout, p.arity);
    for j in [0usize, 5, (1 << p.cfg.layout.log_leaves()) - 1] {
        let op = zero.open(j);
        assert_eq!(op.symbols, z.opening.symbols);
        assert_eq!(op.path, z.opening.path, "leaf {j}");
    }
}

#[test]
fn rebalanced_schedules_keep_lens_queries_and_reach_128_bits() {
    use lens::rspcs::whir::WhirConfig;
    let (ivc_p, levels) = zheng::envelope::wrapped::chain();
    let k = ivc::key(&ivc_p, 15).unwrap();
    let mut cfgs = vec![("IVC decider", k.dcfg.clone(), k.params.vars)];
    let ikey = k.clone();
    let mut prev: Option<zheng::recursion::wrap::WrapKey> = None;
    for (i, l) in levels.iter().enumerate() {
        let wk = match &prev {
            None => zheng::recursion::wrap::derive_key_ivc_at(
                *l,
                &ikey,
                zheng::envelope::wrapped::INNER_ROOTS[0].map(Goldilocks::new),
            ),
            Some(pk) => {
                if i + 1 < levels.len() {
                    zheng::recursion::wrap::derive_key_wrap_at(
                        *l,
                        pk,
                        zheng::envelope::wrapped::INNER_ROOTS[i].map(Goldilocks::new),
                    )
                } else {
                    zheng::recursion::wrap::derive_key_wrap(*l, pk)
                }
            }
        }
        .unwrap();
        cfgs.push((
            ["level 0", "level 1", "final"][i],
            wk.cfg.clone(),
            wk.cfg.wc.num_vars,
        ));
        prev = Some(wk);
    }
    for (name, c, vars) in cfgs {
        let lens_wc = WhirConfig::derive(&c.whir, vars).unwrap();
        let q = |w: &WhirConfig| w.rounds.iter().map(|s| s.queries).collect::<Vec<_>>();
        assert_eq!(q(&c.wc), q(&lens_wc), "{name}: queries");
        let terms = c.terms();
        assert!(terms.iter().all(|(_, b)| *b >= 128.0), "{name}: {terms:?}");
    }
}
