use lens::WhirParams;
use lens::rspcs::field::{ml_eval_ext, pow_point};
use nebu::{Fp3, Goldilocks};

use super::*;
use crate::recursion::circuit::builder::Builder;
use crate::recursion::ops::{Native, Ops};
use crate::recursion::perm::tag;
use crate::recursion::sponge::{ProverTranscript, Sponge};
use crate::recursion::word::Word;

fn e(i: u64) -> Fp3 {
    Fp3::new(Goldilocks::new(i * 7 + 1), Goldilocks::new(i * i + 11), Goldilocks::new(3 * i + 2))
}

fn params(rate: u8, k: u8, fin: u8) -> WhirParams {
    WhirParams { log_inv_rate: rate, folding_factor: k, pow_bits: 8, max_final_vars: fin, ..WhirParams::default() }
}

struct Case {
    cfg: Config,
    words: Vec<Word>,
    claims: Vec<Vec<(Vec<Fp3>, Fp3)>>,
    /// Per claim: `Some(x)` for a univariate claim at `pow(x)`.
    uni: Vec<Vec<Option<Fp3>>>,
}

fn case(ell: usize, rate: u8, k: u8, fin: u8, ext: &[bool]) -> Case {
    let whir = params(rate, k, fin);
    let claims_per = 3;
    let cfg = Config::derive(&whir, ell, &vec![1; ext.len()], claims_per * ext.len()).unwrap();
    let layout = cfg.layout(0);
    let mut words = Vec::new();
    let mut claims = Vec::new();
    let mut uni = Vec::new();
    for (w, &x) in ext.iter().enumerate() {
        let table: Vec<Fp3> = (0..1u64 << ell)
            .map(|i| if x { e(i + 1000 * w as u64) } else { Fp3::from_base(Goldilocks::new(i * i + 3 + w as u64)) })
            .collect();
        let word = if x { Word::commit_ext(layout, &table) } else { Word::commit_base(layout, &table.iter().map(|v| v.c0).collect::<Vec<_>>()) };
        let p: Vec<Fp3> = (0..ell as u64).map(|i| e(50 + i + 13 * w as u64)).collect();
        let z = e(900 + w as u64);
        let z2 = e(901 + w as u64);
        claims.push(vec![
            (p.clone(), ml_eval_ext(&table, &p)),
            (pow_point(z, ell), word.univariate(z)),
            (pow_point(z2, ell), word.univariate(z2)),
        ]);
        uni.push(vec![None, Some(z), Some(z2)]);
        words.push(word);
    }
    Case { cfg, words, claims, uni }
}

fn inputs<O: Ops>(o: &mut O, c: &Case) -> Vec<InstV<O::V>> {
    c.words
        .iter()
        .zip(&c.claims)
        .zip(&c.uni)
        .map(|((w, cs), us)| InstV {
            root: w.root().map(|x| o.constant(Fp3::from_base(x))),
            ext: w.is_ext(),
            claims: cs
                .iter()
                .zip(us)
                .map(|((p, v), u)| {
                    let v = o.witness(*v);
                    match u {
                        Some(x) => ClaimRef::Uni(o.witness(*x), v),
                        None => ClaimRef::Multi(p.iter().map(|&a| o.witness(a)).collect(), v),
                    }
                })
                .collect(),
        })
        .collect()
}

fn prove_case(c: &Case) -> Proof {
    let mut t = ProverTranscript::new(tag::STEP);
    let words: Vec<&dyn Tree> = c.words.iter().map(|w| w as &dyn Tree).collect();
    prove(&c.cfg, &mut t, &words, &c.claims).unwrap()
}

fn check(c: &Case, pf: &Proof) -> Result<(), String> {
    let mut o = Native::batched();
    let ins = inputs(&mut o, c);
    let mut t = Sponge::new(&mut o, tag::STEP);
    verify(&mut o, &c.cfg, &mut t, &ins, pf);
    o.finish()
}

#[test]
fn a_batched_opening_verifies_natively_and_in_the_circuit() {
    for (ell, rate, k, fin, ext) in [
        (10usize, 2u8, 4u8, 3u8, vec![false]),
        (11, 3, 3, 2, vec![false, true, false]),
        (12, 2, 4, 4, vec![true, true]),
        (8, 2, 4, 4, vec![false, false]),
    ] {
        let c = case(ell, rate, k, fin, &ext);
        let pf = prove_case(&c);
        check(&c, &pf).unwrap_or_else(|e| panic!("ℓ {ell}: {e}"));
        let mut b = Builder::new(true);
        let ins = inputs(&mut b, &c);
        let mut t = Sponge::new(&mut b, tag::STEP);
        verify(&mut b, &c.cfg, &mut t, &ins, &pf);
        b.finish().unwrap_or_else(|e| panic!("ℓ {ell} circuit: {e}"));
        eprintln!("ℓ {ell} rate 1/{} k {k} words {}: circuit rows {}, bits {:.1}", 1 << rate, ext.len(), b.rows(), c.cfg.security_bits());
    }
}

#[test]
fn a_wrong_claim_or_a_tampered_proof_is_refused() {
    let c = case(10, 2, 4, 3, &[false, true]);
    let pf = prove_case(&c);
    check(&c, &pf).unwrap();
    // a wrong claimed value
    let mut bad = case(10, 2, 4, 3, &[false, true]);
    bad.claims[1][0].1 += Fp3::ONE;
    assert!(check(&bad, &pf).is_err());
    // tampered messages
    let tamper: Vec<Box<dyn Fn(&mut Proof)>> = vec![
        Box::new(|p| p.batch.sumcheck[3] += Fp3::ONE),
        Box::new(|p| p.batch.evals[0] += Fp3::ONE),
        Box::new(|p| p.ood0[0] += Fp3::ONE),
        Box::new(|p| p.sumcheck0[1] += Fp3::ONE),
        Box::new(|p| p.rounds[0].root[2] += Goldilocks::ONE),
        Box::new(|p| p.rounds[0].ood[0] += Fp3::ONE),
        Box::new(|p| p.rounds[0].open[1][0].symbols[3] += Fp3::ONE),
        Box::new(|p| p.rounds[0].open[2][1].path[4][0] += Goldilocks::ONE),
        Box::new(|p| p.rounds[0].sumcheck[0] += Fp3::ONE),
        Box::new(|p| p.final_poly[1] += Fp3::ONE),
        Box::new(|p| p.final_open[0][0].symbols[0] += Fp3::ONE),
        Box::new(|p| p.batch.comb_nonce ^= 1),
        Box::new(|p| p.final_nonce ^= 1),
    ];
    for (i, f) in tamper.iter().enumerate() {
        let mut p = pf.clone();
        f(&mut p);
        let shape = check_shape(&c.cfg, 2, &p);
        assert!(shape.is_err() || check(&c, &p).is_err(), "tamper {i} accepted");
    }
}

#[test]
fn words_under_one_tree_open_with_one_path() {
    use crate::recursion::word::Group;
    let ell = 10;
    let whir = params(2, 4, 3);
    let cfg = Config::derive(&whir, ell, &[1, 2], 9).unwrap();
    let layout = cfg.layout(0);
    let table = |w: u64| -> Vec<Goldilocks> { (0..1u64 << ell).map(|i| Goldilocks::new(i * (w + 3) + w)).collect() };
    let single = Word::commit_base(layout, &table(0));
    let group = Group::new(vec![Word::member_base(layout, &table(1)), Word::member_base(layout, &table(2))]);
    let mut claims = Vec::new();
    let mut uni = Vec::new();
    for w in [&single, &group.words[0], &group.words[1]] {
        let p: Vec<Fp3> = (0..ell as u64).map(|i| e(70 + i)).collect();
        let z = e(500 + claims.len() as u64);
        claims.push(vec![(p.clone(), ml_eval_ext(&w.table(), &p)), (pow_point(z, ell), w.univariate(z))]);
        uni.push(vec![None, Some(z)]);
    }
    let mut t = ProverTranscript::new(tag::STEP);
    let pf = prove(&cfg, &mut t, &[&single as &dyn Tree, &group], &claims).unwrap();
    let run = |claims: &[Vec<(Vec<Fp3>, Fp3)>]| -> Result<(), String> {
        let mut o = Native::batched();
        let roots = [single.root(), group.root(), group.root()];
        let ins: Vec<InstV<Fp3>> = roots
            .iter()
            .zip(claims)
            .zip(&uni)
            .map(|((r, cs), us)| InstV {
                root: r.map(Fp3::from_base),
                ext: false,
                claims: cs.iter().zip(us).map(|((p, v), u)| match u { Some(x) => ClaimRef::Uni(*x, *v), None => ClaimRef::Multi(p.clone(), *v) }).collect(),
            })
            .collect();
        let mut sp = Sponge::new(&mut o, tag::STEP);
        verify(&mut o, &cfg, &mut sp, &ins, &pf);
        o.finish()
    };
    run(&claims).unwrap();
    let mut bad = claims.clone();
    bad[2][0].1 += Fp3::ONE;
    assert!(run(&bad).is_err());
    assert_eq!(pf.rounds[0].open[0].len(), 2, "two trees opened per query");
}
