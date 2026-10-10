//! 512 statements of one relation (joy's `hash.tri` on 512 inputs) folded
//! into one decider; forged statements, claims and steps are rejected.

use crate::accumulate::ccs::{Statement, fold, verify_folded};
use crate::execution::ExecutionNoun as N;
use lens::WhirParams;
use nebu::Fp3;

/// joy 0.5 `hash.tri`, as compiled.
const HASH: &str = "[2 [[3 [[4 [[9 [[0 3] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [1 0]]] [1 [15 [3 [[0 2] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [1 0]]]]]]]]]]]]]]]]]]]]]]]]]]]";

fn parse(text: &str) -> N {
    fn go(b: &[u8], p: &mut usize) -> N {
        while b[*p] == b' ' {
            *p += 1;
        }
        if b[*p] == b'[' {
            *p += 1;
            let a = go(b, p);
            let c = go(b, p);
            while b[*p] == b' ' {
                *p += 1;
            }
            *p += 1;
            N::Pair(Box::new(a), Box::new(c))
        } else {
            let s = *p;
            while b[*p].is_ascii_digit() {
                *p += 1;
            }
            N::Atom(std::str::from_utf8(&b[s..*p]).unwrap().parse().unwrap())
        }
    }
    go(text.as_bytes(), &mut 0)
}

#[test]
fn five_hundred_twelve_statements_decide_in_one_proof() {
    let whir = WhirParams {
        log_inv_rate: 3,
        pow_bits: 16,
        ..WhirParams::default()
    };
    let program = parse(HASH);
    let mut prepared = Vec::new();
    for x in 0..512u64 {
        let (st, rel, wit, _) = super::super::statement::prepare(&program, &[x], 1 << 20).unwrap();
        let (instance, pins) = super::relation_and_pins(&st).unwrap();
        assert_eq!(instance.num_cols, rel.instance.num_cols);
        prepared.push((st, instance, pins, wit.z));
    }
    let statements: Vec<Statement<'_>> = prepared
        .iter()
        .map(|(st, inst, pins, _)| Statement {
            instance: inst,
            pins: pins.clone(),
            bytes: st.transcript_bytes(),
        })
        .collect();
    let witnesses: Vec<Vec<nebu::Goldilocks>> = prepared.iter().map(|p| p.3.clone()).collect();
    let chunk = 64;
    let folded = fold(&whir, &statements, &witnesses, chunk).unwrap();
    assert_eq!(folded.claims.len(), 512);
    let t = std::time::Instant::now();
    verify_folded(&whir, &statements, &folded, chunk).unwrap();
    let mut w = lens::rspcs::wire::Writer::default();
    folded.claims[0].write(&mut w);
    let mut d = lens::rspcs::wire::Writer::default();
    folded.decider.write(&mut d, true);
    eprintln!(
        "512 × hash.tri folded: {} B total (claim {} B each, steps {} B, decider {} B), verify {:.0} ms",
        folded.to_bytes().len(),
        w.buf.len(),
        folded.steps.iter().map(|s| s.to_bytes().len()).sum::<usize>(),
        d.buf.len(),
        t.elapsed().as_secs_f64() * 1e3
    );
    // a statement with another output does not verify
    let mut forged = prepared[17].0.clone();
    forged.public_output[0] ^= 1;
    let (fi, fp) = super::relation_and_pins(&forged).unwrap();
    let mut bad: Vec<Statement<'_>> = prepared
        .iter()
        .map(|(st, inst, pins, _)| Statement {
            instance: inst,
            pins: pins.clone(),
            bytes: st.transcript_bytes(),
        })
        .collect();
    bad[17] = Statement {
        instance: &fi,
        pins: fp,
        bytes: forged.transcript_bytes(),
    };
    assert!(verify_folded(&whir, &bad, &folded, chunk).is_err());
    // a forged witness claim, a dropped step
    let mut f = folded.clone();
    f.claims[300].witness_eval += Fp3::ONE;
    assert!(verify_folded(&whir, &statements, &f, chunk).is_err());
    let mut f = folded.clone();
    f.steps.pop();
    assert!(verify_folded(&whir, &statements, &f, chunk).is_err());
}
