use nebu::Goldilocks;

use super::*;
use crate::execution::veil::tests::square_secret;

#[test]
fn a_field_native_proof_verifies_and_round_trips() {
    let program = square_secret();
    let key = RecKey::new(&program, 0).unwrap();
    let (st, pf) = prove_seeded(&key, &program, &[], &[7], 1000, [5; 32]).unwrap();
    verify(&key, &st, &pf).unwrap();
    let bytes = pf.to_bytes(&key);
    let back = RecProof::from_bytes(&bytes, &key).unwrap();
    assert_eq!(back.to_bytes(&key), bytes);
    verify(&key, &st, &back).unwrap();
    let r = key.report();
    eprintln!("{r:?} bytes {}", bytes.len());
}

#[test]
fn a_wrong_pin_or_a_tampered_message_is_refused() {
    let program = square_secret();
    let key = RecKey::new(&program, 0).unwrap();
    let (st, pf) = prove_seeded(&key, &program, &[], &[7], 1000, [6; 32]).unwrap();
    let pins = key.statement_pins(&st).unwrap();
    verify_pins(&key, &pins, &pf).unwrap();
    for i in 0..pins.len() {
        let mut bad = pins.clone();
        bad[i] += Goldilocks::ONE;
        assert!(verify_pins(&key, &bad, &pf).is_err(), "pin {i}");
    }
    let one = nebu::Fp3::ONE;
    let tampers: Vec<Box<dyn Fn(&mut RecProof)>> = vec![
        Box::new(|p| p.root[0] += Goldilocks::ONE),
        Box::new(move |p| p.g1 += one),
        Box::new(move |p| p.outer[0][0] += one),
        Box::new(move |p| p.evals[0] += one),
        Box::new(move |p| p.g2 += one),
        Box::new(move |p| p.inner[0][1] += one),
        Box::new(move |p| p.mu += one),
        Box::new(move |p| p.row_test[3] += one),
        Box::new(move |p| p.linear[0] += one),
        Box::new(|p| p.nonce += 1),
        Box::new(move |p| p.openings[0].symbols[0] += one),
        Box::new(move |p| p.openings[5].symbols.last_mut().map(|s| *s += one).unwrap()),
        Box::new(|p| p.openings[2].path[0][1] += Goldilocks::ONE),
    ];
    for (i, f) in tampers.iter().enumerate() {
        let mut q = pf.clone();
        f(&mut q);
        assert!(verify(&key, &st, &q).is_err(), "tamper {i}");
    }
}
