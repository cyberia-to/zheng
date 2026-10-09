//! The hiding commitment opens any functional it was asked for and nothing
//! a cheating prover substitutes.
use super::*;
use crate::execution::veil::coins::Coins;
use lens::Transcript;
use nebu::Goldilocks;

fn setup(n: usize, seed: u8) -> (Vec<Goldilocks>, Functional, Fp3) {
    let mut coins = Coins::seeded([seed; 32]);
    let entries = coins.bases(n);
    let tensor = (n / 2).next_power_of_two().min(n).trailing_zeros() as usize;
    let point: Vec<Fp3> = (0..tensor).map(|_| coins.ext()).collect();
    let explicit: Vec<(usize, Fp3)> = ((1 << tensor)..n).step_by(3).map(|e| (e, coins.ext())).collect();
    let f = Functional { scale: coins.ext(), point, explicit };
    let eq = prove::eq_msb(&f.point);
    let mut value = Fp3::ZERO;
    for (e, &w) in eq.iter().enumerate() {
        value += f.scale * w * Fp3::from_base(entries[e]);
    }
    for &(e, w) in &f.explicit {
        value += w * Fp3::from_base(entries[e]);
    }
    (entries, f, value)
}

fn run(n: usize, tamper: &dyn Fn(&mut HidingProof, &mut Fp3)) -> Result<(), String> {
    let params = HidingParams::default();
    let (entries, f, mut value) = setup(n, n as u8);
    let (root, committed) = commit(&params, &entries, &mut Coins::seeded([1; 32])).unwrap();
    let mut proof = open(&committed, &f, value, &mut Transcript::new(b"t"));
    tamper(&mut proof, &mut value);
    verify(&params, &root, n, &f, value, &proof, &mut Transcript::new(b"t"))
}

#[test]
fn openings_verify_at_several_shapes() {
    for n in [100, 1 << 10, 3000, 1 << 13] {
        run(n, &|_, _| {}).unwrap_or_else(|e| panic!("{n}: {e}"));
    }
}

#[test]
fn forged_values_and_messages_are_rejected() {
    let n = 1 << 10;
    let one = Fp3::ONE;
    type Tamper = Box<dyn Fn(&mut HidingProof, &mut Fp3)>;
    let cases: Vec<(&str, Tamper)> = vec![
        ("value", Box::new(move |_, v| *v += one)),
        ("mu", Box::new(move |p, _| p.mu += one)),
        ("row test", Box::new(move |p, _| p.row_test[3] += one)),
        ("linear", Box::new(move |p, _| p.linear[200] += one)),
        ("linear coefficient and value", Box::new(move |p, v| {
            *v += one;
            let mid = p.linear.len() / 2;
            p.linear[mid] += one;
        })),
        ("column", Box::new(|p, _| p.columns[5] += Goldilocks::ONE)),
        ("salt", Box::new(|p, _| p.salts[0] += Goldilocks::ONE)),
        ("sibling", Box::new(|p, _| p.siblings[0] = hemera::Hash::from_bytes([7; 32]))),
        ("nonce", Box::new(|p, _| p.pow_nonce = p.pow_nonce.map(|n| n + 1))),
    ];
    for (name, tamper) in cases {
        assert!(run(n, tamper.as_ref()).is_err(), "{name}");
    }
}

#[test]
fn security_is_proven_above_128_bits() {
    let cfg = Config::derive(&HidingParams::default(), 1 << 12).unwrap();
    assert!(cfg.security_bits() >= 128.0, "{}", cfg.security_bits());
    assert!(cfg.k > cfg.queries, "padding covers every opened column");
}

