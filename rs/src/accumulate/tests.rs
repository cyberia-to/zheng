//! Accumulation: completeness at depth, rejection of false claims, forged
//! openings and bit flips, the decider, and the policy.

use lens::rspcs::field::ml_eval_base;
use lens::{MultilinearPcs, Whir, WhirParams};
use nebu::{Fp3, Goldilocks};

use super::*;

/// splitmix64
pub(crate) struct Rng(u64);
impl Rng {
    pub(crate) fn new(s: u64) -> Self {
        Self(s ^ 0x9E37_79B9_7F4A_7C15)
    }
    pub(crate) fn u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub(crate) fn g(&mut self) -> Goldilocks {
        Goldilocks::new(self.u64() % nebu::field::P)
    }
    pub(crate) fn e(&mut self) -> Fp3 {
        Fp3::new(self.g(), self.g(), self.g())
    }
}

pub(crate) fn test_params() -> WhirParams {
    WhirParams {
        log_inv_rate: 3,
        pow_bits: 12,
        ..WhirParams::default()
    }
}

/// A fresh base-field word with `k` true claims at random points.
pub(crate) fn fresh(cfg: &AccConfig, rng: &mut Rng, k: usize) -> Witnessed {
    let table: Vec<Goldilocks> = (0..1usize << cfg.num_vars).map(|_| rng.g()).collect();
    let (root, data) = Whir::commit(&cfg.whir, &table);
    let claims = (0..k)
        .map(|_| {
            let point: Vec<Fp3> = (0..cfg.num_vars).map(|_| rng.e()).collect();
            let value = ml_eval_base(&table, &point);
            Claim { point, value }
        })
        .collect();
    Witnessed {
        instance: Instance {
            root,
            ext: false,
            claims,
        },
        data,
    }
}

fn cfg(vars: usize, inputs: usize) -> AccConfig {
    AccConfig::derive(&test_params(), vars, inputs, 64 + 2 * inputs).unwrap()
}

#[test]
fn chained_steps_decide_and_verify() {
    let cfg = cfg(8, 4);
    let mut rng = Rng::new(1);
    let mut tp = transcript(b"acc-test", b"ctx", &cfg);
    let mut tv = transcript(b"acc-test", b"ctx", &cfg);
    let mut acc: Option<Witnessed> = None;
    let mut acc_inst: Option<Instance> = None;
    for depth in 0..5 {
        let fresh_words: Vec<Witnessed> = (0..3).map(|_| fresh(&cfg, &mut rng, 2)).collect();
        let mut inputs: Vec<&Witnessed> = acc.iter().collect();
        inputs.extend(fresh_words.iter());
        let (next, proof) = accumulate(&cfg, &inputs, &mut tp).unwrap();
        let bytes = proof.to_bytes();
        let parsed = AccProof::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, proof);
        let mut insts: Vec<&Instance> = acc_inst.iter().collect();
        insts.extend(fresh_words.iter().map(|w| &w.instance));
        let derived = verify_step(&cfg, &insts, &parsed, &mut tv).unwrap();
        assert_eq!(derived, next.instance, "depth {depth}");
        assert_eq!(derived.claims.len(), cfg.acc_claims());
        acc_inst = Some(derived);
        acc = Some(next);
    }
    let acc = acc.unwrap();
    let proof = decide(&cfg, &acc, &mut tp).unwrap();
    verify_decider(&cfg, acc_inst.as_ref().unwrap(), &proof, &mut tv).unwrap();
}

#[test]
fn a_false_claim_is_rejected_by_the_step_verifier() {
    let cfg = cfg(7, 3);
    let mut rng = Rng::new(2);
    let mut words: Vec<Witnessed> = (0..3).map(|_| fresh(&cfg, &mut rng, 2)).collect();
    words[1].instance.claims[1].value += Fp3::ONE;
    let inputs: Vec<&Witnessed> = words.iter().collect();
    let mut tp = transcript(b"acc-test", b"", &cfg);
    let (_, proof) = accumulate(&cfg, &inputs, &mut tp).unwrap();
    let insts: Vec<&Instance> = words.iter().map(|w| &w.instance).collect();
    let mut tv = transcript(b"acc-test", b"", &cfg);
    assert!(verify_step(&cfg, &insts, &proof, &mut tv).is_err());
}

#[test]
fn forged_openings_roots_and_bit_flips_are_rejected() {
    let cfg = cfg(6, 2);
    let mut rng = Rng::new(3);
    let words: Vec<Witnessed> = (0..2).map(|_| fresh(&cfg, &mut rng, 1)).collect();
    let inputs: Vec<&Witnessed> = words.iter().collect();
    let insts: Vec<&Instance> = words.iter().map(|w| &w.instance).collect();
    let mut tp = transcript(b"acc-test", b"", &cfg);
    let (next, proof) = accumulate(&cfg, &inputs, &mut tp).unwrap();
    let bytes = proof.to_bytes();
    let mut accepted = 0usize;
    let mut tried = 0usize;
    for i in (0..bytes.len()).step_by(7) {
        let mut b = bytes.clone();
        b[i] ^= 1 << (i % 8);
        tried += 1;
        if let Ok(p) = AccProof::from_bytes(&b) {
            let mut tv = transcript(b"acc-test", b"", &cfg);
            if let Ok(inst) = verify_step(&cfg, &insts, &p, &mut tv) {
                // a flip that keeps the step valid must not change the
                // accumulator the verifier derives
                if inst != next.instance {
                    accepted += 1;
                }
            }
        }
    }
    assert!(tried > 100);
    assert_eq!(accepted, 0);
    // a different root for an input
    let mut other = insts[0].clone();
    other.root = words[1].instance.root;
    let mut tv = transcript(b"acc-test", b"", &cfg);
    assert!(verify_step(&cfg, &[&other, insts[1]], &proof, &mut tv).is_err());
}

#[test]
fn decider_rejects_a_wrong_accumulator_claim_and_wrong_value() {
    let cfg = cfg(6, 2);
    let mut rng = Rng::new(4);
    let words: Vec<Witnessed> = (0..2).map(|_| fresh(&cfg, &mut rng, 1)).collect();
    let inputs: Vec<&Witnessed> = words.iter().collect();
    let mut tp = transcript(b"acc-test", b"", &cfg);
    let (acc, _) = accumulate(&cfg, &inputs, &mut tp).unwrap();
    let mut t1 = transcript(b"d", b"", &cfg);
    let proof = decide(&cfg, &acc, &mut t1).unwrap();
    let mut t2 = transcript(b"d", b"", &cfg);
    verify_decider(&cfg, &acc.instance, &proof, &mut t2).unwrap();
    for j in [0, 1, cfg.ood + 1] {
        let mut bad = acc.instance.clone();
        bad.claims[j].value += Fp3::ONE;
        let mut t3 = transcript(b"d", b"", &cfg);
        assert!(verify_decider(&cfg, &bad, &proof, &mut t3).is_err(), "claim {j}");
    }
    let mut p2 = proof.clone();
    p2.value += Fp3::ONE;
    let mut t4 = transcript(b"d", b"", &cfg);
    assert!(verify_decider(&cfg, &acc.instance, &p2, &mut t4).is_err());
    // a fresh instance decides directly (base symbols)
    let mut t5 = transcript(b"d", b"", &cfg);
    let p = decide(&cfg, &words[0], &mut t5).unwrap();
    let mut t6 = transcript(b"d", b"", &cfg);
    verify_decider(&cfg, &words[0].instance, &p, &mut t6).unwrap();
}

#[test]
fn shipped_parameters_reach_128_bits_for_513_inputs() {
    let whir = crate::execution::succinct::params_for(20);
    for vars in [10, 16, 20, 22] {
        let c = AccConfig::derive(&whir, vars, 513, 513 * 4 + 64).unwrap();
        let bits = c.security_bits(513, 513 * 4 + 64);
        assert!(bits >= MIN_BITS, "{vars}: {bits}");
        eprintln!(
            "vars {vars}: regime {:?} t {} qpow {} ood {} comb_pow(2) {} comb_pow(513) {}",
            c.regime, c.queries, c.query_pow, c.ood, c.comb_pow_for(2), c.comb_pow_for(513)
        );
    }
}
