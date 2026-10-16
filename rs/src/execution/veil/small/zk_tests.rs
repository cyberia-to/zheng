//! Statistical check of veil-W's zero knowledge, per revealed category
//! (`inspect`), as veil's `zk_tests`: witnesses `x` and `−x` of `x·x`,
//! 40 seeded proofs each, top-4-bit buckets, chi-square with 15 degrees
//! of freedom against uniform and between the witnesses (rejection above
//! 44.3). Evidence, not the argument: the argument is the ledger row.
use super::*;
use crate::execution::private::prepare_execution;
use crate::execution::veil::tests::square_secret;

const PROOFS: usize = 40;
const CRITICAL: f64 = 44.3;

fn revealed(x: u64, seed: u64) -> inspect::Revealed {
    let (statement, prepared, witness) = prepare_execution(&square_secret(), &[], &[x], 1000).unwrap();
    let public: Vec<_> = prepared.public_coordinates.iter().map(|&(i, v)| (i, Goldilocks::new(v))).collect();
    let w = CCSWitness { z: witness.into_iter().map(Goldilocks::new).collect() };
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    seed_bytes[31] = 0x57;
    let bytes = statement.transcript_bytes();
    let proof = prove_relation_with(&prepared.relation.instance, &w, &bytes, &public, &Coins::seeded(seed_bytes)).unwrap();
    verify_relation(&prepared.relation.instance, &proof, &bytes, &public).unwrap();
    inspect::revealed_relation(&prepared.relation.instance, &public, &proof).unwrap()
}

fn histogram(values: &[u64]) -> [f64; 16] {
    let mut h = [0f64; 16];
    for &v in values {
        h[(v >> 60) as usize] += 1.0;
    }
    h
}

fn chi_uniform(h: &[f64; 16]) -> f64 {
    let n: f64 = h.iter().sum();
    let e = n / 16.0;
    h.iter().map(|&o| (o - e) * (o - e) / e).sum()
}

fn chi_two_sample(a: &[f64; 16], b: &[f64; 16]) -> f64 {
    let (na, nb): (f64, f64) = (a.iter().sum(), b.iter().sum());
    (0..16)
        .filter(|&i| a[i] + b[i] > 0.0)
        .map(|i| {
            let t = a[i] + b[i];
            let (ea, eb) = (t * na / (na + nb), t * nb / (na + nb));
            (a[i] - ea).powi(2) / ea + (b[i] - eb).powi(2) / eb
        })
        .sum()
}

#[test]
fn revealed_values_are_uniform_and_independent_of_the_witness() {
    let x = 12u64;
    let minus = nebu::field::P - x;
    let collect = |w: u64, base: u64| {
        let mut acc: Vec<(&'static str, Vec<u64>)> = Vec::new();
        for i in 0..PROOFS as u64 {
            for (k, (name, vals)) in revealed(w, base + i).into_iter().enumerate() {
                if acc.len() <= k {
                    acc.push((name, vec![]));
                }
                acc[k].1.extend(vals);
            }
        }
        acc
    };
    let a = collect(x, 0);
    let b = collect(minus, 1 << 32);
    for ((name, va), (_, vb)) in a.iter().zip(&b) {
        if va.is_empty() {
            // this statement's schedule has no committed round after f_0
            println!("{name}: none at this size");
            continue;
        }
        // digests are 4 limbs of a hemera output: canonical limbs < p, so
        // the top bucket is short by ~2^-32 — negligible at these counts
        let (ha, hb) = (histogram(va), histogram(vb));
        let (ua, ub, two) = (chi_uniform(&ha), chi_uniform(&hb), chi_two_sample(&ha, &hb));
        println!("{name}: {} values per witness, chi² uniform {ua:.1} / {ub:.1}, two-sample {two:.1}", va.len());
        assert!(ua < CRITICAL && ub < CRITICAL, "{name} not uniform");
        assert!(two < CRITICAL, "{name} depends on the witness");
    }
}
