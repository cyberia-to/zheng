//! Statistical check of zero knowledge, as far as a test can check it: two
//! different witnesses of one statement (`x` and `−x` for `x·x`) give
//! proofs whose revealed values — matrix evaluations, every round
//! polynomial, the mask sums, the opening's polynomials and every opened
//! column — are uniform on 16 buckets of their top bits and identically
//! distributed between the two witnesses (chi-square, 15 degrees of
//! freedom, rejection above 44.3 ≈ p 1e-4; seeds fixed, so the outcome is
//! reproducible). The exact argument is in `specs/soundness.md`.
use super::tests::square_secret;
use super::*;
use crate::execution::private::prepare_execution;

const PROOFS: usize = 40;
const CRITICAL: f64 = 44.3;

fn parsed(x: u64, seed: u64) -> Parsed {
    let (statement, prepared, witness) = prepare_execution(&square_secret(), &[], &[x], 1000).unwrap();
    let public: Vec<_> =
        prepared.public_coordinates.iter().map(|&(i, v)| (i, Goldilocks::new(v))).collect();
    let w = CCSWitness { z: witness.into_iter().map(Goldilocks::new).collect() };
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let bytes = statement.transcript_bytes();
    let proof = prove_relation_with(
        &HidingParams::default(),
        &prepared.relation.instance,
        &w,
        &bytes,
        &public,
        &mut Coins::seeded(seed_bytes),
    )
    .unwrap();
    verify_relation(&prepared.relation.instance, &proof, &bytes, &public).unwrap();
    let setup = Setup::new(&prepared.relation.instance, &with_constant(&public)).unwrap();
    Parsed::from_bytes(proof.as_bytes(), setup.shape()).unwrap()
}

fn limbs(xs: &[nebu::Fp3]) -> Vec<u64> {
    xs.iter().flat_map(|x| [x.c0.as_u64(), x.c1.as_u64(), x.c2.as_u64()]).collect()
}

/// Revealed values by category.
fn revealed(p: &Parsed) -> Vec<(&'static str, Vec<u64>)> {
    let o = &p.opening;
    let rows = o.columns.len() / (o.salts.len() / hiding::SALT);
    let data_rows = rows - hiding::MASK_ROWS;
    let data: Vec<u64> = o
        .columns
        .chunks_exact(rows)
        .flat_map(|c| c[..data_rows].iter().map(|v| v.as_u64()))
        .collect();
    let masks: Vec<u64> =
        o.columns.chunks_exact(rows).flat_map(|c| c[data_rows..].iter().map(|v| v.as_u64())).collect();
    vec![
        ("matrix evaluations", limbs(&p.evals)),
        ("outer rounds", limbs(&p.outer.rounds.concat())),
        ("inner rounds", limbs(&p.inner.rounds.concat())),
        ("mask sums", limbs(&[p.g1, p.g2])),
        ("proximity polynomial", limbs(&o.row_test)),
        ("linear polynomial", limbs(&o.linear)),
        ("opened data columns", data),
        ("opened masking columns", masks),
    ]
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
            for (k, (name, vals)) in revealed(&parsed(w, base + i)).into_iter().enumerate() {
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
        let (ha, hb) = (histogram(va), histogram(vb));
        let (ua, ub, two) = (chi_uniform(&ha), chi_uniform(&hb), chi_two_sample(&ha, &hb));
        println!("{name}: {} values per witness, chi² uniform {ua:.1} / {ub:.1}, two-sample {two:.1}", va.len());
        assert!(ua < CRITICAL && ub < CRITICAL, "{name} not uniform");
        assert!(two < CRITICAL, "{name} depends on the witness");
    }
}
