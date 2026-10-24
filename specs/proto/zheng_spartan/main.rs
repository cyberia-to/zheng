//! harness for zheng_spartan.zippel inside zippel's example dispatcher
//! (copy this directory into <zippel>/examples/ and register it in examples/registry.rs).
use ark_ff::{Field, One, Zero};
use ark_std::UniformRand;
use backend::{ArkBls12_381, ArkConfig, Value};
use lang::id::Vid;
use share::Ctx;

use crate::common;
use crate::common::size;

type F = <ArkBls12_381 as ArkConfig>::F;

fn make_inputs(sizes: &Ctx<lang::id::Tid, usize>) -> Ctx<Vid, Value<ArkBls12_381>> {
    let lm = size(sizes, "LM");
    let nv = size(sizes, "NV");
    let rows = 1usize << lm;
    let cols = 1usize << nv;
    let mut rng = rand::rngs::OsRng;

    // a satisfying instance: random z with z[0] != 0, random A and B,
    // C with one entry per row so that (A z)_i (B z)_i = (C z)_i
    let mut z: Vec<F> = (0..cols).map(|_| F::rand(&mut rng)).collect();
    if z[0].is_zero() {
        z[0] = F::one();
    }
    let mat_a: Vec<F> = (0..rows * cols).map(|_| F::rand(&mut rng)).collect();
    let mat_b: Vec<F> = (0..rows * cols).map(|_| F::rand(&mut rng)).collect();
    let mut mat_c = vec![F::zero(); rows * cols];
    for i in 0..rows {
        let az: F = (0..cols).map(|j| mat_a[i * cols + j] * z[j]).sum();
        let bz: F = (0..cols).map(|j| mat_b[i * cols + j] * z[j]).sum();
        mat_c[i * cols] = az * bz * z[0].inverse().unwrap();
    }

    Ctx::<Vid, Value<ArkBls12_381>>::from_iter([
        (Vid("mat_a".to_string()), Value::vec_scalar(mat_a)),
        (Vid("mat_b".to_string()), Value::vec_scalar(mat_b)),
        (Vid("mat_c".to_string()), Value::vec_scalar(mat_c)),
        (Vid("z".to_string()), Value::vec_scalar(z)),
        (Vid("placeholder_tau".to_string()), Value::vec_scalar(vec![F::zero(); lm])),
    ])
}

pub fn spec() -> common::ExampleSpec<ArkBls12_381> {
    common::ExampleSpec {
        source: "examples/zheng_spartan/zheng_spartan.zippel",
        defaults: &[("LM", 2), ("NV", 2)],
        validate: None,
        make_inputs,
        analyses: &[common::Analysis::Completeness],
    }
}
