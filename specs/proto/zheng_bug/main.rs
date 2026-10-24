//! harness for zheng_spartan.zippel inside zippel's example dispatcher
//! (copy this directory into <zippel>/examples/ and register it in examples/registry.rs).
use ark_ff::{One, Zero};
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
    let _ = (rows, &mut rng);
    // z[i] * z[(i+1)%4] == z[(i+2)%4] for every row: the all-ones vector satisfies it
    let z: Vec<F> = vec![F::one(); cols];

    Ctx::<Vid, Value<ArkBls12_381>>::from_iter([
        (Vid("z".to_string()), Value::vec_scalar(z)),
        (Vid("placeholder_tau".to_string()), Value::vec_scalar(vec![F::zero(); lm])),
    ])
}

pub fn spec() -> common::ExampleSpec<ArkBls12_381> {
    common::ExampleSpec {
        source: "examples/zheng_bug/zheng_bug.zippel",
        defaults: &[("LM", 2), ("NV", 2)],
        validate: Some(|sizes, _| { if crate::common::size(sizes, "LM") != 2 || crate::common::size(sizes, "NV") != 2 { return Err("the fixed CCS is 4 x 4: LM = NV = 2".into()); } Ok(()) }),
        make_inputs,
        analyses: &[common::Analysis::Completeness],
    }
}
