//! zheng's inner sumcheck alone: random w and z over 2^NV columns, claim = <w, z>.
use ark_ff::Zero;
use ark_std::UniformRand;
use backend::{ArkBls12_381, ArkConfig, Value};
use lang::id::Vid;
use share::Ctx;

use crate::common;
use crate::common::size;

fn make_inputs(sizes: &Ctx<lang::id::Tid, usize>) -> Ctx<Vid, Value<ArkBls12_381>> {
    type F = <ArkBls12_381 as ArkConfig>::F;
    let n = 1usize << size(sizes, "NV");
    let mut rng = rand::rngs::OsRng;
    let w: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
    let z: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
    let claim: F = w.iter().zip(z.iter()).fold(F::zero(), |acc, (a, b)| acc + *a * *b);
    Ctx::<Vid, Value<ArkBls12_381>>::from_iter([
        (Vid("w".to_string()), Value::vec_scalar(w)),
        (Vid("z".to_string()), Value::vec_scalar(z)),
        (Vid("claim".to_string()), Value::Scalar(claim)),
    ])
}

pub fn spec() -> common::ExampleSpec<ArkBls12_381> {
    common::ExampleSpec {
        source: "examples/zheng_inner/zheng_inner.zippel",
        defaults: &[("NV", 2)],
        validate: None,
        make_inputs,
        analyses: &[common::Analysis::Completeness, common::Analysis::Soundness(&[3, 3])],
    }
}
