//! zheng's outer sumcheck alone: random a, b and c = a ⊙ b over 2^LM rows.
use ark_std::UniformRand;
use backend::{ArkBls12_381, ArkConfig, Value};
use lang::id::Vid;
use share::Ctx;

use crate::common;
use crate::common::size;

fn make_inputs(sizes: &Ctx<lang::id::Tid, usize>) -> Ctx<Vid, Value<ArkBls12_381>> {
    type F = <ArkBls12_381 as ArkConfig>::F;
    let n = 1usize << size(sizes, "LM");
    let mut rng = rand::rngs::OsRng;
    let a: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
    let b: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();
    let c: Vec<F> = a.iter().zip(b.iter()).map(|(x, y)| *x * *y).collect();
    Ctx::<Vid, Value<ArkBls12_381>>::from_iter([
        (Vid("az".to_string()), Value::vec_scalar(a)),
        (Vid("bz".to_string()), Value::vec_scalar(b)),
        (Vid("cz".to_string()), Value::vec_scalar(c)),
    ])
}

pub fn spec() -> common::ExampleSpec<ArkBls12_381> {
    common::ExampleSpec {
        source: "examples/zheng_outer/zheng_outer.zippel",
        defaults: &[("LM", 2)],
        validate: None,
        make_inputs,
        analyses: &[common::Analysis::Completeness, common::Analysis::Soundness(&[4, 4, 4])],
    }
}
