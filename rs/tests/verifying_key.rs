//! Cached verifying keys on the shipped succinct choice: the same verdict
//! with and without the key, a foreign key rejected, and the time a cached
//! key saves (printed; `cargo test --release --test verifying_key -- --nocapture`).
mod common;

use common::{ADD, HASH, parse};
use std::time::Instant;
use zheng::envelope::AnySuccinct;
use zheng::execution::succinct::{self, prove_default};
use zheng::execution::VerifyingKey;

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

#[test]
fn cached_key_verifies_hash_tri_without_recompiling() {
    let (statement, proof) = prove_default(&parse(HASH), &[7], 1_000_000).unwrap();
    let AnySuccinct::Whir(proof) = proof else { panic!("shipped choice is WHIR") };
    let reps = 31;
    let time = |f: &dyn Fn()| {
        median(
            (0..reps)
                .map(|_| {
                    let t = Instant::now();
                    f();
                    t.elapsed().as_secs_f64() * 1e3
                })
                .collect(),
        )
    };
    let derive = time(&|| {
        VerifyingKey::for_execution(&statement).unwrap();
    });
    let vk = VerifyingKey::for_execution(&statement).unwrap();
    let cold = time(&|| succinct::verify_with(&statement, &proof, None).unwrap());
    let cached = time(&|| succinct::verify_with(&statement, &proof, Some(&vk)).unwrap());
    let compile = time(&|| {
        succinct::relation_and_pins(&statement).unwrap();
    });
    let key = time(&|| {
        statement.program_key();
    });
    println!(
        "hash.tri shipped choice: verify {cold:.3} ms without a key, {cached:.3} ms with a cached key; \
         derive (compile + digest) {derive:.3} ms, of which compile {compile:.3} ms; program key {key:.4} ms"
    );
    assert!(cached < cold, "a cached key skips the compile");
    let (add, _) = zheng::execution::certify_execution(&parse(ADD), &[7, 5], 1000).unwrap();
    let foreign = VerifyingKey::for_execution(&add).unwrap();
    assert!(succinct::verify_with(&statement, &proof, Some(&foreign)).is_err());
}

