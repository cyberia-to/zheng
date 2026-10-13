//! zheng #60 review (`audit/proof-stack-review-2026-10.md`): the prover
//! backends (#59) cannot move a verifier's accept/reject.
//!
//! One test, one process (the backend is process-wide): the keys are
//! derived under a backend `X` (`ZHENG_REVIEW_BACKEND`: `rec` — the CPU
//! under a device name, counting every call and taking every device path
//! with lens's reference kernels; or `metal` / `webgpu`), the pinned key
//! digest checked, then the stored proofs (profile 5's IVC proof, both
//! inner wrap levels, the final proof and a sample of its bit flips) are
//! verified under `X`, under the CPU backend, and under a backend that
//! corrupts every result it returns: the three verdict lists are equal,
//! and under `rec` the verifiers make no backend call at all.
//!
//! `ZHENG_IVC_DIR=<dir> [ZHENG_REVIEW_BACKEND=metal] cargo test --release
//! -p zheng --test proof_stack_backend -- --ignored --nocapture`.

mod common;

#[path = "common/rec.rs"]
mod rec;

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use lens::rspcs::backend;
use rec::{Cpu2, Rec};
use zheng::envelope::{Profile, keys, wrapped};
use zheng::machine;
use zheng::recursion::ivc;
use zheng::recursion::wrap::{self, FinalProof, WrapKey, WrapProof};

#[test]
#[ignore = "stored proofs (ZHENG_IVC_DIR)"]
fn no_backend_moves_a_verdict() {
    let choice = std::env::var("ZHENG_REVIEW_BACKEND").unwrap_or_else(|_| "rec".into());
    let rec = Arc::new(Rec::new("rec-device", false));
    if choice == "rec" {
        backend::install(rec.clone());
    } else {
        let (name, dev) = cyber_lens_gpu::install(choice.parse().unwrap()).unwrap();
        eprintln!("backend {name} ({dev})");
    }

    // keys, derived under the chosen backend (a fresh process: no cache)
    let (ivc_whir, levels) = wrapped::chain();
    let step = wrapped::admitted_ivc().1;
    let ikey = ivc::key(&ivc_whir, step).unwrap();
    let pin = |i: usize| wrapped::INNER_ROOTS[i].map(nebu::Goldilocks::new);
    let k0 = wrap::derive_key_ivc_at(levels[0], &ikey, pin(0)).unwrap();
    let k1 = wrap::derive_key_wrap_at(levels[1], &k0, pin(1)).unwrap();
    let fk = wrapped::final_key().unwrap();
    let bundle = keys::export(Profile::Wrapped).unwrap();
    assert_eq!(Some(keys::digest(&bundle)), keys::pinned(Profile::Wrapped), "keys derived under {choice} are not the pinned ones");
    if choice == "rec" {
        eprintln!("verifier-side key derivation under the device-named backend: calls {:?}", rec.counts());
        rec.calls.iter().for_each(|c| c.store(0, Relaxed));
    }

    let dir = std::env::var("ZHENG_IVC_DIR").expect("ZHENG_IVC_DIR");
    let read = |f: &str| std::fs::read(format!("{dir}/{f}")).unwrap_or_else(|e| panic!("{f}: {e}"));
    let chain = wrap::SHIPPED.replace(',', "_");
    assert_eq!(fk.vk_bytes(), read(&format!("final-{chain}.vk")), "derived final key ≠ the prover's");
    let run = machine::execute_exact(&common::parse(common::ADD), &[7, 5], 1 << 40, step as u32).unwrap();
    let st = run.statement;
    let ivc_bytes = read("add.tri.ivc");
    let proof = ivc::IvcProof::from_bytes(&ivc_bytes, |lr| ivc::key(&ivc_whir, lr as usize)).unwrap();
    let prep = ivc::prepare(&st, &ivc_whir, proof.log_rows, proof.start, proof.segments, proof.chain).unwrap();
    let pn = ivc::verify_claim(&prep, &proof).unwrap();
    let x = wrap::public_digest_native(&prep.publics, &pn).unwrap();
    let w0 = read("add.tri.w0-4i:16");
    let w1 = read("add.tri.w1-4i:16_7i:22");
    let fbytes = read(&format!("add.tri.final-{chain}"));

    // the cases: honest, then decoded single-bit flips of each proof
    let flips = |b: &[u8], parses: &dyn Fn(&[u8]) -> bool, count: usize, seed: u64| -> Vec<Vec<u8>> {
        let mut out = vec![b.to_vec()];
        let mut s = seed;
        while out.len() <= count {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let mut c = b.to_vec();
            c[(s % b.len() as u64) as usize] ^= 1 << ((s >> 40) % 8);
            if parses(&c) {
                out.push(c);
            }
        }
        out
    };
    let ivc_cases = flips(&ivc_bytes, &|c| ivc::IvcProof::from_bytes(c, |lr| ivc::key(&ivc_whir, lr as usize)).is_ok(), 24, 1);
    let w0_cases = flips(&w0, &|c| WrapProof::from_bytes(c, &k0).is_ok(), 24, 2);
    let w1_cases = flips(&w1, &|c| WrapProof::from_bytes(c, &k1).is_ok(), 24, 3);
    let f_cases = flips(&fbytes, &|c| FinalProof::from_bytes(c, &fk).is_ok(), 48, 4);
    let verdicts = |k0: &WrapKey, k1: &WrapKey, fk: &WrapKey| -> Vec<Result<(), String>> {
        let mut v = Vec::new();
        for c in &ivc_cases {
            let p = ivc::IvcProof::from_bytes(c, |lr| ivc::key(&ivc_whir, lr as usize)).unwrap();
            v.push(ivc::verify(&st, &p, &ivc_whir));
        }
        for (k, cases) in [(k0, &w0_cases), (k1, &w1_cases)] {
            for c in cases {
                v.push(wrap::verify_native(k, x, &WrapProof::from_bytes(c, k).unwrap()));
            }
        }
        for c in &f_cases {
            v.push(wrap::verify_final(&prep, fk, &FinalProof::from_bytes(c, fk).unwrap()));
        }
        v
    };
    let under_x = verdicts(&k0, &k1, &fk);
    if choice == "rec" {
        let calls = rec.counts();
        eprintln!("verifiers under the device-named backend: calls {calls:?}");
        assert!(calls.is_empty(), "a verifier called the prover backend: {calls:?}");
    }
    backend::install(Arc::new(Cpu2));
    let under_cpu = verdicts(&k0, &k1, &fk);
    let evil = Arc::new(Rec::new("evil-device", true));
    backend::install(evil.clone());
    let under_evil = verdicts(&k0, &k1, &fk);
    backend::install(Arc::new(Cpu2));
    let accepted: Vec<usize> = under_cpu.iter().enumerate().filter(|r| r.1.is_ok()).map(|r| r.0).collect();
    let honest = [0, ivc_cases.len(), ivc_cases.len() + w0_cases.len(), ivc_cases.len() + w0_cases.len() + w1_cases.len()];
    assert_eq!(accepted, honest, "exactly the four honest proofs verify");
    assert_eq!(under_x, under_cpu, "{choice} ≠ cpu");
    assert_eq!(under_evil, under_cpu, "a corrupting backend moved a verdict");
    eprintln!("{} verdicts ({} accepted) equal under {choice}, cpu and a corrupting backend (its calls {:?})", under_cpu.len(), accepted.len(), evil.counts());
}
