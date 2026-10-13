//! zheng #60 review (`audit/proof-stack-review-2026-10.md`): keys a
//! verifier derives under a corrupting prover backend.
//!
//! The verifier's keys are derived in-process; the derivation commits the
//! IVC key's words (Merkle levels, coset leaves, permutation batches) on
//! the process's prover backend. Under a backend that corrupts its
//! results, the derived keys must be refused (pinned digests) rather than
//! verify against a wrong key root.
//!
//! One test, one process: the backend is process-wide and the keys are
//! cached per process.

#[path = "common/rec.rs"]
mod rec;

use std::sync::Arc;

use lens::rspcs::backend;
use rec::Rec;
use zheng::envelope::{Profile, keys, recursive, wrapped};
use zheng::recursion::ivc;

#[test]
fn keys_derived_under_a_corrupting_backend_are_refused() {
    backend::install(Arc::new(Rec::new("evil-device", true)));
    let (ivc_whir, _) = wrapped::chain();
    let step = wrapped::admitted_ivc().1;
    // the derivation itself completes; its key-word root is another
    let raw = ivc::key(&recursive::params(), step).unwrap();
    assert_ne!(Some(raw.kw_root.map(|x| x.as_u64())), recursive::KEY_ROOTS.iter().find(|r| r.0 == recursive::params().header()).map(|r| r.1));
    // before the fix the profile-5 verifier used it: the honest proof is
    // then checked against a wrong root (here refused; a reproducible
    // device fault would let a prover open the key words to other values)
    // — now every verifier-facing key path refuses it
    let r5 = recursive::key(&recursive::params(), step as u32);
    assert!(r5.as_ref().is_err_and(|e| e.contains("not the pinned ones")), "{:?}", r5.map(|_| ()));
    assert!(keys::export(Profile::Recursive).is_err());
    let w6 = ivc::key(&ivc_whir, step).unwrap();
    assert!(recursive::pinned_key(&ivc_whir, w6).is_err());
    assert!(wrapped::final_key().is_err());
    eprintln!("keys derived under a corrupting backend: every verifier-facing key path refuses them");
}
