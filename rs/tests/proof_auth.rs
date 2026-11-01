//! Transactions without signatures: a zk-profile (veil) proof that the
//! prover knows a secret key `k` (four Goldilocks limbs) whose hemera hash is
//! the account's public key, bound to a 32-byte transaction digest. The
//! statement carries the program and the key hash (the public output) and
//! nothing of `k`; the digest rides in the envelope's `context`, which
//! `prove_zk` absorbs into the transcript (`veil::prove_bound` over
//! `zk_statement_bytes`). The proof therefore authorises exactly one
//! transaction: the same bytes verify against no other digest.
//!
//! Measured (numbers print with `--nocapture`, one machine-readable line
//! starting `P5 `): veil proof bytes and envelope bytes (median/min/max of
//! 11 proofs), prove time (median), verify time cold (`Envelope::verify`,
//! median of 21) and with a cached `VerifyingKey` (`veil::verify_bound`,
//! median of 21). Asserted: the context binds, the claimed key hash binds,
//! 64 spread single-bit flips of the envelope are all rejected, and the key
//! limbs appear nowhere in the statement or the envelope bytes.
//!
//! `ZHENG_BACKEND=metal` (or `auto`, `webgpu`) installs that lens prover
//! backend for the process before proving; unset is the CPU backend.
//!
//! Serves soft3 release/director/plan.md row P5 (decision D16).
//!
//! The formula. nox pattern 15 is the structural hash of its argument noun
//! (the digest of the noun's tree, then the hemera permutation), and the
//! hash.tri idiom feeds it the 8-element right-nested list
//! `[x0 [x1 [... [x6 x7]]]]`, built with pattern 3 (cons): `cons8`. Pattern
//! 16 is `[16 [tag check]]`: the prover injects a witness `w`, then
//! `check` runs on `[w subject]` and must return 0; with tag `[1 0]` and
//! check `[1 0]` (quote 0) it is a bare secret read. The relation compiler
//! consumes the secret stream in evaluation order, and cons evaluates its
//! left child before its right, so
//!
//!   chain = cons(S, cons(S, cons(S, cons(S, [0 1]))))   S = [16 [[1 0] [1 0]]]
//!
//! reads k0, k1, k2, k3 in that order and builds the subject
//! `[k0 [k1 [k2 [k3 s]]]]` (`s` the original subject, `[0 1]`). In that
//! subject k0 is axis 2, k1 axis 6 (left of right), k2 axis 14, k3 axis 30
//! (axis `a`: bits after the leading 1, 0 = left, 1 = right). The program is
//!
//!   [2 [chain [1 [15 cons8(axis2, axis6, axis14, axis30, 0, 0, 0, 0)]]]]]
//!
//! (pattern 2 runs the quoted hash formula on the subject `chain` built),
//! i.e. `hemera(k0, k1, k2, k3, 0, 0, 0, 0)` with all four limbs secret. The
//! same hash of four PUBLIC inputs is the cross-check (`certify_execution`;
//! the last input sits at the subject's head, so it is given `[k3 k2 k1 k0]`),
//! and so is native nox reducing the hash of the constant 8-list.
mod common;

use common::parse;
use std::time::Instant;
use zheng::envelope::{Envelope, ZkProof, prove_zk, zk_statement_bytes};
use zheng::execution::{ExecutionNoun, VerifyingKey, certify_execution, veil};

const BUDGET: u64 = 1_000_000;

/// The account's secret key: four limbs below the modulus, two of them large.
const KEY: [u64; 4] = [
    0x7FFF_FFFF_FFFF_FFC5,
    0xDEAD_BEEF_CAFE_F00D,
    0x0123_4567_89AB_CDEF,
    0xFFFF_FFFE_FFFF_FFFF,
];

/// A sample transaction (any byte string stands for the serialised
/// transaction) and a different one, for the context-binding check.
const TX: &[u8] = b"transfer 42 tokens from account A to account B, nonce 7";
const OTHER_TX: &[u8] = b"transfer 4200 tokens from account A to account C, nonce 7";

/// The transaction digest: hemera of the transaction bytes.
fn tx_digest(tx: &[u8]) -> [u8; 32] {
    *hemera::hash(tx).as_bytes()
}

/// `[3 [a0 [3 [a1 ... [3 [a_{n-2} a_{n-1}]]]]]]`: the right-nested cons list.
fn cons_list(items: &[String]) -> String {
    match items {
        [only] => only.clone(),
        [first, rest @ ..] => format!("[3 [{first} {}]]", cons_list(rest)),
        [] => unreachable!(),
    }
}

fn zeros(n: usize) -> impl Iterator<Item = String> {
    (0..n).map(|_| "[1 0]".to_string())
}

/// `[15 hash-input]` over the axes of the pushed keys and four zeros.
fn hash_of_axes() -> String {
    let items: Vec<String> = ["[0 2]", "[0 6]", "[0 14]", "[0 30]"]
        .iter()
        .map(|s| s.to_string())
        .chain(zeros(4))
        .collect();
    format!("[15 {}]", cons_list(&items))
}

/// The key hash of four SECRET limbs, read in order k0..k3.
fn program_secret() -> ExecutionNoun {
    let secret = "[16 [[1 0] [1 0]]]".to_string();
    let items = vec![
        secret.clone(),
        secret.clone(),
        secret.clone(),
        secret,
        "[0 1]".to_string(),
    ];
    parse(&format!(
        "[2 [{} [1 {}]]]",
        cons_list(&items),
        hash_of_axes()
    ))
}

/// The same hash of four PUBLIC inputs (the subject is `[k0 [k1 [k2 [k3 0]]]]`).
fn program_public() -> ExecutionNoun {
    parse(&hash_of_axes())
}

/// The hash of the constant 8-list, reduced by native nox.
fn native_nox() -> Vec<u64> {
    fn arena(r: &mut nox::Reduction<8192>, n: &ExecutionNoun) -> nox::Order {
        match n {
            ExecutionNoun::Atom(v) => r.atom(nebu::Goldilocks::new(*v)).unwrap(),
            ExecutionNoun::Pair(a, b) => {
                let a = arena(r, a);
                let b = arena(r, b);
                r.pair(a, b).unwrap()
            }
        }
    }
    fn flatten(r: &nox::Reduction<8192>, o: nox::Order, out: &mut Vec<u64>) {
        match r.get(o).unwrap().inner {
            nox::data::Data::Atom { value } => out.push(value.as_u64()),
            nox::data::Data::Pair { left, right } => {
                flatten(r, left, out);
                flatten(r, right, out);
            }
        }
    }
    let items: Vec<String> = KEY
        .iter()
        .map(|k| format!("[1 {k}]"))
        .chain(zeros(4))
        .collect();
    let formula = parse(&format!("[15 {}]", cons_list(&items)));
    let mut r = Box::new(nox::Reduction::<8192>::new());
    let subject = arena(&mut r, &ExecutionNoun::Atom(0));
    let formula = arena(&mut r, &formula);
    match nox::reduce(
        &mut r,
        subject,
        formula,
        BUDGET,
        &nox::NullCalls,
        &mut nox::NoTrace,
    ) {
        nox::Outcome::Ok(o, _) => {
            let mut out = vec![];
            flatten(&r, o, &mut out);
            out
        }
        other => panic!("native nox: {other:?}"),
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}
fn veil_len(e: &Envelope) -> usize {
    match e {
        Envelope::Zk { proof, .. } => proof.as_bytes().len(),
        _ => unreachable!("a zk envelope"),
    }
}

#[test]
fn proof_authorized_transaction_binds_the_digest_and_is_measured() {
    // the prover backend: the CPU unless `ZHENG_BACKEND` (cpu, metal, webgpu,
    // auto) installs another one for the process (an explicit choice that is
    // unavailable fails the test)
    let (backend, device) = match std::env::var("ZHENG_BACKEND") {
        Ok(choice) => cyber_lens_gpu::install(choice.parse::<cyber_lens_gpu::Choice>().unwrap())
            .unwrap_or_else(|e| panic!("backend `{choice}`: {e}")),
        Err(_) => ("cpu", "default".to_string()),
    };
    println!("backend: {backend} ({device})");

    // the key hash, three ways
    let program = program_secret();
    let public_input = [KEY[3], KEY[2], KEY[1], KEY[0]];
    let (public, _) = certify_execution(&program_public(), &public_input, BUDGET).unwrap();
    assert_eq!(public.public_output.len(), 4, "a 4-limb key hash");
    assert_eq!(
        public.public_output,
        native_nox(),
        "the compiled hash equals native nox on the 8-list"
    );

    let digest = tx_digest(TX);
    let other_digest = tx_digest(OTHER_TX);
    assert_ne!(digest, other_digest);

    // prove
    let reps = 11;
    let (mut prove_ms, mut proof_sizes, mut env_sizes) = (vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..reps {
        let t = Instant::now();
        let envelope = prove_zk(&program, &[], &KEY, BUDGET, digest).unwrap();
        prove_ms.push(ms(t));
        proof_sizes.push(veil_len(&envelope));
        env_sizes.push(envelope.to_bytes().len());
        last = Some(envelope);
    }
    let envelope = last.unwrap();
    let bytes = envelope.to_bytes();
    let Envelope::Zk {
        statement,
        context,
        proof: ZkProof::Veil(proof),
    } = envelope.clone()
    else {
        panic!("a veil zk envelope")
    };
    assert_eq!(context, digest);
    assert_eq!(
        statement.execution.public_output, public.public_output,
        "the proof's key hash is the public-input key hash"
    );
    assert_eq!(Envelope::from_bytes(&bytes).unwrap(), envelope);

    // d. nothing of the key in the statement or the envelope
    assert!(
        statement.execution.public_input.is_empty(),
        "no public input"
    );
    for k in KEY {
        let le = k.to_le_bytes();
        assert!(
            !bytes.windows(8).any(|w| w == &le[..]),
            "key limb {k:#x} appears in the envelope"
        );
    }

    // verify: cold, and with a cached key through the bound entry point
    envelope.verify(None).unwrap();
    let vk = VerifyingKey::for_execution(&statement.execution).unwrap();
    let bound = zk_statement_bytes(&statement, &context);
    veil::verify_bound(&statement, &proof, Some(&vk), &bound).unwrap();
    let cold = median(
        (0..21)
            .map(|_| {
                let t = Instant::now();
                envelope.verify(None).unwrap();
                ms(t)
            })
            .collect(),
    );
    let cached = median(
        (0..21)
            .map(|_| {
                let t = Instant::now();
                veil::verify_bound(&statement, &proof, Some(&vk), &bound).unwrap();
                ms(t)
            })
            .collect(),
    );
    println!(
        "{:?}",
        veil::report(&statement, &veil::HidingParams::default()).unwrap()
    );

    // a. the digest of another transaction does not verify
    let moved = Envelope::Zk {
        statement: statement.clone(),
        context: other_digest,
        proof: ZkProof::Veil(proof.clone()),
    };
    assert!(moved.verify(None).is_err(), "other tx digest accepted");
    assert!(
        veil::verify_bound(
            &statement,
            &proof,
            Some(&vk),
            &zk_statement_bytes(&statement, &other_digest)
        )
        .is_err(),
        "other tx digest accepted (cached key)"
    );

    // b. another key hash does not verify, in any of its four limbs
    for limb in 0..4 {
        let mut forged = statement.clone();
        forged.execution.public_output[limb] ^= 1;
        let e = Envelope::Zk {
            statement: forged,
            context,
            proof: ZkProof::Veil(proof.clone()),
        };
        assert!(e.verify(None).is_err(), "forged key hash limb {limb} accepted");
    }

    // c. 64 single-bit flips spread evenly over the envelope
    let flips = 64usize;
    let mut accepted = 0usize;
    for i in 0..flips {
        let (byte, bit) = (i * bytes.len() / flips, (i % 8) as u32);
        let mut bad = bytes.clone();
        bad[byte] ^= 1u8 << bit;
        if Envelope::from_bytes(&bad).is_ok_and(|e| e.verify(None).is_ok()) {
            eprintln!("accepted flip: byte {byte} bit {bit}");
            accepted += 1;
        }
    }

    let (lo, hi) = (
        *proof_sizes.iter().min().unwrap(),
        *proof_sizes.iter().max().unwrap(),
    );
    let sizes_f = |v: &[usize]| v.iter().map(|&x| x as f64).collect::<Vec<_>>();
    let proof_med = median(sizes_f(&proof_sizes)) as usize;
    let env_med = median(sizes_f(&env_sizes)) as usize;
    let threads = std::env::var("ZHENG_THREADS").unwrap_or_else(|_| "unset".into());
    println!(
        "P5 arch={} os={} ZHENG_THREADS={threads} backend={backend} key_limbs=4 proof_B={proof_med},{lo},{hi} \
         envelope_B={env_med} prove_ms={:.1} verify_cold_ms={cold:.3} verify_cached_ms={cached:.3} \
         flips_accepted={accepted}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        median(prove_ms),
    );
    assert_eq!(accepted, 0, "a bit flip was accepted");
}
