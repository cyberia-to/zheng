//! zheng #60/#61 review (`audit/proof-stack-review-2026-10.md`): the
//! split key's sent limbs against the committed words, the program digest
//! across every level, key bundles, the size gate, and the inner levels'
//! ledgers from the keys the chain actually derives.
//!
//! The ignored tests read the stored proofs of `add.tri` under
//! `wrap::SHIPPED`: `ZHENG_IVC_DIR=<dir> cargo test --release -p zheng
//! --test proof_stack_review -- --ignored`, `<dir>` holding `add.tri.ivc`,
//! `add.tri.w0-4i:16`, `add.tri.w1-4i:16_7i:22`,
//! `add.tri.final-4i:16_7i:22_9f:26` and `final-4i:16_7i:22_9f:26.vk`
//! (`examples/wrap_bench`, `examples/wrap_verify`).

mod common;

use std::sync::OnceLock;

use nebu::{Fp3, Goldilocks};
use zheng::envelope::{Envelope, EnvelopeError, Profile, keys, wrapped};
use zheng::execution::NounToken;
use zheng::machine::{self, MachineStatement};
use zheng::recursion::gm;
use zheng::recursion::ivc;
use zheng::recursion::ops::Native;
use zheng::recursion::perm::tag;
use zheng::recursion::splitkey;
use zheng::recursion::sponge::Sponge;
use zheng::recursion::state::ClaimV;
use zheng::recursion::wrap::{self, CBITS, FinalProof, Mode, WrapKey, WrapProof};

fn pinned(i: usize) -> [Goldilocks; 4] {
    wrapped::INNER_ROOTS[i].map(Goldilocks::new)
}

/// The inner levels' keys as a verifier derives them (over the pinned
/// roots; their words never committed).
fn inner_keys() -> &'static (WrapKey, WrapKey) {
    static K: OnceLock<(WrapKey, WrapKey)> = OnceLock::new();
    K.get_or_init(|| {
        let (ivc_whir, levels) = wrapped::chain();
        let ikey = ivc::key(&ivc_whir, wrapped::admitted_ivc().1).unwrap();
        let k0 = wrap::derive_key_ivc_at(levels[0], &ikey, pinned(0)).unwrap();
        let k1 = wrap::derive_key_wrap_at(levels[1], &k0, pinned(1)).unwrap();
        (k0, k1)
    })
}

struct Stored {
    st: MachineStatement,
    prep: ivc::Prepared,
    pn: ClaimV<Fp3>,
    x: [Goldilocks; 4],
    w0: WrapProof,
    w1: WrapProof,
    fk: WrapKey,
    fbytes: Vec<u8>,
}

fn stored() -> &'static Stored {
    static S: OnceLock<Stored> = OnceLock::new();
    S.get_or_init(|| {
        let dir = std::env::var("ZHENG_IVC_DIR").expect("ZHENG_IVC_DIR");
        let read =
            |f: &str| std::fs::read(format!("{dir}/{f}")).unwrap_or_else(|e| panic!("{f}: {e}"));
        let (ivc_whir, _) = wrapped::chain();
        let step = wrapped::admitted_ivc().1;
        let proof =
            ivc::IvcProof::from_bytes(&read("add.tri.ivc"), |lr| ivc::key(&ivc_whir, lr as usize))
                .expect("stored IVC proof");
        let run =
            machine::execute_exact(&common::parse(common::ADD), &[7, 5], 1 << 40, step as u32)
                .expect("run");
        let st = run.statement;
        let prep = ivc::prepare(
            &st,
            &ivc_whir,
            proof.log_rows,
            proof.start,
            proof.segments,
            proof.chain,
        )
        .expect("prepare");
        let pn = ivc::verify_claim(&prep, &proof).expect("the stored IVC proof verifies");
        let x = wrap::public_digest_native(&prep.publics, &pn).unwrap();
        let (k0, k1) = inner_keys();
        let w0 = WrapProof::from_bytes(&read("add.tri.w0-4i:16"), k0).expect("level 0");
        let w1 = WrapProof::from_bytes(&read("add.tri.w1-4i:16_7i:22"), k1).expect("level 1");
        let chain = wrap::SHIPPED.replace(',', "_");
        let vk = read(&format!("final-{chain}.vk"));
        let fk = WrapKey::from_vk_bytes(&vk).expect("stored final key");
        // the final key a verifier derives over the pinned roots is the
        // prover's (byte for byte)
        assert_eq!(
            wrapped::final_key().unwrap().vk_bytes(),
            vk,
            "derived final key ≠ the prover's"
        );
        let fbytes = read(&format!("add.tri.final-{chain}"));
        Stored {
            st,
            prep,
            pn,
            x,
            w0,
            w1,
            fk,
            fbytes,
        }
    })
}

/// The inner verifier's transcript up to `γ_k`: (`ρ`, `γ_k`).
fn replay(k: &WrapKey, x: [Goldilocks; 4], pf: &WrapProof) -> (Vec<Fp3>, Vec<Fp3>) {
    assert_eq!(k.params.mode, Mode::Inner);
    let mut o = Native::new();
    let mut t = Sponge::new(&mut o, tag::WRAP);
    let xv: Vec<Fp3> = x.iter().map(|&v| Fp3::from_base(v)).collect();
    t.absorb_all(&mut o, &xv);
    let bind = |o: &mut Native, t: &mut Sponge<Native>, a: &[Fp3]| {
        for &y in a {
            t.squeeze_ext(o);
            t.absorb_free_ext(o, y);
        }
    };
    for r in pf.roots[0] {
        t.absorb_free(&mut o, r);
    }
    bind(&mut o, &mut t, &pf.ood[0]);
    t.squeeze_ext(&mut o);
    t.squeeze_ext(&mut o);
    for r in pf.roots[1] {
        t.absorb_free(&mut o, r);
    }
    bind(&mut o, &mut t, &pf.ood[1]);
    t.squeeze_exts(&mut o, k.params.n);
    t.squeeze_ext(&mut o);
    let mut rho = Vec::new();
    for m in &pf.zerocheck {
        for &h in m {
            t.absorb_free_ext(&mut o, h);
        }
        rho.push(t.squeeze_ext(&mut o));
    }
    for &v in pf.local.iter().chain(&pf.next).chain(&pf.key) {
        t.absorb_free_ext(&mut o, v);
    }
    let gk = t.squeeze_exts(&mut o, splitkey::BITS);
    (rho, gk)
}

fn err(k: &WrapKey, x: [Goldilocks; 4], pf: &WrapProof) -> String {
    wrap::verify_native(k, x, pf).expect_err("accepted")
}

/// The split key: the limbs a prover sends at `ρ` are bound to the
/// committed base words, not trusted. Per inner level of the shipped
/// chain (stored proofs):
///
/// - honest: the sent physical columns are exactly the key's limbs at `ρ`
///   (`splitkey::at`), and the proof verifies;
/// - limbs moved so the rebuilt logical column is unchanged
///   (`p₀ − T·δ`, `p₁ + δ`): the constraint check passes and the key-claim
///   identity refuses;
/// - the same, the first word's value re-solved so the key-claim identity
///   holds: the opening of the committed word refuses (neither the
///   constraints nor the key claim fail first);
/// - a base-only column moved: refused;
/// - a non-canonical limb on the wire: refused by the parser.
#[test]
#[ignore = "stored proofs (ZHENG_IVC_DIR)"]
fn split_key_limbs_are_bound_to_the_committed_words() {
    let s = stored();
    let (k0, k1) = inner_keys();
    for (lvl, k, w) in [(0, k0, &s.w0), (1, k1, &s.w1)] {
        // level 1's public input is the level-0 public digest: the same X
        wrap::verify_native(k, s.x, w)
            .unwrap_or_else(|e| panic!("level {lvl}: honest proof refused: {e}"));
        assert_eq!(k.key_root, Some(pinned(lvl)));
        assert_eq!(
            k.key_phys.len(),
            132,
            "level {lvl}: 108 logical + 2·12 limbs"
        );
        assert_eq!(k.key_words(), 3);
        let (rho, gk) = replay(k, s.x, w);
        assert_eq!(
            w.key,
            splitkey::at(&k.sparse, &k.key_phys, &rho),
            "level {lvl}: sent ≠ the key's limbs at ρ"
        );

        let ext_col = k
            .key_phys
            .iter()
            .find(|p| p.1 == 1)
            .expect("an Fp3 column")
            .0;
        let at = |c: u16, l: u8| k.key_phys.iter().position(|&p| p == (c, l)).unwrap();
        let (i0, i1) = (at(ext_col, 0), at(ext_col, 1));
        let t = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
        let delta = Fp3::new(
            Goldilocks::new(12345),
            Goldilocks::new(678),
            Goldilocks::new(9),
        );
        let mut bad = w.clone();
        bad.key[i1] += delta;
        bad.key[i0] -= t * delta;
        // the logical column is unchanged
        {
            let mut o = Native::new();
            let a = splitkey::logical(&mut o, &k.key_phys, &w.key, k.sparse.len());
            let b = splitkey::logical(&mut o, &k.key_phys, &bad.key, k.sparse.len());
            assert_eq!(a, b);
        }
        let e = err(k, s.x, &bad);
        assert!(
            !e.contains("constraints"),
            "level {lvl}: limb shift refused at the constraints: {e}"
        );
        // the key-claim identity at the new γ_k with the committed words'
        // true values there (what an opening binds v_w to) refuses the
        // shifted limbs and accepts the honest ones
        let (_, gk2) = replay(k, s.x, &bad);
        assert_ne!(gk, gk2);
        let mut o = Native::new();
        let true_v: Vec<Fp3> = (0..k.key_words())
            .map(|wi| {
                let cols: Vec<Fp3> = (0..64)
                    .map(|j| w.key.get(64 * wi + j).copied().unwrap_or(Fp3::ZERO))
                    .collect();
                gm::mle(&mut o, &cols, &gk2[..CBITS])
            })
            .collect();
        let sum = |o: &mut Native, v: &[Fp3]| {
            v.iter().enumerate().fold(Fp3::ZERO, |a, (wi, &x)| {
                a + gm::eq_row(o, wi, &gk2[CBITS..]) * x
            })
        };
        let rhs = sum(&mut o, &true_v);
        assert_eq!(
            gm::mle(&mut o, &w.key, &gk2),
            rhs,
            "level {lvl}: honest limbs fail the identity"
        );
        assert_ne!(
            gm::mle(&mut o, &bad.key, &gk2),
            rhs,
            "level {lvl}: shifted limbs pass the identity"
        );

        // re-solve v_0 so the key claim holds at the new γ_k: refused by
        // what follows it (the shift and the opening), never accepted
        let kv = gm::mle(&mut o, &bad.key, &gk2);
        let mut rest = Fp3::ZERO;
        for (wi, &v) in bad.kv.iter().enumerate().skip(1) {
            rest += gm::eq_row(&mut o, wi, &gk2[CBITS..]) * v;
        }
        let e0 = gm::eq_row(&mut o, 0, &gk2[CBITS..]);
        bad.kv[0] = (kv - rest) * e0.inv();
        let e = err(k, s.x, &bad);
        assert!(
            !e.contains("key claim") && !e.contains("constraints"),
            "level {lvl}: solved key claim refused at {e}"
        );
        eprintln!(
            "level {lvl}: limbs shifted (logical unchanged) → refused after the constraints; key claim re-solved → {e}"
        );

        // a base-only column
        let base_col = (0..k.sparse.len() as u16)
            .find(|&c| !k.key_phys.contains(&(c, 1)) && !k.sparse[c as usize].is_empty())
            .unwrap();
        let mut bad = w.clone();
        bad.key[at(base_col, 0)] += Fp3::ONE;
        err(k, s.x, &bad);

        // a non-canonical limb on the wire (the first key value's c0 + p)
        let bytes = w.to_bytes(k);
        let n = k.params.n;
        let off =
            32 * 2 + 24 * (2 * k.fresh + n * (wrap::DEGREE + 1) + k.cols() + k.next_cols.len());
        let limb = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        assert_eq!(limb, w.key[0].c0.as_u64(), "level {lvl}: key offset");
        if let Some(nc) = limb.checked_add(common::P) {
            let mut b = bytes.clone();
            b[off..off + 8].copy_from_slice(&nc.to_le_bytes());
            assert!(
                WrapProof::from_bytes(&b, k).is_err(),
                "level {lvl}: non-canonical limb parsed"
            );
        }
        let mut b = bytes.clone();
        b[off..off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(WrapProof::from_bytes(&b, k).is_err());
        // a wrong count of physical values never reaches the verifier
        let mut short = w.clone();
        short.key.pop();
        assert!(
            wrap::check_shape(k, &short).is_err() && wrap::verify_native(k, s.x, &short).is_err()
        );
        let mut fewer = w.clone();
        fewer.kv.pop();
        assert!(wrap::check_shape(k, &fewer).is_err());
    }
}

/// The program is bound by its digest at every level: another program
/// with the same geometry (one atom changed, same token count, inputs,
/// output, cycles) moves the IVC statement digest, hence the public digest
/// `X` every wrap level outputs — refused by level 0, level 1 and the
/// final level — and a statement naming another digest is refused before
/// any proof work.
#[test]
#[ignore = "stored proofs (ZHENG_IVC_DIR)"]
fn a_substituted_program_is_refused_at_every_level() {
    let s = stored();
    let (k0, k1) = inner_keys();
    // honest
    wrap::verify_final(
        &s.prep,
        &s.fk,
        &FinalProof::from_bytes(&s.fbytes, &s.fk).unwrap(),
    )
    .unwrap();
    let mut other = s.st.clone();
    let i = other
        .program
        .iter()
        .rposition(|t| matches!(t, NounToken::Atom(14)))
        .expect("an atom to change");
    other.program[i] = NounToken::Atom(13);
    assert_ne!(
        machine::program_digest(&other.program),
        machine::program_digest(&s.st.program)
    );
    assert_eq!(other.program.len(), s.st.program.len());
    let (ivc_whir, _) = wrapped::chain();
    let fp = FinalProof::from_bytes(&s.fbytes, &s.fk).unwrap();
    let prep = ivc::prepare(
        &other,
        &ivc_whir,
        fp.log_rows,
        fp.start,
        fp.segments,
        fp.chain,
    )
    .expect("same geometry");
    let x = wrap::public_digest_native(&prep.publics, &s.pn).unwrap();
    assert_ne!(x, s.x, "X does not move with the program");
    assert!(wrap::verify_native(k0, x, &s.w0).is_err(), "level 0");
    assert!(wrap::verify_native(k1, x, &s.w1).is_err(), "level 1");
    assert!(
        wrap::verify_final(&prep, &s.fk, &fp).is_err(),
        "final level"
    );
    // the envelope: the honest statement with another program's digest
    let mut public = s.st.public();
    let honest = Envelope::Wrapped {
        statement: public.clone(),
        proof: Box::new(fp.clone()),
    };
    honest.verify_program(&s.st.program, None).unwrap();
    assert!(honest.verify_program(&other.program, None).is_err());
    public.program = machine::program_digest(&other.program);
    let swapped = Envelope::Wrapped {
        statement: public,
        proof: Box::new(fp),
    };
    assert!(swapped.verify_program(&other.program, None).is_err());
    assert!(swapped.verify_program(&s.st.program, None).is_err());
    let bytes = honest.to_bytes();
    assert_eq!(
        Envelope::from_bytes_for(&bytes, &other.program),
        Err(EnvelopeError::ProgramMismatch)
    );
    assert_eq!(
        Envelope::from_bytes_for(&bytes, &s.st.program).unwrap(),
        honest
    );
    // the digest is over the canonical encoding: a pair where an atom was
    // (one token either way) is another digest
    let mut pair = s.st.program.clone();
    pair[i] = NounToken::Pair;
    assert_ne!(
        machine::program_digest(&pair),
        machine::program_digest(&s.st.program)
    );
}

/// Bundles that look like key bundles but are not the pinned ones: a
/// bundle of real, well-formed layouts of other parameters (an IVC key of
/// another step size; a final key of another chain), and a profile-6
/// bundle with its layouts swapped, are refused by digest before parsing
/// — and nothing is installed.
#[test]
fn a_well_formed_bundle_of_other_keys_is_refused() {
    let tag = b"ZHKEYS01";
    let bundle = |profile: u8, layouts: &[Vec<u8>]| {
        let mut b = tag.to_vec();
        b.push(profile);
        for l in layouts {
            let mut n = l.len() as u64;
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                b.push(if n == 0 { byte } else { byte | 0x80 });
                if n == 0 {
                    break;
                }
            }
            b.extend_from_slice(l);
        }
        b
    };
    let (ivc_whir, _) = wrapped::chain();
    let step = wrapped::admitted_ivc().1;
    let real = ivc::key(&ivc_whir, step).unwrap().layout_bytes();
    // the pinned profile-5 bundle rebuilt here equals the export
    let p5 = keys::export(Profile::Recursive).unwrap();
    assert_eq!(Some(keys::digest(&p5)), keys::pinned(Profile::Recursive));
    let other_step = ivc::key(&ivc_whir, step + 1).unwrap().layout_bytes();
    assert!(
        ivc::Key::from_layout(&other_step).is_ok(),
        "a well-formed layout"
    );
    let fk = wrapped::final_key().unwrap().layout_bytes();
    let mut whir = ivc_whir;
    whir.log_inv_rate = 9;
    whir.pow_bits = 30;
    let ik = ivc::key(&ivc_whir, step).unwrap();
    let other_final = wrap::derive_key_ivc(
        wrap::WrapParams {
            whir,
            n: 0,
            mode: Mode::Final,
        },
        &ik,
    )
    .unwrap()
    .layout_bytes();
    for (what, b) in [
        (
            "profile 5, another step size",
            bundle(5, std::slice::from_ref(&other_step)),
        ),
        (
            "profile 6, another final key",
            bundle(6, &[real.clone(), other_final]),
        ),
        (
            "profile 6, layouts swapped",
            bundle(6, &[fk.clone(), real.clone()]),
        ),
        (
            "profile 6, the IVC key twice",
            bundle(6, &[real.clone(), real.clone()]),
        ),
        (
            "profile 6 without its final key",
            bundle(6, std::slice::from_ref(&real)),
        ),
    ] {
        let r = keys::install(&b);
        assert!(
            r.as_ref().is_err_and(|e| e.contains("pinned")),
            "{what}: {r:?}"
        );
    }
    // the honest export still installs
    assert_eq!(keys::install(&p5), Ok(Profile::Recursive));
}

/// The size gate: the admitted final key's bound is 72,965 B ≤ 72 KiB (73,728 B);
/// a proof one byte over the key's bound, or a length prefix over the
/// envelope's cap, is refused before parsing; random bytes of exactly the
/// bound never parse into a proof (no panic either).
#[test]
fn the_size_gate_refuses_before_parsing() {
    let k = wrapped::final_key().unwrap();
    let max = wrap::max_proof_bytes(&k);
    assert_eq!(max, 72_965);
    assert!(max <= wrapped::MAX_PROOF_BYTES && wrapped::MAX_PROOF_BYTES == 73_728);
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut rnd = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    };
    let mut over = rnd(max + 1);
    over[0] = wrapped::admitted_ivc().1 as u8;
    assert!(
        FinalProof::from_bytes(&over, &k).is_err_and(|e| e.contains("longer than its key allows"))
    );
    for _ in 0..8 {
        let mut b = rnd(max);
        b[0] = wrapped::admitted_ivc().1 as u8;
        assert!(FinalProof::from_bytes(&b, &k).is_err());
    }
    // the envelope: a length prefix past MAX_PROOF_BYTES is TooLarge
    // whatever follows
    let mut env = b"ZHENGPF1".to_vec();
    env.extend_from_slice(&zheng::envelope::VERSION.to_le_bytes());
    env.push(Profile::Wrapped as u8);
    env.push(wrapped::WRAPPED_FORMAT);
    env.extend(wrapped::chain_bytes());
    env.extend([0u8; 32]); // program digest
    env.extend([0, 1, 0, 0, 0, 0, 0]); // inputs: 0; output: 1 token, atom 0; cycles 0; budget 0; no state
    let head = env.len();
    for (n, want) in [
        (wrapped::MAX_PROOF_BYTES + 1, EnvelopeError::TooLarge),
        (usize::MAX >> 1, EnvelopeError::TooLarge),
    ] {
        let mut e = env[..head].to_vec();
        let mut v = n as u64;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            e.push(if v == 0 { byte } else { byte | 0x80 });
            if v == 0 {
                break;
            }
        }
        e.extend(rnd(64));
        assert_eq!(
            Envelope::from_bytes(&e).map(|_| ()),
            Err(want),
            "prefix {n}"
        );
    }
}

/// The inner levels' ledgers from the keys the chain derives (their own
/// opening configurations: three key words, `2·(fresh+1)+3` claims), and
/// every row ≥ 128 bits.
#[test]
fn the_inner_levels_ledgers_are_their_keys() {
    let (k0, k1) = inner_keys();
    for (lvl, k) in [(0, k0), (1, k1)] {
        assert_eq!(
            (k.key_phys.len(), k.key_words()),
            (132, 3),
            "level {lvl}: 108 logical + 2·12 limbs, three base words"
        );
        assert_eq!(k.cfg.groups, vec![1, 1, k.key_words()]);
        assert_eq!(k.cfg.inputs, 2 + k.key_words());
        assert_eq!(k.cfg.claims, 2 * (k.fresh + 1) + k.key_words());
        let rows = wrap::ledger(&k.params, &k.cfg, k.constraints, 0);
        let mut inter = f64::INFINITY;
        for (i, rd) in k.cfg.wc.rounds.iter().enumerate() {
            for (nm, b) in &rows {
                if *nm == format!("fold_{i}") {
                    inter = inter.min(b - f64::from(rd.fold_pow));
                }
                if i > 0 && *nm == format!("shift_{i}") {
                    inter = inter.min(b - f64::from(k.cfg.wc.rounds[i - 1].query_pow));
                }
            }
        }
        if let Some((_, b)) = rows.iter().find(|r| r.0 == "batch combine") {
            inter = inter.min(b - f64::from(k.cfg.comb_pow));
        }
        if let Some((_, b)) = rows.iter().find(|r| r.0 == "fin") {
            inter = inter.min(b - f64::from(k.cfg.wc.rounds.last().unwrap().query_pow));
        }
        for (nm, b) in &rows {
            eprintln!(
                "level {lvl} 1/{} pow {} n {} (constraints {}): {nm:<44} {b:.2}",
                1u32 << k.params.whir.log_inv_rate,
                k.params.whir.pow_bits,
                k.params.n,
                k.constraints
            );
        }
        for (i, rd) in k.cfg.wc.rounds.iter().enumerate() {
            eprintln!("level {lvl} round {i}: {rd:?}");
        }
        let (name, bits) = rows
            .iter()
            .cloned()
            .fold((String::new(), f64::INFINITY), |a, r| {
                if r.1 < a.1 { r } else { a }
            });
        eprintln!(
            "level {lvl}: fresh {} comb_pow {} final_vars {} weakest {name} {bits:.2}; interactive {inter:.2}",
            k.fresh, k.cfg.comb_pow, k.cfg.wc.final_vars
        );
        assert!(bits >= 128.0, "level {lvl}: {name} {bits}");
        // the stated figures (`specs/soundness.md`; review D1)
        let want = [(128.09, 110.23), (128.24, 104.24)][lvl];
        assert!(
            (bits - want.0).abs() < 0.01 && (inter - want.1).abs() < 0.01,
            "level {lvl}: {bits} / {inter}"
        );
    }
    let fk = wrapped::final_key().unwrap();
    for (i, rd) in fk.cfg.wc.rounds.iter().enumerate() {
        eprintln!("final round {i}: {rd:?}");
    }
    eprintln!(
        "final: n {} fresh {} pn {} cols {} next_cols {} final_vars {} arity {:?} max_proof_bytes {}",
        fk.params.n,
        fk.fresh,
        fk.pn,
        fk.cols(),
        fk.next_cols.len(),
        fk.cfg.wc.final_vars,
        fk.cfg.arity,
        wrap::max_proof_bytes(&fk)
    );
}
