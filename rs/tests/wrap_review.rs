//! Adversarial review of the wrap chain (`audit/wrap-review-2026-10.md`)
//! on one small chain (IVC 1/16 → inner 1/16 → final 1/16): replays of a
//! level under other public values or another level's key, a true
//! deferred claim at a point the circuit did not derive, a header naming
//! another step size, every AIR message and every opening message of the
//! final proof tampered alone, and the canonical wire form of base
//! symbols.

mod common;

use nebu::{Fp3, Goldilocks};
use zheng::recursion::ivc;
use zheng::recursion::prove::pbar_nox;
use zheng::recursion::state::ClaimV;
use zheng::recursion::wrap::{self, FinalProof, Inner, Mode, WrapParams};

const STEP: u32 = 15;

fn whir() -> lens::WhirParams {
    let mut w = zheng::execution::succinct::params_for(20);
    w.log_inv_rate = 4;
    w.pow_bits = 24;
    w
}

#[test]
fn the_wrap_chain_refuses_replays_foreign_claims_and_every_tampered_message() {
    let prog = common::parse(common::ADD);
    let (st, p) = ivc::prove(&prog, &[7, 5], 1 << 20, &whir(), STEP).unwrap();
    let ikey = ivc::key(&whir(), STEP as usize).unwrap();
    let prep = ivc::prepare(&st, &whir(), STEP, p.start, p.segments, p.chain).unwrap();
    let pn = ivc::verify_claim(&prep, &p).unwrap();
    let k0 = wrap::derive_key_ivc(WrapParams { whir: whir(), n: 0, mode: Mode::Inner }, &ikey).unwrap();
    let (w0, x0) = wrap::prove(&k0, &Inner::Ivc { key: &ikey, proof: &p }, &prep.publics, &pn).unwrap();
    let k1 = wrap::derive_key_wrap(WrapParams { whir: whir(), n: 0, mode: Mode::Final }, &k0).unwrap();
    let (w1, x1) = wrap::prove(&k1, &Inner::Wrap { key: &k0, proof: &w0 }, &prep.publics, &pn).unwrap();
    assert_eq!(x0, x1);
    let fp = FinalProof { log_rows: p.log_rows, start: p.start, segments: p.segments, chain: p.chain, pn: pn.clone(), wrap: w1.clone() };
    wrap::verify_final(&prep, &k1, &fp).unwrap();

    // a level's proof binds its public input: the inner proof under any
    // other digest, either proof under the other level's key
    for i in 0..4 {
        let mut x = x0;
        x[i] += Goldilocks::ONE;
        assert!(wrap::verify_native(&k0, x, &w0).is_err(), "inner wrap under another digest (limb {i})");
        assert!(wrap::verify_native(&k1, x, &w1).is_err(), "final wrap under another digest (limb {i})");
    }
    let swapped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (wrap::verify_native(&k1, x0, &w0).is_err(), wrap::verify_native(&k0, x0, &w1).is_err())
    }));
    assert!(matches!(swapped, Ok((true, true))), "a level's proof under the other level's key");
    // a final-mode key never enters a circuit
    assert!(wrap::derive_key_wrap(WrapParams { whir: whir(), n: 0, mode: Mode::Final }, &k1).is_err());

    // the deferred nox-public claim: a *true* claim at a point the
    // circuit did not derive passes the native evaluation and is refused
    // by the public digest the circuit output
    let mut point = pn.point.clone();
    point[0] += Fp3::ONE;
    point[pn.point.len() - 1] += Fp3::from_base(Goldilocks::new(3));
    let value = pbar_nox(&prep.global, &point, prep.key.params.n);
    let mut bad = fp.clone();
    bad.pn = ClaimV { point, value };
    let e = wrap::verify_final(&prep, &k1, &bad).unwrap_err();
    assert!(!e.contains("deferred nox publics"), "the claim itself is true: {e}");

    // a header naming another step size: refused by the key, before any
    // evaluation
    let mut bad = fp.clone();
    bad.log_rows = STEP + 1;
    let e = wrap::verify_statement(&st, &whir(), &k1, &bad).unwrap_err();
    assert!(e.contains("another recursive proof") || e.contains("geometry"), "{e}");

    // every AIR message and every opening message alone
    let refuse = |bad: &FinalProof, what: String| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wrap::verify_final(&prep, &k1, bad)));
        assert!(matches!(r, Ok(Err(_))), "{what} accepted (or panicked)");
    };
    let one = Fp3::ONE;
    let t = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
    let mut count = 0;
    for d in [one, t] {
        for i in 0..fp.wrap.local.len() {
            let mut bad = fp.clone();
            bad.wrap.local[i] += d;
            refuse(&bad, format!("local column {i}"));
            count += 1;
        }
        for i in 0..fp.wrap.next.len() {
            let mut bad = fp.clone();
            bad.wrap.next[i] += d;
            refuse(&bad, format!("successor column {i} ({})", k1.next_cols[i]));
            count += 1;
        }
        for (r, m) in fp.wrap.zerocheck.iter().enumerate() {
            for j in 0..m.len() {
                let mut bad = fp.clone();
                bad.wrap.zerocheck[r][j] += d;
                refuse(&bad, format!("zerocheck round {r} coefficient {j}"));
                count += 1;
            }
        }
        for j in 0..fp.wrap.ood[0].len() {
            let mut bad = fp.clone();
            bad.wrap.ood[0][j] += d;
            refuse(&bad, format!("OOD answer {j}"));
            count += 1;
        }
        let wp = &fp.wrap.whir;
        for j in 0..wp.ood0.len() {
            let mut bad = fp.clone();
            bad.wrap.whir.ood0[j] += d;
            refuse(&bad, format!("WHIR OOD {j}"));
            count += 1;
        }
        for j in 0..wp.sumcheck0.len() {
            let mut bad = fp.clone();
            bad.wrap.whir.sumcheck0[j] += d;
            refuse(&bad, format!("WHIR sumcheck0 {j}"));
            count += 1;
        }
        for (r, rd) in wp.rounds.iter().enumerate() {
            for j in 0..rd.sumcheck.len() {
                let mut bad = fp.clone();
                bad.wrap.whir.rounds[r].sumcheck[j] += d;
                refuse(&bad, format!("WHIR round {r} sumcheck {j}"));
                count += 1;
            }
            for j in 0..rd.ood.len() {
                let mut bad = fp.clone();
                bad.wrap.whir.rounds[r].ood[j] += d;
                refuse(&bad, format!("WHIR round {r} OOD {j}"));
                count += 1;
            }
        }
        for j in 0..wp.final_poly.len() {
            let mut bad = fp.clone();
            bad.wrap.whir.final_poly[j] += d;
            refuse(&bad, format!("final polynomial {j}"));
            count += 1;
        }
    }
    eprintln!("{count} single-message tampers refused");

    // base symbols travel as one limb: their extension limbs never reach
    // the verifier (the in-memory value is not canonical, the wire form
    // is), so a proof differing only there is the same proof on the wire
    let mut odd = fp.clone();
    odd.wrap.whir.rounds[0].open[0][0].symbols[0].c1 += Goldilocks::ONE;
    assert_eq!(odd.to_bytes(&k1), fp.to_bytes(&k1), "base symbols are one limb on the wire");
    let back = FinalProof::from_bytes(&fp.to_bytes(&k1), &k1).unwrap();
    assert_eq!(back, fp);
}
