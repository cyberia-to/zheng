//! Wrap proofs: the IVC final verifier proved by an inner wrap, that
//! verifier proved by a final wrap — the outermost proof verifies against
//! its statement; wrong statements, a wrong deferred claim and tampered
//! proofs are refused.

mod common;

use nebu::{Fp3, Goldilocks};
use zheng::machine::{self, MachineStatement};
use zheng::recursion::ivc;
use zheng::recursion::wrap::{self, FinalProof, Inner, Mode, WrapKey, WrapParams};

const STEP: u32 = 15;

fn whir(rate: u8) -> lens::WhirParams {
    let mut w = zheng::execution::succinct::params_for(20);
    w.log_inv_rate = rate;
    w.pow_bits = 24;
    w
}

fn refuses(st: &MachineStatement, fp: &FinalProof, k: &WrapKey, what: &str) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify(st, fp, k)));
    assert!(matches!(r, Ok(Err(_))), "{what} accepted");
}

fn verify(st: &MachineStatement, fp: &FinalProof, k: &WrapKey) -> Result<(), String> {
    wrap::verify_statement(st, &whir(4), k, fp)
}

#[test]
fn a_wrapped_proof_verifies_and_binds_its_statement() {
    let prog = common::parse(common::ADD);
    let (st, p) = ivc::prove(&prog, &[7, 5], 1 << 20, &whir(4), STEP).unwrap();
    let ikey = ivc::key(&whir(4), STEP as usize).unwrap();
    let prep = ivc::prepare(&st, &whir(4), STEP, p.start, p.segments, p.chain).unwrap();
    let pn = ivc::verify_claim(&prep, &p).unwrap();
    let k0 = wrap::derive_key_ivc(WrapParams { whir: whir(4), n: 0, mode: Mode::Inner }, &ikey).unwrap();
    let (w0, x0) = wrap::prove(&k0, &Inner::Ivc { key: &ikey, proof: &p }, &prep.publics, &pn).unwrap();
    wrap::verify_native(&k0, x0, &w0).unwrap();
    let k1 = wrap::derive_key_wrap(WrapParams { whir: whir(4), n: 0, mode: Mode::Final }, &k0).unwrap();
    let (w1, x1) = wrap::prove(&k1, &Inner::Wrap { key: &k0, proof: &w0 }, &prep.publics, &pn).unwrap();
    assert_eq!(x0, x1, "every level binds the same public values");
    let fp = FinalProof { log_rows: p.log_rows, start: p.start, segments: p.segments, chain: p.chain, pn: pn.clone(), wrap: w1 };
    let bytes = fp.to_bytes(&k1);
    let fp = FinalProof::from_bytes(&bytes, &k1).unwrap();
    verify(&st, &fp, &k1).unwrap();
    // the inner wrap refuses tampering too
    let mut bad = w0.clone();
    bad.local[5] += Fp3::ONE;
    assert!(wrap::verify_native(&k0, x0, &bad).is_err());
    // wrong statements
    let mut other = st.clone();
    other.output = machine::statement::tokens(&zheng::execution::ExecutionNoun::Atom(13));
    refuses(&other, &fp, &k1, "a wrong output");
    let mut other = st.clone();
    other.input = vec![7, 6];
    refuses(&other, &fp, &k1, "a wrong input");
    let mut other = st.clone();
    other.cycles += 1;
    refuses(&other, &fp, &k1, "a wrong cycle count");
    // a wrong deferred claim, tampered messages
    let mut bad = fp.clone();
    bad.pn.value += Fp3::ONE;
    refuses(&st, &bad, &k1, "a deferred claim value");
    let mut bad = fp.clone();
    bad.pn.point[3] += Fp3::ONE;
    refuses(&st, &bad, &k1, "a deferred claim point");
    let tamper: Vec<Box<dyn Fn(&mut FinalProof)>> = vec![
        Box::new(|p| p.wrap.roots[0][1] += Goldilocks::ONE),
        Box::new(|p| p.wrap.ood[0][0] += Fp3::ONE),
        Box::new(|p| p.wrap.zerocheck[2][4] += Fp3::ONE),
        Box::new(|p| p.wrap.local[17] += Fp3::ONE),
        Box::new(|p| p.wrap.next[0] += Fp3::ONE),
        Box::new(|p| p.wrap.whir.sumcheck0[1] += Fp3::ONE),
        Box::new(|p| p.wrap.whir.final_poly[0] += Fp3::ONE),
        Box::new(|p| p.wrap.whir.rounds[0].open[0][0].symbols[2] += Fp3::ONE),
        Box::new(|p| p.segments += 1),
        Box::new(|p| p.chain[0] += Goldilocks::ONE),
        Box::new(|p| p.start += 32),
    ];
    for (i, f) in tamper.iter().enumerate() {
        let mut bad = fp.clone();
        f(&mut bad);
        refuses(&st, &bad, &k1, &format!("tamper {i}"));
    }
}
