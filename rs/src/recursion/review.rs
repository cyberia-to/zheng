//! Adversarial review of the recursion profile (`audit/recursion-review-2026-10.md`):
//! attacks on the binding between a step's public input and the state the
//! final verifier reads, and on the base step.

use lens::Transcript;
use nebu::{Fp3, Goldilocks};

use crate::accumulate::{self, Claim, Instance, Witnessed};
use crate::air::Trace;
use crate::execution::ExecutionNoun;
use crate::machine::{self, air::Machine};
use crate::recursion::circuit::{air::CircuitAir, builder::Builder, trace};
use crate::recursion::ivc::{self, IvcProof};
use crate::recursion::ops::{Native, Ops};
use crate::recursion::params::Params;
use crate::recursion::perm::RATE;
use crate::recursion::program;
use crate::recursion::prove::{self, AccData, StepInput, pbar_nox, pbar_v};
use crate::recursion::relation::{G_POINT, Relation, WORD};
use crate::recursion::state::{self, AccV, CtxParts, State, ZeroWord};
use crate::recursion::step;
use crate::recursion::word::{Digest, Word};

const N: u32 = 15;

fn whir() -> lens::WhirParams {
    let mut w = crate::execution::succinct::params_for(20);
    w.log_inv_rate = 4;
    w.pow_bits = 24;
    w
}

fn pr(a: ExecutionNoun, b: ExecutionNoun) -> ExecutionNoun {
    ExecutionNoun::Pair(Box::new(a), Box::new(b))
}
fn op(t: u64, a: ExecutionNoun, b: ExecutionNoun) -> ExecutionNoun {
    pr(ExecutionNoun::Atom(t), pr(a, b))
}

/// `tests/common::tree_program`: a doubling tree of `2^k` leaves.
fn tree_program(k: usize) -> ExecutionNoun {
    let axis2 = pr(ExecutionNoun::Atom(0), ExecutionNoun::Atom(2));
    let quote1 = pr(ExecutionNoun::Atom(1), ExecutionNoun::Atom(1));
    (0..k).fold(op(5, axis2, quote1), |f, _| op(5, f.clone(), f))
}

fn base_lift(d: Digest) -> [Fp3; 4] {
    d.map(Fp3::from_base)
}

fn row0(seg: &Trace, n2: &Trace) -> Vec<Goldilocks> {
    seg.row(0).iter().chain(n2.row(0)).copied().collect()
}

/// The state digest computed generically (a fresh native interpreter whose
/// errors are not inspected — what `ivc::verify_prepared` did).
fn unchecked_digest(st: &State) -> Digest {
    let mut o = Native::new();
    let d = state::digest(&mut o, st);
    [d[0].c0, d[1].c0, d[2].c0, d[3].c0]
}

/// `ivc::decider_instance` / `ivc::decider_transcript`, for the forger.
fn decider_inputs(fin: &AccV<Fp3>, digest: Digest, vars: usize) -> (Instance, Transcript) {
    let mut bytes = [0u8; 32];
    for (i, x) in fin.root.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&x.c0.as_u64().to_le_bytes());
    }
    let mut claims = vec![Claim { point: fin.rho.clone(), value: fin.v0 }];
    claims.extend(fin.ood.iter().map(|&(z, y)| Claim::univariate(z, vars, y)));
    claims.extend(fin.spot.iter().map(|&(x, y)| Claim::univariate(x, vars, y)));
    let inst = Instance { root: lens::Commitment(hemera::Hash::from_bytes(bytes)), ext: true, claims };
    let mut t = Transcript::new(b"zheng-ivc-decide-v1");
    for x in digest {
        t.absorb_u64(x.as_u64());
    }
    (inst, t)
}

/// Where each state item lands in the state digest's sponge: `(block, lane)`.
fn state_lanes(st: &State) -> Vec<(usize, usize)> {
    let items = st.items();
    let (mut used, mut block) = (0, 0);
    let mut pos = Vec::with_capacity(items.len());
    for (i, &(_, ext)) in items.iter().enumerate() {
        let w = if ext { 3 } else { 1 };
        if used + w > RATE {
            block += 1;
            used = 0;
        }
        pos.push((block, used));
        used += w;
        if used == RATE && i + 1 < items.len() {
            block += 1;
            used = 0;
        }
    }
    pos
}

/// The native sponge stops hashing at its first failed check; before the
/// fix the final verifier hashed the proof's state with a fresh native
/// interpreter and ignored the failure. An extension value in a base slot
/// (a spot point `ω^s`, which nothing else in the native step checks) made
/// the "digest" the raw rate lanes of the state's last block — four
/// coordinates of the carried key claim's point, which the prover sets.
/// The state the final verifier folds and checks was then unbound from
/// the last step's public input: a two-segment run is accepted with only
/// its last segment proven, as a *base* step (live = 0, verifying
/// nothing), from a state whose step count, chain prefix, boundary row and
/// deferred claims the prover wrote down. Fixed: base slots must be base
/// (`state::is_canonical`), and `state::digest_native` fails instead of
/// returning unhashed lanes.
///
/// The second half: the same base step under its honest state (the initial
/// state it outputs) is refused by the step count — a base step after the
/// first restarts the chain (`live` cannot be dropped to skip a step).
#[test]
fn a_state_unbound_from_the_last_public_input_is_refused() {
    let w = whir();
    let run = machine::execute_exact(&tree_program(12), &[3], 1 << 30, N).unwrap();
    assert_eq!(run.segments(), 2);
    let k = ivc::key(&w, N as usize).unwrap();
    let p: &Params = &k.params;
    let n = p.n;
    let layout = p.cfg.layout;
    // pre-commit: segment 0's word a is a zero table — no segment-0 trace
    // is ever bound to the chain
    let segs = [Trace::new(WORD, 1 << n), run.segment(1)];
    let mut chain = [Goldilocks::ZERO; 4];
    let mut prefix = Vec::new();
    let mut ood_a = Vec::new();
    for seg in &segs {
        let wa = Word::commit_base(layout, &seg.column_major(WORD));
        let mut o = Native::new();
        let root = base_lift(wa.root());
        let z = step::pre_points(&mut o, root, p.fresh);
        let ys: Vec<Fp3> = z.iter().map(|&z| wa.univariate(z)).collect();
        prefix.push(chain);
        let c = step::chain_next(&mut o, base_lift(chain), root, &ys);
        chain = c.map(|x| x.c0);
        ood_a.push(ys);
    }
    let sd = ivc::statement_digest(&run.statement, n, run.start as u64, 2);
    let ch = ivc::run_challenges(sd, chain);
    let global = Machine::new(run.constants.clone(), &run.init, run.start, 0, 2 << n).publics;
    let rel = Relation::new(run.machine(1), ch);
    let parts = CtxParts {
        statement: sd,
        chain,
        g0: rel.g(&vec![Fp3::ZERO; G_POINT]),
        pn0: pbar_nox(&global, &vec![Fp3::ZERO; p.dims.pn], n),
        pv0: pbar_v(&k.sparse, &vec![Fp3::ZERO; p.dims.pv], n),
    };
    let (n2_0, carry) = machine::phase2_build(&run.machine(0), &run.segment(0), &ch, Fp3::ZERO);
    let (n2_1, _) = machine::phase2_build(&rel.machine, &run.segment(1), &ch, carry);
    // the last step's circuit is a base step: it verifies nothing
    let mut b = Builder::new(false);
    let live = b.live_var();
    let (init_v, h) = program::run(&mut b, p, live, &program::dummy_state(p), &program::dummy_proof(p), &parts, |b, c| b.set_output(c));
    b.finish().unwrap();
    let d: Digest = h.map(|v| b.value(v).c0);
    let honest_prev: State = state::StateV::from_items(&p.dims, &init_v.items().iter().map(|&(v, _)| b.value(v)).collect::<Vec<_>>());
    let (v1, _, _) = trace::generate(&b, &CircuitAir::default(), n).unwrap();
    let word_a = Word::commit_base(layout, &segs[1].column_major(WORD));
    let b_out = row0(&run.segment(0), &n2_0);
    let input = StepInput {
        rel: &rel,
        global: &global,
        n1: &segs[1],
        n2: &n2_1,
        word_a: &word_a,
        ood_a: &ood_a[1],
        b_out: &b_out,
        v1: &v1,
        key: &k.pre,
        sparse: &k.sparse,
    };
    let forge = |s: &State, x: Digest| -> IvcProof {
        let (pf, data, _) = prove::prove(p, &input, s, x, &AccData::Zero(ZeroWord::new(&layout)), true).unwrap();
        let mut o = Native::batched();
        let fin = step::verify(&mut o, p, s, base_lift(x), &pf);
        o.finish().unwrap();
        let AccData::Lens(data) = data else { panic!("last accumulator") };
        let (inst, mut t) = decider_inputs(&fin.acc, unchecked_digest(&fin), p.vars);
        let decider = accumulate::decide(&p.cfg, &Witnessed { instance: inst, data }, &mut t).unwrap();
        IvcProof { log_rows: N, start: run.start as u64, segments: 2, chain, state: s.clone(), step: pf, decider }
    };

    // the forged state: "one step verified", every carried value chosen
    let mut s = honest_prev.clone();
    s.step = Fp3::ONE;
    s.chain = base_lift(prefix[1]);
    s.b_first = b_out.iter().map(|&x| Fp3::from_base(x)).collect();
    s.b_last = row0(&segs[1], &n2_1).iter().map(|&x| Fp3::from_base(x)).collect();
    s.acc.spot[0].0 = Fp3::new(Goldilocks::ONE, Goldilocks::ONE, Goldilocks::ZERO);
    // the last block of the state sponge: pv.point[20], pv.point[21],
    // pv.value — its first four lanes are the forged "digest"
    let lanes = state_lanes(&s);
    let last = lanes.last().unwrap().0;
    let tail: Vec<usize> = (0..lanes.len()).filter(|&i| lanes[i].0 == last).collect();
    assert_eq!(tail.len(), 3, "state sponge layout moved: {tail:?}");
    let pv = p.dims.pv;
    s.pv.point[pv - 2] = Fp3::new(d[0], d[1], d[2]);
    s.pv.point[pv - 1] = Fp3::new(d[3], Goldilocks::ZERO, Goldilocks::ZERO);
    s.pv.value = pbar_v(&k.sparse, &s.pv.point, n);
    assert_eq!(unchecked_digest(&s), d, "the unchecked digest is the raw lanes");
    assert!(!state::is_canonical(&s));
    let forged = forge(&s, d);
    let r = ivc::verify(&run.statement, &forged, &w);
    assert!(r.is_err(), "a state unbound from the step's public input was accepted");

    // the honest state of a base step in last position: refused by the
    // step count (the chain restarted at the base step)
    let x = unchecked_digest(&honest_prev);
    assert_eq!(x, d);
    let restarted = forge(&honest_prev, x);
    let r = ivc::verify(&run.statement, &restarted, &w);
    assert!(r.is_err(), "a base step in the last position was accepted");
}

/// The base step (live = 0) outputs the initial state of the context it
/// is given, whatever previous state and proof it reads; its step count is
/// zero, so a base step anywhere but first restarts the count.
#[test]
fn the_base_step_outputs_the_initial_state_whatever_it_is_given() {
    let p = Params::new(&whir(), N as usize).unwrap();
    let parts = CtxParts {
        statement: [Goldilocks::new(1), Goldilocks::new(2), Goldilocks::new(3), Goldilocks::new(4)],
        chain: [Goldilocks::new(5); 4],
        g0: Fp3::from_base(Goldilocks::new(6)),
        pn0: Fp3::from_base(Goldilocks::new(7)),
        pv0: Fp3::from_base(Goldilocks::new(8)),
    };
    let mut prev = program::dummy_state(&p);
    prev.step = Fp3::from_base(Goldilocks::new(41));
    prev.g.value = Fp3::from_base(Goldilocks::new(99));
    let mut b = Builder::new(false);
    let live = b.live_var();
    let (out, _) = program::run(&mut b, &p, live, &prev, &program::dummy_proof(&p), &parts, |_, _| {});
    b.finish().unwrap();
    let got: Vec<Fp3> = out.items().iter().map(|&(v, _)| b.value(v)).collect();
    let mut o = Native::new();
    let want = state::init(&mut o, &p.dims, base_lift(state::ctx_native(&parts)), p.zero_root, parts.g0, parts.pn0, parts.pv0);
    let want: Vec<Fp3> = want.items().iter().map(|&(v, _)| v).collect();
    assert_eq!(got, want);
    assert_eq!(got[4], Fp3::ZERO, "step count");
}

/// A grinding nonce is absorbed as a field element: `n` and `n + p` would
/// hash alike, two encodings of one proof. Nonces must be canonical.
#[test]
fn a_non_canonical_grinding_nonce_is_refused() {
    let p = Params::new(&whir(), N as usize).unwrap();
    let pf = program::dummy_proof(&p);
    assert!(step::check_shape(&p, &pf).is_ok());
    for k in 0..2 {
        let mut bad = pf.clone();
        let nonce = if k == 0 { &mut bad.acc.comb_nonce } else { &mut bad.acc.query_nonce };
        *nonce = nebu::field::P;
        assert!(step::check_shape(&p, &bad).is_err());
    }
}
