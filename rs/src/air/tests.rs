//! A toy AIR exercising every part of the protocol: a transition with the
//! next row, a first-row pin through a public column, and a logUp lookup
//! of every `x` into the public table of row indices with phase-2 Fp3
//! helper columns.

use lens::WhirParams;
use nebu::{Fp3, Goldilocks};

use super::*;
use crate::accumulate::{AccConfig, accumulate, decide, transcript, verify_decider, verify_step};

pub(crate) fn ext(c: &[Fp3]) -> Fp3 {
    let t = Fp3::new(Goldilocks::ZERO, Goldilocks::ONE, Goldilocks::ZERO);
    c[0] + t * c[1] + t * t * c[2]
}

pub(crate) fn split(x: Fp3) -> [Goldilocks; 3] {
    [x.c0, x.c1, x.c2]
}

/// W1 = [x, y, m]; W2 = [h1(3), h2(3), S(3)]. Publics: first, last,
/// the row index (the lookup table).
struct Toy {
    publics: Vec<Public>,
}

impl Toy {
    fn new(n: usize) -> Self {
        let rows = 1usize << n;
        let idx: Vec<Fp3> = (0..rows as u64).map(|i| Fp3::from_base(Goldilocks::new(i))).collect();
        Self {
            publics: vec![
                Public::Sparse(vec![(0, Fp3::ONE)]),
                Public::Sparse(vec![(rows - 1, Fp3::ONE)]),
                Public::Prefix(idx),
            ],
        }
    }
}

impl Air for Toy {
    fn shape(&self) -> Shape {
        Shape {
            w1: 3,
            w2: 9,
            challenges: 1,
            constraints: 5,
            degree: 2,
        }
    }
    fn publics(&self) -> &[Public] {
        &self.publics
    }
    fn eval(&self, v: &Vals<'_>, ch: &[Fp3], out: &mut [Fp3]) {
        let (x, y, m) = (v.local[0], v.local[1], v.local[2]);
        let (first, last, tval) = (v.publics[0], v.publics[1], v.publics[2]);
        let alpha = ch[0];
        let h1 = ext(&v.local[3..6]);
        let h2 = ext(&v.local[6..9]);
        let s = ext(&v.local[9..12]);
        let s_next = ext(&v.next[9..12]);
        out[0] = first * y;
        out[1] = (Fp3::ONE - last) * (v.next[1] - y - x);
        out[2] = h1 * (alpha - x) - Fp3::ONE;
        out[3] = h2 * (alpha - tval) - Fp3::ONE;
        // cyclic running sum with S(first) = 0: the wrap closes the sum
        out[4] = s_next - s - h1 + m * h2 + first * s;
    }
}

fn toy_trace(n: usize, xs: &[u64]) -> Trace {
    let rows = 1usize << n;
    let mut w1 = Trace::new(3, rows);
    let mut counts = vec![0u64; rows];
    for &x in xs {
        counts[x as usize] += 1;
    }
    let mut y = Goldilocks::ZERO;
    for r in 0..rows {
        let x = Goldilocks::new(xs[r]);
        w1.row_mut(r).copy_from_slice(&[x, y, Goldilocks::new(counts[r])]);
        y += x;
    }
    w1
}

fn toy_phase2(w1: &Trace, ch: &[Fp3]) -> Trace {
    let rows = w1.rows();
    let alpha = ch[0];
    let mut w2 = Trace::new(9, rows);
    let mut s = Fp3::ZERO;
    for r in 0..rows {
        let x = Fp3::from_base(w1.row(r)[0]);
        let m = Fp3::from_base(w1.row(r)[2]);
        let t = Fp3::from_base(Goldilocks::new(r as u64));
        let h1 = (alpha - x).inv();
        let h2 = (alpha - t).inv();
        let row = w2.row_mut(r);
        row[0..3].copy_from_slice(&split(h1));
        row[3..6].copy_from_slice(&split(h2));
        row[6..9].copy_from_slice(&split(s));
        s += h1 - m * h2;
    }
    w2
}

fn params() -> WhirParams {
    WhirParams {
        log_inv_rate: 2,
        pow_bits: 10,
        ..WhirParams::default()
    }
}

#[test]
fn toy_constraints_hold_exactly_on_valid_traces() {
    let n = 5;
    let air = Toy::new(n);
    let xs: Vec<u64> = (0..32u64).map(|i| (i * 7 + 3) % 30).collect();
    let w1 = toy_trace(n, &xs);
    let ch = [Fp3::new(Goldilocks::new(5), Goldilocks::new(9), Goldilocks::new(2))];
    let w2 = toy_phase2(&w1, &ch);
    assert_eq!(first_violation(&air, &w1, &w2, &ch), None);
    let mut bad = w1.clone();
    bad.row_mut(7)[1] += Goldilocks::ONE;
    assert!(first_violation(&air, &bad, &w2, &ch).is_some());
}

#[test]
fn toy_air_with_a_valid_trace_verifies_and_decides() {
    let n = 6;
    let air = Toy::new(n);
    let xs: Vec<u64> = (0..64u64).map(|i| (i * 11 + 5) % 60).collect();
    let w1 = toy_trace(n, &xs);
    let whir = params();
    let mut tp = lens::Transcript::new(b"toy");
    let (proof, words) = prove(&air, &whir, &w1, |ch| toy_phase2(&w1, ch), &mut tp).unwrap();
    let mut tv = lens::Transcript::new(b"toy");
    let insts = verify(&air, n, &proof, &mut tv).unwrap();
    assert_eq!(insts.len(), 2);
    assert_eq!(insts[0], words[0].instance);
    assert_eq!(insts[1], words[1].instance);
    let cfg = AccConfig::derive(&whir, words[0].data.num_vars(), 4, 64).unwrap();
    let mut ap = transcript(b"toy-acc", b"", &cfg);
    let inputs: Vec<&crate::accumulate::Witnessed> = words.iter().collect();
    let (acc, aproof) = accumulate(&cfg, &inputs, &mut ap).unwrap();
    let dproof = decide(&cfg, &acc, &mut ap).unwrap();
    let mut av = transcript(b"toy-acc", b"", &cfg);
    let refs: Vec<&crate::accumulate::Instance> = insts.iter().collect();
    let acc_inst = verify_step(&cfg, &refs, &aproof, &mut av).unwrap();
    verify_decider(&cfg, &acc_inst, &dproof, &mut av).unwrap();
    // a broken transition is caught by the verifier, not by the prover
    let mut bad = w1.clone();
    bad.row_mut(9)[1] += Goldilocks::ONE;
    let mut tb = lens::Transcript::new(b"toy");
    let (bp, _) = prove(&air, &whir, &bad, |ch| toy_phase2(&bad, ch), &mut tb).unwrap();
    let mut tbv = lens::Transcript::new(b"toy");
    assert!(verify(&air, n, &bp, &mut tbv).is_err());
    // a forged column value at ρ is caught
    let mut forged = proof.clone();
    forged.local[0] += Fp3::ONE;
    let mut tf = lens::Transcript::new(b"toy");
    assert!(verify(&air, n, &forged, &mut tf).is_err());
}
