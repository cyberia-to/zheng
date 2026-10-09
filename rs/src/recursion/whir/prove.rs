//! The batched field-native WHIR prover: the messages
//! [`super::verify`] reads, in its transcript order.

use lens::rspcs::field::{add_scaled_eq, eq_table, fold_coeffs_ext, fold_evals_ext, pow_point, root_of_unity};
use lens::rspcs::whir::RoundSpec;
use nebu::Fp3;

use super::{BatchProof, Config, Proof, Round, Tree};
use crate::accumulate::sumcheck::{self, Weight};
use crate::recursion::sponge::ProverTranscript;
use crate::recursion::word::{LeafOpening, Word};

/// `(h(0), h(2))` of `Σ_b f(b)·w(b)` in its first (low) variable.
fn round_poly(f: &[Fp3], w: &[Fp3]) -> (Fp3, Fp3) {
    let pairs = f.len() / 2;
    let part = |lo: usize, hi: usize| {
        let (mut a, mut c) = (Fp3::ZERO, Fp3::ZERO);
        for i in lo..hi {
            let (f0, f1, w0, w1) = (f[2 * i], f[2 * i + 1], w[2 * i], w[2 * i + 1]);
            a += f0 * w0;
            c += (f1 + f1 - f0) * (w1 + w1 - w0);
        }
        (a, c)
    };
    if pairs < 1 << 14 {
        return part(0, pairs);
    }
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16);
    let size = pairs.div_ceil(threads);
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads).map(|k| s.spawn(move || part(k * size, ((k + 1) * size).min(pairs)))).collect();
        hs.into_iter().map(|h| h.join().expect("round")).fold((Fp3::ZERO, Fp3::ZERO), |a, x| (a.0 + x.0, a.1 + x.1))
    })
}

/// The folding sumcheck: `rounds` rounds over `f·w`, folding `f`, `w`
/// and the coefficients.
fn fold_rounds(
    t: &mut ProverTranscript,
    f: &mut Vec<Fp3>,
    w: &mut Vec<Fp3>,
    coeffs: &mut Vec<Fp3>,
    rounds: usize,
    pow: u32,
) -> (Vec<Fp3>, Vec<u64>) {
    let mut msgs = Vec::with_capacity(2 * rounds);
    let mut nonces = Vec::new();
    for _ in 0..rounds {
        let (h0, h2) = round_poly(f, w);
        t.absorb_ext(h0);
        t.absorb_ext(h2);
        msgs.push(h0);
        msgs.push(h2);
        if pow > 0 {
            nonces.push(t.grind(pow));
        }
        let a = t.squeeze_ext();
        fold_evals_ext(f, a);
        fold_evals_ext(w, a);
        fold_coeffs_ext(coeffs, a);
    }
    (msgs, nonces)
}

fn queries(t: &mut ProverTranscript, s: &RoundSpec) -> Result<Vec<usize>, String> {
    if s.opens_all() {
        return Ok((0..1usize << s.log_leaves()).collect());
    }
    t.indices(s.queries, s.log_leaves() as usize)
}

/// Prove the batched opening of the words of `trees` (each in round 0's
/// layout, `cfg.groups` words a tree) with `claims[i]` on word `i`
/// (`(point, value)`, a univariate claim as its `pow` point).
pub fn prove(cfg: &Config, t: &mut ProverTranscript, trees: &[&dyn Tree], claims: &[Vec<(Vec<Fp3>, Fp3)>]) -> Result<Proof, String> {
    let wc = &cfg.wc;
    let ell = wc.num_vars;
    let words: Vec<&Word> = trees.iter().flat_map(|tr| tr.members()).collect();
    let m = words.len();
    let shape: Vec<usize> = trees.iter().map(|tr| tr.members().len()).collect();
    if m != cfg.inputs || shape != cfg.groups || claims.len() != m || words.iter().any(|w| w.num_vars != ell || w.layout != cfg.layout(0)) {
        return Err("whir: input words".into());
    }
    // batch
    let gamma = t.squeeze_ext();
    let mut g = Fp3::ONE;
    let weights: Vec<Weight> = claims
        .iter()
        .map(|cs| Weight {
            terms: cs
                .iter()
                .map(|(pt, _)| {
                    let term = (pt.clone(), g);
                    g *= gamma;
                    term
                })
                .collect(),
        })
        .collect();
    let tables: Vec<Vec<Fp3>> = words.iter().map(|w| w.table()).collect();
    let (msgs, rho, evals) = sumcheck::prove(t, tables.clone(), &weights, ell);
    for &e in &evals {
        t.absorb_ext(e);
    }
    let comb_nonce = t.grind(cfg.comb_pow);
    let r = t.squeeze_ext();
    let mut coef = Vec::with_capacity(m);
    let mut c = Fp3::ONE;
    for _ in 0..m {
        coef.push(c);
        c *= r;
    }
    let mut f = vec![Fp3::ZERO; 1 << ell];
    let mut coeffs = vec![Fp3::ZERO; 1 << ell];
    for ((tb, w), &c) in tables.iter().zip(words).zip(&coef) {
        for (x, &y) in f.iter_mut().zip(tb) {
            *x += c * y;
        }
        for (x, y) in coeffs.iter_mut().zip(w.coeffs()) {
            *x += c * y;
        }
    }
    drop(tables);
    // round 0
    let s0 = wc.rounds[0];
    let mut ood0 = Vec::with_capacity(s0.ood);
    let mut zs = Vec::with_capacity(s0.ood);
    for _ in 0..s0.ood {
        let z = t.squeeze_ext();
        let y = lens::rspcs::field::univariate_ext(&coeffs, z);
        t.absorb_ext(y);
        ood0.push(y);
        zs.push(z);
    }
    let gamma = t.squeeze_ext();
    let mut w = eq_table(&rho);
    let mut g = gamma;
    for &z in &zs {
        add_scaled_eq(&mut w, &pow_point(z, ell), g);
        g *= gamma;
    }
    let (sumcheck0, fold_nonces0) = fold_rounds(t, &mut f, &mut w, &mut coeffs, s0.fold, s0.fold_pow);
    let mut prev_words: Option<Word> = None;
    let mut prev = s0;
    let mut rounds = Vec::with_capacity(wc.rounds.len() - 1);
    let open = |prev_words: &Option<Word>, idx: &[usize]| -> Vec<Vec<LeafOpening>> {
        idx.iter()
            .map(|&j| match prev_words {
                Some(wd) => vec![wd.open(j)],
                None => trees.iter().map(|tr| tr.open(j)).collect(),
            })
            .collect()
    };
    for (i, s) in wc.rounds.iter().enumerate().skip(1) {
        let wd = Word::commit_coeffs(cfg.layout(i), coeffs.clone());
        t.absorb_all(&wd.root());
        let mut ood = Vec::with_capacity(s.ood);
        let mut zs = Vec::with_capacity(s.ood);
        for _ in 0..s.ood {
            let z = t.squeeze_ext();
            let y = wd.univariate(z);
            t.absorb_ext(y);
            ood.push(y);
            zs.push(z);
        }
        let query_nonce = t.grind(prev.query_pow);
        let idx = queries(t, &prev)?;
        let gamma = t.squeeze_ext();
        let opening = open(&prev_words, &idx);
        let mut g = gamma;
        for &z in &zs {
            add_scaled_eq(&mut w, &pow_point(z, s.num_vars), g);
            g *= gamma;
        }
        let omega_l = root_of_unity(prev.log_leaves());
        for &j in &idx {
            let x = Fp3::from_base(omega_l.exp(j as u64));
            add_scaled_eq(&mut w, &pow_point(x, s.num_vars), g);
            g *= gamma;
        }
        let (sumcheck, fold_nonces) = fold_rounds(t, &mut f, &mut w, &mut coeffs, s.fold, s.fold_pow);
        rounds.push(Round { root: wd.root(), ood, query_nonce, open: opening, sumcheck, fold_nonces });
        prev_words = Some(wd);
        prev = *s;
    }
    for &c in &coeffs {
        t.absorb_ext(c);
    }
    let final_nonce = t.grind(prev.query_pow);
    let idx = queries(t, &prev)?;
    let final_open = open(&prev_words, &idx);
    if t.sp.has_pending() {
        t.sp.flush(&mut t.o);
    }
    Ok(Proof {
        batch: BatchProof { sumcheck: msgs, evals, comb_nonce },
        ood0,
        sumcheck0,
        fold_nonces0,
        rounds,
        final_poly: coeffs,
        final_nonce,
        final_open,
    })
}
