//! The wrap prover: run the program in the circuit, then the messages
//! [`super::verify`] reads, in its transcript order.

use lens::rspcs::field::{eq_table, ml_eval_ext, pow_point};
use nebu::Fp3;

use super::program::{Inner, run};
use super::{CBITS, COLS, View, WORD, WrapKey, WrapProof};
use crate::air::public::next_table;
use crate::air::{Public, Trace, shift_prove, zerocheck_prove};
use crate::recursion::circuit::air::CircuitAir;
use crate::recursion::circuit::builder::Builder;
use crate::recursion::circuit::layout::{V1, pre};
use crate::recursion::circuit::trace;
use crate::recursion::finalv::Publics;
use crate::recursion::ops::Ops;
use crate::recursion::perm::tag;
use crate::recursion::sponge::ProverTranscript;
use crate::recursion::state::ClaimV;
use crate::recursion::whir;
use crate::recursion::word::{Digest, Word};

fn bind(t: &mut ProverTranscript, word: &Word, s: usize) -> (Vec<Fp3>, Vec<Fp3>) {
    t.absorb_all(&word.root());
    (0..s)
        .map(|_| {
            let z = t.squeeze_ext();
            let y = word.univariate(z);
            t.absorb_ext(y);
            (z, y)
        })
        .unzip()
}

fn columns(t: &Trace) -> Vec<Vec<Fp3>> {
    (0..t.width).map(|c| (0..t.rows()).map(|r| Fp3::from_base(t.row(r)[c])).collect()).collect()
}

/// Prove that the circuit ran `inner`'s verifier and output the digest of
/// `pubs` and `pn`; returns the proof and that digest (its public input).
pub fn prove(k: &WrapKey, inner: &Inner<'_>, pubs: &Publics<Fp3>, pn: &ClaimV<Fp3>) -> Result<(WrapProof, Digest), String> {
    let lap = crate::recursion::ivc::timer_pub("    wrap ");
    let n = k.params.n;
    let rows = 1usize << n;
    let air = CircuitAir::default();
    let mut b = Builder::new(true);
    let xv = run(&mut b, inner, pubs, pn, |b, c| b.set_output(c));
    b.finish()?;
    let x: Digest = xv.map(|v| b.value(v).c0);
    let (v1, pre_cols, out) = trace::generate(&b, &air, n)?;
    if out != k.out_row || pre_cols.cols != k.pre.cols {
        return Err("wrap: the circuit's layout differs from its key".into());
    }
    drop(pre_cols);
    drop(b);
    lap("circuit");
    let layout = k.cfg.layout(0);
    let mut t = ProverTranscript::new(tag::WRAP);
    t.absorb_all(&x);
    let w1 = Word::commit_base(layout, &v1.column_major(WORD));
    let (z1, y1) = bind(&mut t, &w1, k.fresh);
    let ab = [t.squeeze_ext(), t.squeeze_ext()];
    let v2 = trace::phase2(&v1, &k.pre, ab[0], ab[1]);
    let w2 = Word::commit_base(layout, &v2.column_major(WORD));
    let (z2, y2) = bind(&mut t, &w2, k.fresh);
    lap("words");
    let tau = t.squeeze_exts(n);
    let mu = t.squeeze_ext();
    let mut mus = Vec::with_capacity(k.constraints);
    let mut m = Fp3::ONE;
    for _ in 0..k.constraints {
        mus.push(m);
        m *= mu;
    }
    let mut cols = columns(&v1);
    cols.extend(columns(&v2));
    let local_cols = cols.clone();
    let succ: Vec<Vec<Fp3>> = local_cols.iter().map(|c| (0..rows).map(|r| c[(r + 1) % rows]).collect()).collect();
    cols.extend(succ);
    cols.extend(k.pre.cols.iter().cloned());
    for &xj in &x {
        cols.push(Public::Sparse(vec![(k.out_row, Fp3::from_base(xj))]).table(n));
    }
    let (zc, rho, evals) = zerocheck_prove(&View(&air), COLS, cols, eq_table(&tau), &ab, &mus, &mut t);
    lap("zerocheck");
    let local = evals[..COLS].to_vec();
    let next = evals[COLS..2 * COLS].to_vec();
    let keyv = evals[2 * COLS..2 * COLS + pre::COUNT].to_vec();
    for &v in local.iter().chain(&next) {
        t.absorb_ext(v);
    }
    let committed = k.kw.is_some();
    if committed {
        for &v in &keyv {
            t.absorb_ext(v);
        }
    }
    let gk = if committed { t.squeeze_exts(pre::LOG) } else { vec![] };
    // shift
    let gs: Vec<Vec<Fp3>> = (0..2).map(|_| t.squeeze_exts(CBITS)).collect();
    let beta = t.squeeze_ext();
    let zeta = t.squeeze_ext();
    let split = [(0, V1), (V1, COLS)];
    let mut ps: Vec<Vec<Fp3>> = split
        .iter()
        .zip(&gs)
        .map(|(&(lo, hi), g)| {
            let e = eq_table(g);
            (0..rows).map(|r| (lo..hi).fold(Fp3::ZERO, |a, c| a + e[c - lo] * local_cols[c][r])).collect()
        })
        .collect();
    drop(local_cols);
    let eqr = eq_table(&rho);
    let nx = next_table(&rho);
    let kt: Vec<Fp3> = (0..rows).map(|y| eqr[y] + beta * nx[y]).collect();
    let q: Vec<Fp3> = (0..rows).map(|r| ps[0][r] + zeta * ps[1][r]).collect();
    let (shift, rho2) = shift_prove(&mut t, kt, q, &mut ps);
    let vals = [ps[0][0], ps[1][0]];
    for &v in &vals {
        t.absorb_ext(v);
    }
    lap("shift");
    let up = |z: Fp3| pow_point(z, n + CBITS);
    let mut claims: Vec<Vec<(Vec<Fp3>, Fp3)>> = Vec::with_capacity(4);
    for (w, (zs, ys)) in [(z1, y1.clone()), (z2, y2.clone())].into_iter().enumerate() {
        let mut cs: Vec<(Vec<Fp3>, Fp3)> = zs.iter().zip(&ys).map(|(&z, &y)| (up(z), y)).collect();
        cs.push((rho2.iter().chain(&gs[w]).copied().collect(), vals[w]));
        claims.push(cs);
    }
    let mut kv = Vec::new();
    let mut words: Vec<&Word> = vec![&w1, &w2];
    if let Some(kw) = &k.kw {
        let zg: Vec<Fp3> = rho.iter().chain(&gk[..CBITS]).copied().collect();
        for wd in &kw.words {
            let v = ml_eval_ext(&wd.table(), &zg);
            t.absorb_ext(v);
            kv.push(v);
            claims.push(vec![(zg.clone(), v)]);
            words.push(wd);
        }
    }
    let whir = whir::prove(&k.cfg, &mut t, &words, &claims)?;
    lap("opening");
    Ok((
        WrapProof {
            roots: [w1.root(), w2.root()],
            ood: [y1, y2],
            zerocheck: zc,
            local,
            next,
            key: if committed { keyv } else { vec![] },
            shift,
            vals,
            kv,
            whir,
        },
        x,
    ))
}
