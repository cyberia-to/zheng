//! The wrap prover: run the program in the circuit, then the messages
//! [`super::verify`] reads, in its transcript order.

use lens::rspcs::field::{eq_table, ml_eval_ext, pow_point};
use nebu::Fp3;

use super::program::{Inner, run};
use super::{CBITS, View, WORD, WrapKey, WrapProof};
use crate::air::public::next_table;
use crate::air::{Public, Trace, shift_prove, zerocheck_prove};
use crate::recursion::circuit::air::CircuitAir;
use crate::recursion::circuit::builder::Builder;
use crate::recursion::circuit::layout::{SLOTS, V1, pre};
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

/// `u_λ` as a table over the word's index `col·N + row`.
pub(crate) fn wiring_table(k: &WrapKey, lambda: Fp3) -> Vec<Fp3> {
    let w = k.wiring.as_ref().expect("final mode");
    let rows = 1usize << k.params.n;
    let mut u = vec![Fp3::ZERO; WORD * rows];
    let mut add = |s: u32, c: Fp3| {
        let row = (s / SLOTS as u32) as usize;
        for &(col, kc) in &w.kappa[s as usize] {
            u[col as usize * rows + row] += c * kc;
        }
    };
    let mut l = Fp3::ONE;
    for &(r, wr) in &w.reads {
        add(r, l);
        add(wr, -l);
        l *= lambda;
    }
    u
}

/// Prove that the circuit ran `inner`'s verifier and output the digest of
/// `pubs` and `pn`; returns the proof and that digest (its public input).
pub fn prove(k: &WrapKey, inner: &Inner<'_>, pubs: &Publics<Fp3>, pn: &ClaimV<Fp3>) -> Result<(WrapProof, Digest), String> {
    let lap = crate::recursion::ivc::timer_pub("    wrap ");
    let n = k.params.n;
    let rows = 1usize << n;
    let mode = k.params.mode;
    let is_inner = k.inner();
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
    let w1 = Word::commit_base_a(layout, &v1.column_major(WORD), k.arity());
    let (z1, y1) = bind(&mut t, &w1, k.fresh);
    let mut words: Vec<Word> = vec![w1];
    let mut oods = vec![(z1, y1)];
    let mut cols = columns(&v1);
    let (ab, lambda) = if is_inner {
        let ab = [t.squeeze_ext(), t.squeeze_ext()];
        let v2 = trace::phase2(&v1, &k.pre, ab[0], ab[1]);
        let w2 = Word::commit_base_a(layout, &v2.column_major(WORD), k.arity());
        oods.push(bind(&mut t, &w2, k.fresh));
        words.push(w2);
        cols.extend(columns(&v2));
        (ab, None)
    } else {
        ([Fp3::ZERO; 2], Some(t.squeeze_ext()))
    };
    lap("words");
    let w = cols.len();
    let tau = t.squeeze_exts(n);
    let mu = t.squeeze_ext();
    let mut mus = Vec::with_capacity(k.constraints);
    let mut m = Fp3::ONE;
    for _ in 0..k.constraints {
        mus.push(m);
        m *= mu;
    }
    let local_cols = cols.clone();
    let succ: Vec<Vec<Fp3>> = local_cols.iter().map(|c| (0..rows).map(|r| c[(r + 1) % rows]).collect()).collect();
    cols.extend(succ);
    cols.extend(k.pre.cols.iter().cloned());
    for &xj in &x {
        cols.push(Public::Sparse(vec![(k.out_row, Fp3::from_base(xj))]).table(n));
    }
    let (zc, rho, evals) = zerocheck_prove(&View(&air, mode), w, cols, eq_table(&tau), &ab, &mus, &mut t);
    lap("zerocheck");
    let local = evals[..w].to_vec();
    let next: Vec<Fp3> = k.next_cols.iter().map(|&c| evals[w + c]).collect();
    let keyv = evals[2 * w..2 * w + pre::COUNT].to_vec();
    for &v in local.iter().chain(&next) {
        t.absorb_ext(v);
    }
    if !is_inner {
        drop(local_cols);
        let lambda = lambda.expect("final mode");
        let gl = t.squeeze_exts(CBITS);
        let gn = t.squeeze_exts(CBITS);
        let (el, en) = (eq_table(&gl), eq_table(&gn));
        let cl: Vec<Fp3> = (0..WORD).map(|c| if c < V1 { el[c] } else { Fp3::ZERO }).collect();
        let cn: Vec<Fp3> = (0..WORD).map(|c| if k.next_cols.contains(&c) { en[c] } else { Fp3::ZERO }).collect();
        let vl = local.iter().zip(&cl).fold(Fp3::ZERO, |a, (&x, &c)| a + x * c);
        let vn = k.next_cols.iter().zip(&next).fold(Fp3::ZERO, |a, (&c, &x)| a + x * cn[c]);
        let rowcol = |rt: Vec<Fp3>, col: &[Fp3]| -> Vec<Fp3> { (0..WORD * rows).map(|i| rt[i % rows] * col[i / rows]).collect() };
        let up = |z: Fp3| eq_table(&pow_point(z, n + CBITS));
        let mut claims: Vec<(Vec<Fp3>, Fp3)> = oods[0].0.iter().zip(&oods[0].1).map(|(&z, &y)| (up(z), y)).collect();
        claims.push((rowcol(eq_table(&rho), &cl), vl));
        claims.push((rowcol(next_table(&rho), &cn), vn));
        claims.push((wiring_table(k, lambda), Fp3::ZERO));
        let whir = whir::prove_direct(&k.cfg, &mut t, &words[0], &claims)?;
        lap("opening");
        return Ok((
            WrapProof {
                roots: vec![words[0].root()],
                ood: oods.into_iter().map(|o| o.1).collect(),
                zerocheck: zc,
                local,
                next,
                key: vec![],
                shift: vec![],
                vals: vec![],
                kv: vec![],
                whir,
            },
            x,
        ));
    }
    if is_inner {
        for &v in &keyv {
            t.absorb_ext(v);
        }
    }
    let gk = if is_inner { t.squeeze_exts(pre::LOG) } else { vec![] };
    // shift
    let nw = words.len();
    let gs: Vec<Vec<Fp3>> = (0..nw).map(|_| t.squeeze_exts(CBITS)).collect();
    let beta = t.squeeze_ext();
    let zeta = t.squeeze_ext();
    let split = [(0, V1), (V1, w)];
    let mut ps: Vec<Vec<Fp3>> = split
        .iter()
        .take(nw)
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
    let q: Vec<Fp3> = (0..rows).map(|r| if nw == 2 { ps[0][r] + zeta * ps[1][r] } else { ps[0][r] }).collect();
    let (shift, rho2) = shift_prove(&mut t, kt, q, &mut ps);
    let vals: Vec<Fp3> = ps.iter().map(|p| p[0]).collect();
    for &v in &vals {
        t.absorb_ext(v);
    }
    lap("shift");
    let up = |z: Fp3| pow_point(z, n + CBITS);
    let mut claims: Vec<Vec<(Vec<Fp3>, Fp3)>> = Vec::with_capacity(4);
    for (wi, (zs, ys)) in oods.iter().enumerate() {
        let mut cs: Vec<(Vec<Fp3>, Fp3)> = zs.iter().zip(ys).map(|(&z, &y)| (up(z), y)).collect();
        cs.push((rho2.iter().chain(&gs[wi]).copied().collect(), vals[wi]));
        claims.push(cs);
    }
    let mut kv = Vec::new();
    let mut opened: Vec<&dyn whir::Tree> = words.iter().map(|w| w as &dyn whir::Tree).collect();
    let kw = k.key_root.map(|_| crate::recursion::decide::KeyWords::commit(layout, n, &k.pre, k.arity()).0);
    if let Some(kw) = &kw {
        let zg: Vec<Fp3> = rho.iter().chain(&gk[..CBITS]).copied().collect();
        for wd in &kw.group.words {
            let v = ml_eval_ext(&wd.table(), &zg);
            t.absorb_ext(v);
            kv.push(v);
            claims.push(vec![(zg.clone(), v)]);
        }
        opened.push(&kw.group);
    }
    let whir = whir::prove(&k.cfg, &mut t, &opened, &claims)?;
    lap("opening");
    Ok((
        WrapProof {
            roots: words.iter().map(|w| w.root()).collect(),
            ood: oods.into_iter().map(|o| o.1).collect(),
            zerocheck: zc,
            local,
            next,
            key: if is_inner { keyv } else { vec![] },
            shift,
            vals,
            kv,
            whir,
        },
        x,
    ))
}
