//! The wrap verifier over [`Ops`].

use lens::rspcs::field::eq_table;
use nebu::Fp3;

use super::{CBITS, DEGREE, WrapKey, WrapProof};
use crate::recursion::acc::{ClaimRef, InstV};
use crate::recursion::circuit::layout::{V1, pre};
use crate::recursion::expr;
use crate::recursion::gm;
use crate::recursion::ops::{Arith, Ops};
use crate::recursion::perm::tag;
use crate::recursion::sponge::Sponge;
use crate::recursion::whir;

/// The proof's shape under `k`.
pub fn check_shape(k: &WrapKey, pf: &WrapProof) -> Result<(), String> {
    let n = k.params.n;
    let inner = k.inner();
    let words = k.trace_words();
    let ok = pf.roots.len() == words
        && pf.ood.len() == words
        && pf.ood.iter().all(|a| a.len() == k.fresh)
        && pf.zerocheck.len() == n
        && pf.zerocheck.iter().all(|m| m.len() == DEGREE + 1)
        && pf.local.len() == k.cols()
        && pf.next.len() == k.cols()
        && pf.key.len() == if inner { pre::COUNT } else { 0 }
        && pf.shift.len() == 2 * n
        && pf.vals.len() == words
        && pf.kv.len() == if inner { 2 } else { 0 }
        && pf.wiring.len() == if inner { 0 } else { 2 * k.vars() + 1 };
    if !ok {
        return Err("wrap: proof shape".into());
    }
    whir::check_shape(&k.cfg, k.inputs(), &pf.whir)
}

fn bind<O: Ops>(o: &mut O, t: &mut Sponge<O>, answers: &[Fp3]) -> Vec<ClaimRef<O::V>> {
    answers
        .iter()
        .map(|&y| {
            let z = t.squeeze_ext(o);
            let yv = t.absorb_free_ext(o, y);
            ClaimRef::Uni(z, yv)
        })
        .collect()
}

/// The key's columns at `ρ` from the key itself.
pub(crate) fn key_at(k: &WrapKey, rho: &[Fp3]) -> Vec<Fp3> {
    let e = eq_table(rho);
    k.sparse.iter().map(|col| col.iter().fold(Fp3::ZERO, |a, &(x, v)| a + v * e[x as usize])).collect()
}

/// `ũ_λ(z)`: the batched wiring vector's multilinear extension at `z`
/// (row variables first, then the 6 column variables).
pub(crate) fn wiring_at(k: &WrapKey, lambda: Fp3, z: &[Fp3]) -> Fp3 {
    let w = k.wiring.as_ref().expect("final mode");
    let n = k.params.n;
    let er = eq_table(&z[..n]);
    let ec = eq_table(&z[n..]);
    let slots = crate::recursion::circuit::layout::SLOTS as u32;
    let at = |s: u32| -> Fp3 {
        let row = er[(s / slots) as usize];
        w.kappa[&s].iter().fold(Fp3::ZERO, |a, &(c, kc)| a + kc * ec[c as usize]) * row
    };
    let mut acc = Fp3::ZERO;
    let mut l = Fp3::ONE;
    for &(r, wr) in &w.reads {
        acc += l * (at(r) - at(wr));
        l *= lambda;
    }
    acc
}

/// Verify a wrap proof whose public input is `x` (final mode: a native
/// interpreter only — the key and the wiring are evaluated in the field).
pub fn verify<O: Ops>(o: &mut O, k: &WrapKey, x: [O::V; 4], pf: &WrapProof) {
    check_shape(k, pf).expect("wrap: proof shape");
    let n = k.params.n;
    let inner = k.inner();
    let mut t = Sponge::new(o, tag::WRAP);
    t.absorb_all(o, &x);
    let mut roots = Vec::with_capacity(2);
    let mut oods = Vec::with_capacity(2);
    let r1: [O::V; 4] = core::array::from_fn(|i| t.absorb_free(o, pf.roots[0][i]));
    roots.push(r1);
    oods.push(bind(o, &mut t, &pf.ood[0]));
    let (ab, lambda) = if inner {
        let ab = [t.squeeze_ext(o), t.squeeze_ext(o)];
        let r2: [O::V; 4] = core::array::from_fn(|i| t.absorb_free(o, pf.roots[1][i]));
        roots.push(r2);
        oods.push(bind(o, &mut t, &pf.ood[1]));
        (ab, None)
    } else {
        let z = o.zero();
        ([z, z], Some(t.squeeze_ext(o)))
    };
    let tau = t.squeeze_exts(o, n);
    let mu = t.squeeze_ext(o);
    // zerocheck
    let mut claim = o.zero();
    let mut rho = Vec::with_capacity(n);
    for msg in &pf.zerocheck {
        let m: Vec<O::V> = msg.iter().map(|&h| t.absorb_free_ext(o, h)).collect();
        let a = t.squeeze_ext(o);
        let h1 = o.sub(claim, m[0]);
        let mut h = vec![m[0], h1];
        h.extend_from_slice(&m[1..]);
        claim = gm::interpolate(o, &h, a);
        rho.push(a);
    }
    let local: Vec<O::V> = pf.local.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    let next: Vec<O::V> = pf.next.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    let key: Vec<O::V> = if inner {
        pf.key.iter().map(|&v| t.absorb_free_ext(o, v)).collect()
    } else {
        let r: Vec<Fp3> = rho.iter().map(|&v| o.value(v)).collect();
        key_at(k, &r).into_iter().map(|v| o.constant(v)).collect()
    };
    let e_out = gm::eq_row(o, k.out_row, &rho);
    let pin: Vec<O::V> = x.iter().map(|&xj| o.mul(e_out, xj)).collect();
    let e = gm::eq(o, &tau, &rho);
    let einv = o.inv(e, "wrap: eq(τ, ρ) is invertible");
    let c = o.mul(claim, einv);
    let mut ins = local.clone();
    ins.extend_from_slice(&next);
    ins.extend_from_slice(&key);
    ins.extend_from_slice(&pin);
    ins.extend_from_slice(&[ab[0], ab[1], mu]);
    let g = expr::compile(o, &k.g, &ins)[0];
    o.assert_eq(g, c, "wrap: constraints");
    let gk = if inner { t.squeeze_exts(o, pre::LOG) } else { vec![] };
    // shift: every word's local and successor claims to one point
    let words = k.trace_words();
    let gs: Vec<Vec<O::V>> = (0..words).map(|_| t.squeeze_exts(o, CBITS)).collect();
    let beta = t.squeeze_ext(o);
    let zeta = t.squeeze_ext(o);
    let split = [(0, V1), (V1, k.cols())];
    let mut sigma: Option<O::V> = None;
    for (w, &(lo, hi)) in split.iter().take(words).enumerate() {
        let a = gm::mle(o, &local[lo..hi], &gs[w]);
        let nn = gm::mle(o, &next[lo..hi], &gs[w]);
        let s = o.mul_add(beta, nn, a);
        sigma = Some(match sigma {
            None => s,
            Some(acc) => o.mul_add(zeta, s, acc),
        });
    }
    let mut claim = sigma.expect("a word");
    let mut rho2 = Vec::with_capacity(n);
    for pair in pf.shift.chunks_exact(2) {
        let h0 = t.absorb_free_ext(o, pair[0]);
        let h2 = t.absorb_free_ext(o, pair[1]);
        let a = t.squeeze_ext(o);
        let h1 = o.sub(claim, h0);
        claim = gm::quadratic(o, h0, h1, h2, a);
        rho2.push(a);
    }
    let vals: Vec<O::V> = pf.vals.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    let eqr = gm::eq(o, &rho, &rho2);
    let nxt = gm::next_eval(o, &rho, &rho2);
    let kk = o.mul_add(beta, nxt, eqr);
    let vz = if inner { o.mul_add(zeta, vals[1], vals[0]) } else { vals[0] };
    let lhs = o.mul(kk, vz);
    o.assert_eq(lhs, claim, "wrap: shift reduction");
    let mut inputs: Vec<InstV<O::V>> = Vec::with_capacity(4);
    for (w, (root, cl)) in roots.into_iter().zip(oods).enumerate() {
        let mut claims = cl;
        claims.push(ClaimRef::Multi(rho2.iter().chain(&gs[w]).copied().collect(), vals[w]));
        inputs.push(InstV { root, ext: false, claims });
    }
    if let Some(kw) = &k.kw {
        let kv = gm::mle(o, &key, &gk);
        let v = [t.absorb_free_ext(o, pf.kv[0]), t.absorb_free_ext(o, pf.kv[1])];
        let line = o.lerp(gk[CBITS], v[0], v[1]);
        o.assert_eq(line, kv, "wrap: key claim");
        let zg: Vec<O::V> = rho.iter().chain(&gk[..CBITS]).copied().collect();
        for (h, &vh) in v.iter().enumerate() {
            let root = kw.roots[h].map(|x| o.constant(Fp3::from_base(x)));
            inputs.push(InstV { root, ext: k.key_ext, claims: vec![ClaimRef::Multi(zg.clone(), vh)] });
        }
    }
    if let Some(lambda) = lambda {
        // wiring: Σ_x ũ_λ(x)·W̃1(x) = 0
        let mut claim = o.zero();
        let mut z = Vec::with_capacity(k.vars());
        for pair in pf.wiring[..2 * k.vars()].chunks_exact(2) {
            let h0 = t.absorb_free_ext(o, pair[0]);
            let h2 = t.absorb_free_ext(o, pair[1]);
            let a = t.squeeze_ext(o);
            let h1 = o.sub(claim, h0);
            claim = gm::quadratic(o, h0, h1, h2, a);
            z.push(a);
        }
        let v = t.absorb_free_ext(o, pf.wiring[2 * k.vars()]);
        let zf: Vec<Fp3> = z.iter().map(|&a| o.value(a)).collect();
        let u = o.constant(wiring_at(k, o.value(lambda), &zf));
        let lhs = o.mul(u, v);
        o.assert_eq(lhs, claim, "wrap: wiring");
        inputs[0].claims.push(ClaimRef::Multi(z, v));
    }
    whir::verify(o, &k.cfg, &mut t, &inputs, &pf.whir);
}
