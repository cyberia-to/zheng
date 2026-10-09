//! The wrap verifier over [`Ops`].

use nebu::Fp3;

use super::{CBITS, COLS, DEGREE, WrapKey, WrapProof};
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
    let committed = k.kw.is_some();
    let ok = pf.ood.iter().all(|a| a.len() == k.fresh)
        && pf.zerocheck.len() == n
        && pf.zerocheck.iter().all(|m| m.len() == DEGREE + 1)
        && pf.local.len() == COLS
        && pf.next.len() == COLS
        && pf.key.len() == if committed { pre::COUNT } else { 0 }
        && pf.shift.len() == 2 * n
        && pf.kv.len() == if committed { 2 } else { 0 };
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

/// The key's columns at `ρ` from the key itself (a native verifier).
fn key_native(k: &WrapKey, rho: &[Fp3]) -> Vec<Fp3> {
    let e = lens::rspcs::field::eq_table(rho);
    k.sparse.iter().map(|col| col.iter().fold(Fp3::ZERO, |a, &(x, v)| a + v * e[x as usize])).collect()
}

/// Verify a wrap proof whose public input is `x`.
pub fn verify<O: Ops>(o: &mut O, k: &WrapKey, x: [O::V; 4], pf: &WrapProof) {
    check_shape(k, pf).expect("wrap: proof shape");
    let n = k.params.n;
    let mut t = Sponge::new(o, tag::WRAP);
    t.absorb_all(o, &x);
    let r1: [O::V; 4] = core::array::from_fn(|i| t.absorb_free(o, pf.roots[0][i]));
    let ood1 = bind(o, &mut t, &pf.ood[0]);
    let ab = [t.squeeze_ext(o), t.squeeze_ext(o)];
    let r2: [O::V; 4] = core::array::from_fn(|i| t.absorb_free(o, pf.roots[1][i]));
    let ood2 = bind(o, &mut t, &pf.ood[1]);
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
    let key: Vec<O::V> = if k.kw.is_some() {
        pf.key.iter().map(|&v| t.absorb_free_ext(o, v)).collect()
    } else {
        let r: Vec<Fp3> = rho.iter().map(|&v| o.value(v)).collect();
        key_native(k, &r).into_iter().map(|v| o.constant(v)).collect()
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
    let gk = if k.kw.is_some() { t.squeeze_exts(o, pre::LOG) } else { vec![] };
    // shift: local and successor claims of W1, W2 to one point
    let gs: Vec<Vec<O::V>> = (0..2).map(|_| t.squeeze_exts(o, CBITS)).collect();
    let beta = t.squeeze_ext(o);
    let zeta = t.squeeze_ext(o);
    let split = [(0, V1), (V1, COLS)];
    let mut sigma: Option<O::V> = None;
    for (w, &(lo, hi)) in split.iter().enumerate() {
        let a = gm::mle(o, &local[lo..hi], &gs[w]);
        let nn = gm::mle(o, &next[lo..hi], &gs[w]);
        let s = o.mul_add(beta, nn, a);
        sigma = Some(match sigma {
            None => s,
            Some(acc) => o.mul_add(zeta, s, acc),
        });
    }
    let mut claim = sigma.expect("two words");
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
    let vz = o.mul_add(zeta, vals[1], vals[0]);
    let lhs = o.mul(kk, vz);
    o.assert_eq(lhs, claim, "wrap: shift reduction");
    let mut inputs = Vec::with_capacity(4);
    for (w, (root, oods)) in [(r1, ood1), (r2, ood2)].into_iter().enumerate() {
        let mut claims = oods;
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
    whir::verify(o, &k.cfg, &mut t, &inputs, &pf.whir);
}
