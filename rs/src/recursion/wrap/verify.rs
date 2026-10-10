//! The wrap verifier over [`Ops`].

use lens::rspcs::field::eq_table;
use nebu::Fp3;

use super::{CBITS, DEGREE, WrapKey, WrapProof};
use crate::recursion::acc::{ClaimRef, InstV};
use crate::recursion::circuit::layout::{V1, pre};
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
        && pf.next.len() == k.next_cols.len()
        && pf.key.len() == if inner { pre::COUNT } else { 0 }
        && pf.shift.len() == if inner { 2 * n } else { 0 }
        && pf.vals.len() == if inner { words } else { 0 }
        && pf.kv.len() == if inner { 2 } else { 0 };
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
    use lens::rspcs::field::mul_base;
    let e = eq_table(rho);
    let one = nebu::Goldilocks::ONE;
    k.sparse
        .iter()
        .map(|col| {
            col.iter().fold(Fp3::ZERO, |a, &(x, v)| {
                let ex = e[x as usize];
                if v.c1 != nebu::Goldilocks::ZERO || v.c2 != nebu::Goldilocks::ZERO {
                    a + v * ex
                } else if v.c0 == one {
                    a + ex
                } else {
                    a + mul_base(ex, v.c0)
                }
            })
        })
        .collect()
}

/// The batched wiring vector `u_λ` as a weight of the opening: every
/// read slot's value minus its write slot's, with powers of `λ`.
pub(crate) struct WiringWeight<'a> {
    pub k: &'a WrapKey,
    pub lambda: Fp3,
}

impl whir::NativeWeight for WiringWeight<'_> {
    fn table(&self) -> Vec<Fp3> {
        super::prove::wiring_table(self.k, self.lambda)
    }
    /// `u_λ(α, b)` for every `b`: the word's index `x = col·2^n + row`,
    /// `α` its low `ℓ − fv` bits, `b` the rest.
    fn partial(&self, alpha: &[Fp3], fv: usize) -> Vec<Fp3> {
        let w = self.k.wiring.as_ref().expect("final mode");
        let pre = alpha.len();
        let ea = eq_table(alpha);
        let mask = (1usize << pre) - 1;
        let lp = w.powers(self.lambda);
        let mut out = vec![Fp3::ZERO; 1 << fv];
        for &(i, x, kc) in &w.entries {
            let x = x as usize;
            out[x >> pre] += lp[i as usize] * (kc * ea[x & mask]);
        }
        out
    }
}

/// Verify a wrap proof whose public input is `x` (final mode: a native
/// interpreter only — the key and the wiring are evaluated in the field).
pub fn verify<O: Ops>(o: &mut O, k: &WrapKey, x: [O::V; 4], pf: &WrapProof) {
    check_shape(k, pf).expect("wrap: proof shape");
    let lap = crate::recursion::ivc::timer_pub("      wrap verify ");
    let n = k.params.n;
    let inner = k.inner();
    let mut t = Sponge::new(o, tag::WRAP);
    t.absorb_all(o, &x);
    let mut roots = Vec::with_capacity(2);
    let mut oods: Vec<Vec<ClaimRef<O::V>>> = Vec::with_capacity(2);
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
    let sent: Vec<O::V> = pf.next.iter().map(|&v| t.absorb_free_ext(o, v)).collect();
    let zero = o.zero();
    let mut next = vec![zero; k.cols()];
    for (&c, &v) in k.next_cols.iter().zip(&sent) {
        next[c] = v;
    }
    let key: Vec<O::V> = if inner {
        pf.key.iter().map(|&v| t.absorb_free_ext(o, v)).collect()
    } else {
        let r: Vec<Fp3> = rho.iter().map(|&v| o.value(v)).collect();
        key_at(k, &r).into_iter().map(|v| o.constant(v)).collect()
    };
    lap("zerocheck, key");
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
    let g = o.graph(&k.g, &ins)[0];
    o.assert_eq(g, c, "wrap: constraints");
    lap("constraints");
    if !inner {
        // one word: its claims are the opening's weights — OOD, the
        // columns at ρ and at its successor, the wiring
        let gl = t.squeeze_exts(o, CBITS);
        let gn = t.squeeze_exts(o, CBITS);
        let cols = |o: &mut O, g: &[O::V], keep: &dyn Fn(usize) -> bool| -> Vec<O::V> {
            (0..1usize << CBITS).map(|c| if keep(c) { gm::eq_row(o, c, g) } else { zero }).collect()
        };
        let cl = cols(o, &gl, &|c| c < V1);
        let cn = cols(o, &gn, &|c| k.next_cols.contains(&c));
        let vl = gm::combine(o, &cl[..V1], &local);
        let nsel: Vec<O::V> = k.next_cols.iter().map(|&c| cn[c]).collect();
        let vn = gm::combine(o, &nsel, &sent);
        let mut claims: Vec<(whir::Weight<O::V>, O::V)> = oods
            .remove(0)
            .into_iter()
            .map(|c| match c {
                ClaimRef::Uni(z, y) => (whir::Weight::Pow(z), y),
                ClaimRef::Multi(p, y) => (whir::Weight::Eq(p), y),
            })
            .collect();
        claims.push((whir::Weight::RowCol { next: false, rho: rho.clone(), col: cl }, vl));
        claims.push((whir::Weight::RowCol { next: true, rho: rho.clone(), col: cn }, vn));
        claims.push((whir::Weight::Native(0), zero));
        let wiring = WiringWeight { k, lambda: o.value(lambda.expect("final mode")) };
        whir::verify_direct(o, &k.cfg, &mut t, roots[0], false, claims, &[&wiring], &pf.whir);
        lap("opening");
        return;
    }
    let gk = t.squeeze_exts(o, pre::LOG);
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
    if let Some(key_root) = k.key_root {
        let kv = gm::mle(o, &key, &gk);
        let v = [t.absorb_free_ext(o, pf.kv[0]), t.absorb_free_ext(o, pf.kv[1])];
        let line = o.lerp(gk[CBITS], v[0], v[1]);
        o.assert_eq(line, kv, "wrap: key claim");
        let zg: Vec<O::V> = rho.iter().chain(&gk[..CBITS]).copied().collect();
        for &vh in &v {
            let root = key_root.map(|x| o.constant(Fp3::from_base(x)));
            inputs.push(InstV { root, ext: k.key_ext, claims: vec![ClaimRef::Multi(zg.clone(), vh)] });
        }
    }
    whir::verify(o, &k.cfg, &mut t, &inputs, &pf.whir);
}
