//! The wrap circuit's program and the key a wrap level derives from it.

use nebu::Fp3;

use super::{KeyMode, WrapKey, WrapParams, WrapProof, g_graph};
use crate::recursion::circuit::air::CircuitAir;
use crate::recursion::circuit::builder::Builder;
use crate::recursion::circuit::trace;
use crate::recursion::decide::{self, KeyWords};
use crate::recursion::finalv::{self, PUBLICS, Publics};
use crate::recursion::ivc::{IvcProof, Key};
use crate::recursion::ops::Ops;
use crate::recursion::perm::tag;
use crate::recursion::program as ivc_program;
use crate::recursion::sponge::Sponge;
use crate::recursion::state::ClaimV;
use crate::recursion::whir;
use crate::recursion::word::Digest;

/// The verifier a wrap circuit runs, with the proof it checks.
pub enum Inner<'a> {
    /// The IVC final verifier on a recursive proof.
    Ivc { key: &'a Key, proof: &'a IvcProof },
    /// The verifier of a wrap proof.
    Wrap { key: &'a WrapKey, proof: &'a WrapProof },
}

impl Inner<'_> {
    /// Coordinates of the deferred nox-public claim's point.
    pub fn pn_len(&self) -> usize {
        match self {
            Inner::Ivc { key, .. } => key.params.dims.pn,
            Inner::Wrap { key, .. } => key.pn,
        }
    }
}

/// The digest of the public values (generically); returns it and its
/// chain (the circuit marks the chain's last row as the public input).
pub fn public_digest<O: Ops>(o: &mut O, pubs: &Publics<O::V>, pn: &ClaimV<O::V>) -> ([O::V; 4], O::Chain) {
    let mut sp = Sponge::new(o, tag::PUBLIC);
    for (v, ext) in pubs.items() {
        if ext {
            sp.absorb_ext(o, v);
        } else {
            sp.absorb(o, v);
        }
    }
    sp.absorb_all_ext(o, &pn.point);
    sp.absorb_ext(o, pn.value);
    let d: [O::V; 4] = core::array::from_fn(|_| sp.squeeze(o));
    (d, sp.chain)
}

/// [`public_digest`] of field values.
pub fn public_digest_native(pubs: &Publics<Fp3>, pn: &ClaimV<Fp3>) -> Result<Digest, String> {
    let mut o = crate::recursion::ops::Native::new();
    let p = finalv::constants(&mut o, pubs);
    let pn = ClaimV { point: pn.point.clone(), value: pn.value };
    let (d, _) = public_digest(&mut o, &p, &pn);
    o.finish()?;
    Ok(d.map(|x| x.c0))
}

/// The program: verify `inner` on its proof and output the digest of the
/// public values it binds. `pubs`, `pn`: the values the prover claims
/// (`pn` is computed, not read, when the inner verifier is the IVC's).
pub fn run<O: Ops>(o: &mut O, inner: &Inner<'_>, pubs: &Publics<Fp3>, pn: &ClaimV<Fp3>, mark: impl FnOnce(&mut O, &O::Chain)) -> [O::V; 4] {
    let items: Vec<O::V> = pubs.items().into_iter().map(|(v, _)| o.witness(v)).collect();
    let pv = Publics::from_items(&items);
    let pn_v = match inner {
        Inner::Ivc { key, proof } => finalv::run(o, key, &pv, &proof.state, &proof.step, &proof.decider),
        Inner::Wrap { key, proof } => {
            let pn_v = ClaimV { point: pn.point.iter().map(|&x| o.witness(x)).collect(), value: o.witness(pn.value) };
            let (x, _) = public_digest(o, &pv, &pn_v);
            super::verify(o, key, x, proof);
            pn_v
        }
    };
    let (x, chain) = public_digest(o, &pv, &pn_v);
    mark(o, &chain);
    x
}

fn dummy_publics() -> Publics<Fp3> {
    Publics::from_items(&vec![Fp3::ZERO; PUBLICS])
}

/// A wrap proof of the right shape (key derivation).
pub(crate) fn dummy_proof(k: &WrapKey) -> WrapProof {
    let z = Fp3::ZERO;
    let n = k.params.n;
    let committed = k.kw.is_some();
    WrapProof {
        roots: [[nebu::Goldilocks::ZERO; 4]; 2],
        ood: [vec![z; k.fresh], vec![z; k.fresh]],
        zerocheck: vec![vec![z; super::DEGREE + 1]; n],
        local: vec![z; super::COLS],
        next: vec![z; super::COLS],
        key: if committed { vec![z; crate::recursion::circuit::layout::pre::COUNT] } else { vec![] },
        shift: vec![z; 2 * n],
        vals: [z; 2],
        kv: if committed { vec![z; 2] } else { vec![] },
        whir: whir::dummy(&k.cfg, k.inputs()),
    }
}

/// Derive the key of the wrap level over the IVC final verifier
/// (`params.n = 0`: the smallest size the circuit fits).
pub fn derive_key_ivc(params: WrapParams, key: &Key) -> Result<WrapKey, String> {
    let state = ivc_program::dummy_state(&key.params);
    let step = ivc_program::dummy_proof(&key.params);
    let decider = decide::dummy(&key.dcfg);
    let proof = IvcProof { log_rows: key.params.n as u32, start: 0, segments: 1, chain: [nebu::Goldilocks::ZERO; 4], state, step, decider };
    derive_key(params, &Inner::Ivc { key, proof: &proof })
}

/// Derive the key of a wrap level over another wrap level's verifier.
pub fn derive_key_wrap(params: WrapParams, key: &WrapKey) -> Result<WrapKey, String> {
    let proof = dummy_proof(key);
    derive_key(params, &Inner::Wrap { key, proof: &proof })
}

/// Derive the key of a wrap level over `inner`'s verifier (the proof is
/// never read: layouts are fixed by shapes).
fn derive_key(params: WrapParams, inner: &Inner<'_>) -> Result<WrapKey, String> {
    let air = CircuitAir::default();
    let pn = ClaimV { point: vec![Fp3::ZERO; inner.pn_len()], value: Fp3::ZERO };
    let mut b = Builder::new(false);
    run(&mut b, inner, &dummy_publics(), &pn, |b, c| b.set_output(c));
    let rows = b.rows();
    let n = if params.n == 0 { rows.next_power_of_two().trailing_zeros().max(4) as usize } else { params.n };
    let (_, pre, out_row) = trace::generate(&b, &air, n)?;
    let vars = n + super::CBITS;
    let fresh = crate::accumulate::fresh_ood(&params.whir, vars)?;
    let committed = params.key == KeyMode::Committed;
    let claims = 2 * (fresh + 1) + if committed { 2 } else { 0 };
    let inputs = if committed { 4 } else { 2 };
    let cfg = whir::Config::derive(&params.whir, vars, inputs, claims)?;
    let (kw, key_ext) = if committed {
        let (kw, ext) = KeyWords::commit(cfg.layout(0), n, &pre);
        (Some(kw), ext)
    } else {
        (None, pre.cols.iter().flatten().any(|v| v.c1 != nebu::Goldilocks::ZERO || v.c2 != nebu::Goldilocks::ZERO))
    };
    let sparse = pre
        .cols
        .iter()
        .map(|c| c.iter().enumerate().filter(|(_, v)| **v != Fp3::ZERO).map(|(i, &v)| (i as u32, v)).collect())
        .collect();
    let (g, constraints) = g_graph(&air);
    Ok(WrapKey {
        params: WrapParams { n, ..params },
        pre,
        sparse,
        kw,
        key_ext,
        cfg,
        fresh,
        out_row,
        g,
        constraints,
        pn: inner.pn_len(),
        rows,
    })
}
