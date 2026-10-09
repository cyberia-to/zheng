//! The step prover: the messages [`super::step::verify`] reads, in its
//! transcript order.

use lens::rspcs::WhirData;
use lens::rspcs::field::{eq_table, pow_point, root_of_unity};
use lens::Whir;
use nebu::{Fp3, Goldilocks};

use super::acc::AccProof;
use super::circuit::layout::{V1, V2};
use super::circuit::trace::{self, Pre};
use super::params::{CBITS, PN_COLS, Params, STEP_BITS};
use super::perm::tag;
use super::relation::{COLS, PUB_NOX, PUB_V, Relation, View, WORD};
use super::sponge::ProverTranscript;
use super::state::{AccV, State, ZeroWord};
use super::step::{StepProof, word_row};
use super::word::{Digest, LeafOpening, Word};
use crate::accumulate::sumcheck::{self, Weight};
use crate::air::public::next_table;
use crate::air::{Public, Trace, shift_prove, zerocheck_prove};
use crate::machine::layout::{W1, W2};

/// The word an accumulator stands for.
pub enum AccData {
    Zero(ZeroWord),
    Word(Word),
    /// The last accumulator, committed for the decider.
    Lens(WhirData),
}

impl AccData {
    fn table(&self, vars: usize) -> Vec<Fp3> {
        match self {
            AccData::Zero(_) => vec![Fp3::ZERO; 1 << vars],
            AccData::Word(w) => w.table(),
            AccData::Lens(d) => d.table(),
        }
    }
    fn open(&self, leaf: usize) -> LeafOpening {
        match self {
            AccData::Zero(z) => LeafOpening { leaf: Some(leaf), ..z.opening.clone() },
            AccData::Word(w) => w.open(leaf),
            AccData::Lens(_) => unreachable!("the decided word is never an input"),
        }
    }
}

/// Everything step `i` proves besides the state.
pub struct StepInput<'a> {
    pub rel: &'a Relation,
    /// The run's nox public columns over all rows.
    pub global: &'a [Public],
    pub n1: &'a Trace,
    pub n2: &'a Trace,
    pub word_a: &'a Word,
    pub ood_a: &'a [Fp3],
    /// The nox columns of the successor of the segment's last row.
    pub b_out: &'a [Goldilocks],
    pub v1: &'a Trace,
    pub key: &'a Pre,
    pub sparse: &'a [Vec<(u32, Fp3)>],
}

fn line(a: &[Fp3], b: &[Fp3], x: u64) -> Vec<Fp3> {
    let x = Fp3::from_base(Goldilocks::new(x));
    a.iter().zip(b).map(|(&u, &v)| u + x * (v - u)).collect()
}

/// `P̄_nox(z, γ) = Σ_j eq(γ, j)·P_j(z)` over the run's public columns.
pub fn pbar_nox(global: &[Public], point: &[Fp3], n: usize) -> Fp3 {
    let (z, g) = point.split_at(n + STEP_BITS);
    let e = eq_table(g);
    global.iter().zip(&e).fold(Fp3::ZERO, |a, (col, &w)| a + w * col.eval(z))
}

/// `P̄_V(z, γ) = Σ_x eq(z, x) Σ_j eq(γ, j)·K_j(x)` over the circuit key.
pub fn pbar_v(key: &[Vec<(u32, Fp3)>], point: &[Fp3], n: usize) -> Fp3 {
    let (z, g) = point.split_at(n);
    let ez = eq_table(z);
    let eg = eq_table(g);
    let mut acc = Fp3::ZERO;
    for (col, &w) in key.iter().zip(&eg) {
        let s = col.iter().fold(Fp3::ZERO, |a, &(x, k)| a + k * ez[x as usize]);
        acc += w * s;
    }
    acc
}

fn pack(t: &Trace, cols: usize, rows: usize) -> Vec<Vec<Fp3>> {
    (0..cols)
        .map(|c| (0..rows).map(|r| if c < t.width { Fp3::from_base(t.row(r)[c]) } else { Fp3::ZERO }).collect())
        .collect()
}

fn mle_ext(vals: &[Fp3], point: &[Fp3]) -> Fp3 {
    eq_table(point).iter().zip(vals).fold(Fp3::ZERO, |a, (&e, &v)| a + e * v)
}

/// Prove one step. `acc_in` is the accumulator the state carries;
/// `last` commits the new accumulator for the decider.
pub fn prove(p: &Params, w: &StepInput<'_>, st: &State, x: Digest, acc_in: &AccData, last: bool) -> Result<(StepProof, AccData, AccV<Fp3>), String> {
    let n = p.n;
    let rows = 1usize << n;
    let layout = p.cfg.layout;
    let lap = super::ivc::timer_pub("    ");
    let mut t = ProverTranscript::new(tag::STEP);
    t.absorb_all(&x);
    t.absorb_all(&w.word_a.root());
    for &y in w.ood_a {
        t.absorb_ext(y);
    }
    // word b = nox phase 2 ‖ circuit phase 1
    let mut wb = Trace::new(WORD, rows);
    for r in 0..rows {
        let row = wb.row_mut(r);
        row[..W2].copy_from_slice(w.n2.row(r));
        row[W2..W2 + V1].copy_from_slice(w.v1.row(r));
    }
    let word_b = Word::commit_base(layout, &wb.column_major(WORD));
    let (zb, ood_b) = bind(&mut t, &word_b, p.fresh);
    lap("word b");
    let ch_v = [t.squeeze_ext(), t.squeeze_ext()];
    let v2 = trace::phase2(w.v1, w.key, ch_v[0], ch_v[1]);
    let word_c = Word::commit_base(layout, &v2.column_major(WORD));
    let (zc_pts, ood_c) = bind(&mut t, &word_c, p.fresh);
    lap("word c");
    let b_in: Vec<Goldilocks> = w.n1.row(0).iter().chain(w.n2.row(0)).copied().collect();
    let b_v: Vec<Goldilocks> = w.v1.row(0).iter().chain(v2.row(0)).copied().collect();
    t.absorb_all(&b_in);
    t.absorb_all(w.b_out);
    t.absorb_all(&b_v);
    let tau = t.squeeze_exts(n);
    let seeds = t.squeeze_exts(p.seeds());
    // zerocheck over local, successor and public columns
    let mut cols = pack(w.n1, WORD, rows);
    cols.extend(pack(&wb, WORD, rows));
    cols.extend(pack(&v2, WORD, rows));
    let zero = Goldilocks::ZERO;
    let bout: Vec<Goldilocks> = (0..3).flat_map(|k| word_row(k, w.b_out, &b_v, zero)).collect();
    let succ: Vec<Vec<Fp3>> = (0..COLS)
        .map(|c| (0..rows).map(|r| if r + 1 < rows { cols[c][r + 1] } else { Fp3::from_base(bout[c]) }).collect())
        .collect();
    let local_cols = cols.clone();
    cols.extend(succ);
    for pc in &w.rel.machine.publics {
        cols.push(pc.table(n));
    }
    cols.extend(w.key.cols.iter().cloned());
    for &xj in &x {
        cols.push(Public::Sparse(vec![(p.out_row, Fp3::from_base(xj))]).table(n));
    }
    let mu = w.rel.mu(&seeds);
    let (zc, rho, evals) = zerocheck_prove(&View(w.rel), COLS, cols, eq_table(&tau), &ch_v, &mu, &mut t);
    lap("zerocheck");
    let local = evals[..COLS].to_vec();
    let next = evals[COLS..2 * COLS].to_vec();
    let pubs = &evals[2 * COLS..];
    let (pub_nox, rest) = pubs.split_at(PUB_NOX);
    let (pub_v, pin) = rest.split_at(PUB_V);
    for v in local.iter().chain(&next).chain(pub_nox).chain(pub_v) {
        t.absorb_ext(*v);
    }
    // deferred claims
    let gamma_n = t.squeeze_exts(PN_COLS);
    let gamma_v = t.squeeze_exts(super::circuit::layout::pre::LOG);
    let mut point_g: Vec<Fp3> = Vec::with_capacity(p.dims.g);
    for v in [&local[..], &next[..], pub_nox, pub_v, pin, &ch_v[..], &seeds[..]] {
        point_g.extend_from_slice(v);
    }
    let fold_g: Vec<Fp3> = (2..=p.g_deg as u64).map(|j| w.rel.g(&line(&st.g.point, &point_g, j))).collect();
    for &v in &fold_g {
        t.absorb_ext(v);
    }
    let _ = t.squeeze_ext();
    let step = st.step.c0.as_u64();
    let bits: Vec<Fp3> = (0..STEP_BITS).map(|k| Fp3::from_base(Goldilocks::new((step >> k) & 1))).collect();
    let point_n: Vec<Fp3> = rho.iter().chain(&bits).chain(&gamma_n).copied().collect();
    let fold_pn: Vec<Fp3> = (2..=p.pn_deg as u64).map(|j| pbar_nox(w.global, &line(&st.pn.point, &point_n, j), n)).collect();
    for &v in &fold_pn {
        t.absorb_ext(v);
    }
    let _ = t.squeeze_ext();
    let point_v: Vec<Fp3> = rho.iter().chain(&gamma_v).copied().collect();
    let fold_pv: Vec<Fp3> = (2..=p.pv_deg as u64).map(|j| pbar_v(w.sparse, &line(&st.pv.point, &point_v, j), n)).collect();
    for &v in &fold_pv {
        t.absorb_ext(v);
    }
    let _ = t.squeeze_ext();
    lap("folds");
    // shift
    let gs: Vec<Vec<Fp3>> = (0..3).map(|_| t.squeeze_exts(CBITS)).collect();
    let beta = t.squeeze_ext();
    let zeta = t.squeeze_ext();
    let mut ps: Vec<Vec<Fp3>> = (0..3)
        .map(|k| {
            let e = eq_table(&gs[k]);
            (0..rows)
                .map(|r| (0..WORD).fold(Fp3::ZERO, |a, c| a + e[c] * local_cols[WORD * k + c][r]))
                .collect()
        })
        .collect();
    let eqr = eq_table(&rho);
    let nx = next_table(&rho);
    let kt: Vec<Fp3> = (0..rows).map(|y| eqr[y] + if y == 0 { Fp3::ZERO } else { beta * nx[y] }).collect();
    let z2 = zeta * zeta;
    let q: Vec<Fp3> = (0..rows).map(|r| ps[0][r] + zeta * ps[1][r] + z2 * ps[2][r]).collect();
    let (shift, rho2) = shift_prove(&mut t, kt, q, &mut ps);
    let vals = [ps[0][0], ps[1][0], ps[2][0]];
    for &v in &vals {
        t.absorb_ext(v);
    }
    let gb: Vec<Vec<Fp3>> = (0..3).map(|_| t.squeeze_exts(CBITS)).collect();
    // the instances' claims, in the verifier's order
    let upt = |x: Fp3| pow_point(x, p.vars);
    let mut c_acc = vec![(st.acc.rho.clone(), st.acc.v0)];
    c_acc.extend(st.acc.ood.iter().map(|&(z, y)| (upt(z), y)));
    c_acc.extend(st.acc.spot.iter().map(|&(x, y)| (upt(x), y)));
    let za = super::step::pre_points(&mut super::ops::Native::new(), w.word_a.root().map(Fp3::from_base), p.fresh);
    let fresh_ood = [
        za.iter().zip(w.ood_a).map(|(&z, &y)| (z, y)).collect::<Vec<_>>(),
        zb.iter().copied().zip(ood_b.iter().copied()).collect(),
        zc_pts.iter().copied().zip(ood_c.iter().copied()).collect(),
    ];
    let b_in_l = b_in.clone();
    let b_v_l = b_v.clone();
    let mut claims: [Vec<(Vec<Fp3>, Fp3)>; 4] = [c_acc, vec![], vec![], vec![]];
    for k in 0..3 {
        let mut cs: Vec<(Vec<Fp3>, Fp3)> = fresh_ood[k].iter().map(|&(z, y)| (upt(z), y)).collect();
        cs.push((rho2.iter().chain(&gs[k]).copied().collect(), vals[k]));
        let row: Vec<Fp3> = word_row(k, &b_in_l, &b_v_l, zero).into_iter().map(Fp3::from_base).collect();
        let pt: Vec<Fp3> = core::iter::repeat_n(Fp3::ZERO, n).chain(gb[k].iter().copied()).collect();
        cs.push((pt, mle_ext(&row, &gb[k])));
        claims[k + 1] = cs;
    }
    lap("shift");
    // accumulation
    let tables = [acc_in.table(p.vars), w.word_a.table(), word_b.table(), word_c.table()];
    let proof_partial = StepProof {
        roots: [w.word_a.root(), word_b.root(), word_c.root()],
        ood: [w.ood_a.to_vec(), ood_b, ood_c],
        b_in,
        b_out: w.b_out.to_vec(),
        b_v,
        zerocheck: zc,
        local,
        next,
        pub_nox: pub_nox.to_vec(),
        pub_v: pub_v.to_vec(),
        fold_g,
        fold_pn,
        fold_pv,
        shift,
        vals,
        acc: AccProof {
            sumcheck: vec![],
            evals: vec![],
            comb_nonce: 0,
            root: [Goldilocks::ZERO; 4],
            ood: vec![],
            query_nonce: 0,
            openings: vec![],
        },
    };
    let words: [&dyn Opener; 4] = [acc_in, w.word_a, &word_b, &word_c];
    let (acc, data, inst) = prove_acc(p, &mut t, &tables, &claims, &words, last)?;
    lap("accumulation");
    Ok((StepProof { acc, ..proof_partial }, data, inst))
}

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

/// A word the accumulation opens.
pub trait Opener {
    fn opening(&self, leaf: usize) -> LeafOpening;
    fn symbol_at(&self, s: usize, layout: &lens::rspcs::whir::LeafLayout) -> Fp3 {
        let (leaf, pos) = layout.locate(s);
        self.opening(leaf).symbols[pos]
    }
}

impl Opener for Word {
    fn opening(&self, leaf: usize) -> LeafOpening {
        self.open(leaf)
    }
    fn symbol_at(&self, s: usize, _: &lens::rspcs::whir::LeafLayout) -> Fp3 {
        self.symbol(s)
    }
}

impl Opener for AccData {
    fn opening(&self, leaf: usize) -> LeafOpening {
        self.open(leaf)
    }
}

/// The accumulation step's prover over the four input words.
fn prove_acc(
    p: &Params,
    t: &mut ProverTranscript,
    tables: &[Vec<Fp3>; 4],
    claims: &[Vec<(Vec<Fp3>, Fp3)>; 4],
    words: &[&dyn Opener; 4],
    last: bool,
) -> Result<(AccProof, AccData, AccV<Fp3>), String> {
    let cfg = &p.cfg;
    let lap = super::ivc::timer_pub("      acc ");
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
    let (msgs, rho, evals) = sumcheck::prove(t, tables.to_vec(), &weights, p.vars);
    lap("sumcheck");
    for &e in &evals {
        t.absorb_ext(e);
    }
    let comb_nonce = t.grind(cfg.comb_pow_for(4));
    lap("grind");
    let r = t.squeeze_ext();
    let coef = [Fp3::ONE, r, r * r, r * r * r];
    let mut gt = vec![Fp3::ZERO; 1 << p.vars];
    for (tb, &c) in tables.iter().zip(&coef) {
        for (gi, &f) in gt.iter_mut().zip(tb) {
            *gi += c * f;
        }
    }
    let v0 = evals.iter().zip(&coef).fold(Fp3::ZERO, |a, (&e, &c)| a + c * e);
    let (root, data): (Digest, AccData) = if last {
        let (com, d) = Whir::commit_ext(&p.whir, &gt);
        let b = com.as_bytes();
        let limb = |i: usize| Goldilocks::new(u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("8 bytes")));
        ([limb(0), limb(1), limb(2), limb(3)], AccData::Lens(d))
    } else {
        let wd = Word::commit_ext(cfg.layout, &gt);
        (wd.root(), AccData::Word(wd))
    };
    lap("commit");
    t.absorb_all(&root);
    let mut ood = Vec::with_capacity(cfg.ood);
    let mut ood_claims = Vec::with_capacity(cfg.ood);
    for _ in 0..cfg.ood {
        let z = t.squeeze_ext();
        let y = match &data {
            AccData::Word(w) => w.univariate(z),
            AccData::Lens(d) => d.univariate(z),
            AccData::Zero(_) => unreachable!(),
        };
        t.absorb_ext(y);
        ood.push(y);
        ood_claims.push((z, y));
    }
    lap("ood");
    let query_nonce = t.grind(cfg.query_pow);
    lap("grind");
    let symbols = t.indices(cfg.queries, cfg.layout.log_domain as usize)?;
    let omega = root_of_unity(cfg.layout.log_domain);
    let mut openings = Vec::with_capacity(cfg.queries);
    let mut spot = Vec::with_capacity(cfg.queries);
    for &s in &symbols {
        let (leaf, pos) = cfg.layout.locate(s);
        let ops: Vec<LeafOpening> = words.iter().map(|w| w.opening(leaf)).collect();
        let y = ops.iter().zip(&coef).fold(Fp3::ZERO, |a, (op, &c)| a + c * op.symbols[pos]);
        openings.push(ops);
        spot.push((Fp3::from_base(omega.exp(s as u64)), y));
    }
    let inst = AccV {
        root: root.map(Fp3::from_base),
        rho,
        v0,
        ood: ood_claims,
        spot,
    };
    Ok((
        AccProof { sumcheck: msgs, evals, comb_nonce, root, ood, query_nonce, openings },
        data,
        inst,
    ))
}

const _: () = assert!(V2 <= WORD && W1 == WORD);
