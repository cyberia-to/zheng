//! Adversarial review of zheng #58 (`feat/wrap-fastverify`,
//! `audit/wrap-fastverify-review-2026-10.md`): the streamed commitment
//! against the codeword it commits, the parser's batched leaf digests and
//! its permutation memo against the verifier's sponge, the message
//! digests' binding, the compiled constraint graph and its used key
//! columns, the slot closing of the wiring against the per-cell form, and
//! a loaded key's successor and key columns against its graph.

use lens::rspcs::field::eq_table;
use lens::rspcs::whir::LeafLayout;
use nebu::{Fp3, Goldilocks};

use super::{CBITS, Coef, Mode, WORD, Wiring, g_graph, key_used};
use crate::recursion::circuit::air::CircuitAir;
use crate::recursion::circuit::layout::{V1, pre};
use crate::recursion::msg;
use crate::recursion::ops::Native;
use crate::recursion::perm::{self, WIDTH};
use crate::recursion::stream::{self, Coeffs};
use crate::recursion::word::{Arity, Word, hash_leaves_with, leaf_digest, verify_leaf};

/// xorshift64*: test randomness without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn g(&mut self) -> Goldilocks {
        Goldilocks::new(self.next())
    }
    fn e(&mut self) -> Fp3 {
        Fp3::new(self.g(), self.g(), self.g())
    }
}

fn c_other(a: &[Fp3]) -> Vec<Fp3> {
    let mut b = a.to_vec();
    b[a.len() / 2] += Fp3::ONE;
    b
}

fn bits_of(j: usize, len: usize) -> Vec<Fp3> {
    (0..len).map(|k| Fp3::from_base(Goldilocks::new(((j >> k) & 1) as u64))).collect()
}

/// (1) An opening recomputed from coefficients is accepted only when
/// those coefficients encode the committed codeword: the verifier sees
/// symbols and a path, never coefficients, so a prover that streams one
/// word and opens from another is refused at the leaf digest — also after
/// the honest leaf's permutations were remembered by a parse (the memo
/// the batched Merkle check reads).
#[test]
fn a_streamed_opening_binds_to_the_committed_codeword_not_to_the_coefficients() {
    let mut r = Rng(0x5eed_0001);
    let k = 1usize << 6;
    let layout = LeafLayout { log_domain: 10, log_width: 2 };
    let a: Vec<Fp3> = (0..k).map(|_| r.e()).collect();
    let w = Word::commit_coeffs(layout, a.clone(), Arity::Two);
    let root = w.root().map(Fp3::from_base);
    let leaves = 1usize << layout.log_leaves();
    // the streamed tree is the held tree
    let streamed = stream::digests(&[Coeffs::Ext(&a)], layout.log_domain, layout.log_width, |leaves, width, sym| {
        crate::recursion::word::hash_leaves(leaves, width, true, sym)
    });
    for j in [0, 1, 7, leaves - 1] {
        let honest = w.open(j);
        assert_eq!(honest.symbols, stream::leaf(Coeffs::Ext(&a), layout.log_domain, layout.log_width, j));
        assert_eq!(leaf_digest(true, &honest.symbols), streamed[j]);
        // a parse of the honest leaf fills the memo
        let _ = hash_leaves_with(1, honest.symbols.len(), true, |_, t| honest.symbols[t], true);
        let bits = bits_of(j, honest.path.len());
        for batched in [false, true] {
            let mut o = if batched { Native::batched() } else { Native::new() };
            verify_leaf(&mut o, true, Arity::Two, &honest, &bits, root, "root");
            assert!(o.finish().is_ok(), "honest leaf {j}");
        }
        // other coefficients: one changed, and a whole other word
        let mut b = a.clone();
        b[r.below(k)] += Fp3::ONE;
        let c: Vec<Fp3> = (0..k).map(|_| r.e()).collect();
        for other in [&b, &c] {
            let mut forged = honest.clone();
            forged.symbols = stream::leaf(Coeffs::Ext(other), layout.log_domain, layout.log_width, j);
            assert_ne!(forged.symbols, honest.symbols);
            let _ = hash_leaves_with(1, forged.symbols.len(), true, |_, t| forged.symbols[t], true);
            for batched in [false, true] {
                let mut o = if batched { Native::batched() } else { Native::new() };
                verify_leaf(&mut o, true, Arity::Two, &forged, &bits, root, "root");
                assert!(o.finish().is_err(), "a leaf of other coefficients, leaf {j}");
            }
        }
    }
    // a truly streamed word (no codeword, no leaf level: the opening's
    // leaf-level sibling recomputed): the same root, the same refusals
    crate::recursion::word::FORCE_STREAM.with(|f| f.set(true));
    let ws = Word::commit_coeffs(layout, a.clone(), Arity::Two);
    crate::recursion::word::FORCE_STREAM.with(|f| f.set(false));
    assert_eq!(ws.root(), w.root());
    for j in [0, 2, leaves - 1] {
        let op = ws.open(j);
        assert_eq!(op, w.open(j));
        let bits = bits_of(j, op.path.len());
        let mut o = Native::batched();
        verify_leaf(&mut o, true, Arity::Two, &op, &bits, root, "root");
        assert!(o.finish().is_ok());
        let mut forged = op.clone();
        forged.symbols = stream::leaf(Coeffs::Ext(&c_other(&a)), layout.log_domain, layout.log_width, j);
        let mut o = Native::batched();
        verify_leaf(&mut o, true, Arity::Two, &forged, &bits, root, "root");
        assert!(o.finish().is_err());
    }
    // base words: the symbols of a base word lie in the base field
    let ab: Vec<Goldilocks> = (0..k).map(|_| r.g()).collect();
    let lb = stream::leaf(Coeffs::Base(&ab), layout.log_domain, layout.log_width, 3);
    assert!(lb.iter().all(|s| s.c1 == Goldilocks::ZERO && s.c2 == Goldilocks::ZERO));
}

/// (6) The parser's batched leaf digests (which also fill the memo) are
/// the verifier's leaf sponge, for every width and both symbol fields.
#[test]
fn the_parser_s_batched_leaf_digests_are_the_verifier_s_sponge() {
    let mut r = Rng(0x5eed_0002);
    for ext in [false, true] {
        for width in 1..=40usize {
            let leaves = 5;
            let syms: Vec<Vec<Fp3>> = (0..leaves)
                .map(|_| (0..width).map(|_| if ext { r.e() } else { Fp3::from_base(r.g()) }).collect())
                .collect();
            for remember in [false, true] {
                let got = hash_leaves_with(leaves, width, ext, |j, t| syms[j][t], remember);
                for (j, s) in syms.iter().enumerate() {
                    assert_eq!(got[j], leaf_digest(ext, s), "ext {ext} width {width}");
                }
            }
        }
    }
}

/// (6, 8) The permutation memo is a cache of a pure function: whatever
/// was remembered, by any thread, in any order, across clears, a recall
/// returns the permutation.
#[test]
fn the_permutation_memo_returns_only_permutations_under_concurrency() {
    let truth = |s: &[Goldilocks; WIDTH]| {
        let mut t = *s;
        perm::permute(&mut t);
        t
    };
    std::thread::scope(|sc| {
        for th in 0..8u64 {
            sc.spawn(move || {
                let mut r = Rng(0x5eed_1000 + th);
                for round in 0..12 {
                    let mut states: Vec<[Goldilocks; WIDTH]> =
                        (0..64).map(|_| core::array::from_fn(|_| Goldilocks::new(r.next() % 1000))).collect();
                    let want: Vec<_> = states.iter().map(truth).collect();
                    let mut rem = states.clone();
                    perm::permute_many_remember(&mut rem);
                    assert_eq!(rem, want);
                    // recall a mix: remembered, altered in one lane, fresh
                    for s in states.iter_mut().step_by(3) {
                        s[r.below(WIDTH)] += Goldilocks::ONE;
                    }
                    let want: Vec<_> = states.iter().map(truth).collect();
                    let mut got = states.clone();
                    perm::permute_many_recall(&mut got);
                    assert_eq!(got, want, "thread {th} round {round}");
                    if round == 6 && th == 0 {
                        // past the cap: the memo clears under the others
                        let mut big: Vec<[Goldilocks; WIDTH]> =
                            (0..perm::MEMO_CAP as u64 + 8).map(|i| core::array::from_fn(|l| Goldilocks::new(i * 17 + l as u64 + 5000))).collect();
                        perm::permute_many_remember(&mut big);
                    }
                }
            });
        }
    });
}

/// (3) A message digest binds its length, its order and the split of
/// the final level's column message (local ‖ successor) — the split is
/// the key's, not the proof's.
#[test]
fn message_digests_bind_length_order_and_content() {
    let mut r = Rng(0x5eed_0003);
    for len in 1..=80usize {
        let items: Vec<Fp3> = (0..len).map(|_| r.e()).collect();
        let d = msg::digest_native(&items);
        let mut longer = items.clone();
        longer.push(Fp3::ZERO);
        assert_ne!(msg::digest_native(&longer), d, "a trailing zero, {len}");
        if len > 1 {
            assert_ne!(msg::digest_native(&items[..len - 1]), d, "a dropped item, {len}");
            let mut sw = items.clone();
            sw.swap(0, len - 1);
            assert_ne!(msg::digest_native(&sw), d, "a swap, {len}");
        }
        for i in [0, len / 2, len - 1] {
            for limb in 0..3 {
                let mut bad = items.clone();
                match limb {
                    0 => bad[i].c0 += Goldilocks::ONE,
                    1 => bad[i].c1 += Goldilocks::ONE,
                    _ => bad[i].c2 += Goldilocks::ONE,
                }
                assert_ne!(msg::digest_native(&bad), d, "item {i} limb {limb}, {len}");
            }
        }
    }
}

/// (4) The compiled graph is the graph; the key columns the final
/// verifier evaluates are exactly the inputs the graph reads (derived
/// from the key's graph, never the proof): every other input, perturbed,
/// leaves `G` unchanged.
#[test]
fn the_compiled_graph_is_the_graph_and_skipped_key_columns_are_never_read() {
    let mut r = Rng(0x5eed_0004);
    for mode in [Mode::Final, Mode::Inner] {
        let (g, _) = g_graph(&CircuitAir::default(), mode);
        let gc = g.compile();
        let w = if mode == Mode::Inner { super::COLS } else { V1 };
        let used = g.used_inputs();
        let kc = key_used(&g, w);
        assert_eq!(kc.len(), pre::COUNT);
        assert_eq!(&used[2 * w..2 * w + pre::COUNT], &kc[..]);
        let ins: Vec<Fp3> = (0..g.inputs).map(|_| r.e()).collect();
        let want = g.eval(&ins);
        assert_eq!(gc.eval(&ins), want, "{mode:?}");
        // every unused input, perturbed (all at once and one at a time)
        let mut all = ins.clone();
        for (i, u) in used.iter().enumerate() {
            if !u {
                all[i] = r.e();
                let mut one = ins.clone();
                one[i] = Fp3::ZERO;
                assert_eq!(gc.eval(&one), want, "{mode:?}: input {i} unused yet read");
            }
        }
        assert_eq!(g.eval(&all), want);
        assert_eq!(gc.eval(&all), want);
        // every used key column is read: perturbing it moves G
        for (j, &u) in kc.iter().enumerate() {
            if u {
                let mut one = ins.clone();
                one[2 * w + j] += Fp3::ONE;
                assert_ne!(gc.eval(&one), want, "{mode:?}: key column {j} listed but not read");
            }
        }
        // random points: compiled = graph
        for _ in 0..8 {
            let x: Vec<Fp3> = (0..g.inputs).map(|_| r.e()).collect();
            assert_eq!(gc.eval(&x), g.eval(&x));
        }
        eprintln!("{mode:?}: {} of {} key columns read, {} compiled operations", kc.iter().filter(|&&u| u).count(), kc.len(), gc.len());
    }
}

/// The per-cell closing `Σ_x u_λ(x)·eq(α, x_lo)·f_M(x_hi)` from the
/// wiring's table (the prover's `wiring_table` form).
fn per_cell(w: &Wiring, n: usize, lambda: Fp3, alpha: &[Fp3], fm: &[Fp3]) -> Fp3 {
    let lp = w.powers(lambda);
    let ws = w.write_sums(&lp);
    let mut u = vec![Fp3::ZERO; WORD << n];
    for &(i, x, c) in &w.read_cells {
        u[x as usize] += c.apply(lp[i as usize]);
    }
    for &(j, x, c) in &w.write_cells {
        u[x as usize] -= c.apply(ws[j as usize]);
    }
    let ea = eq_table(alpha);
    let pre = alpha.len();
    u.iter().enumerate().fold(Fp3::ZERO, |s, (x, &v)| s + v * ea[x & ((1 << pre) - 1)] * fm[x >> pre])
}

/// A random wiring of `reads` read slots and `writes` write slots over
/// `2^n` rows: a slot's cells share its row; every read is read by one
/// write (some writes have no reads).
fn random_wiring(r: &mut Rng, n: usize, reads: usize, writes: usize, other: bool) -> Wiring {
    let coef = |r: &mut Rng| match r.below(if other { 4 } else { 3 }) {
        0 => Coef::One,
        1 => Coef::T,
        2 => Coef::T2,
        _ => Coef::Other(r.e()),
    };
    let cells = |r: &mut Rng, slots: usize| -> Vec<(u32, u32, Coef)> {
        let mut v = Vec::new();
        for s in 0..slots {
            let row = r.below(1 << n);
            for _ in 0..1 + r.below(4) {
                let col = r.below(WORD);
                v.push((s as u32, (col << n | row) as u32, coef(r)));
            }
        }
        v
    };
    let read_cells = cells(r, reads);
    let write_cells = cells(r, writes);
    let mut by_write: Vec<Vec<u32>> = vec![Vec::new(); writes];
    for i in 0..reads {
        // writes 0 and 1 stay without reads
        by_write[2 + r.below(writes - 2)].push(i as u32);
    }
    let mut write_at = vec![0u32];
    let mut write_reads = Vec::new();
    for b in by_write {
        write_reads.extend(b);
        write_at.push(write_reads.len() as u32);
    }
    Wiring::new(reads, read_cells, write_reads, write_at, write_cells)
}

/// (5) The closing by slot equals the per-cell closing for every `|α|`
/// the slot form takes, and declines (the per-cell path then runs) when
/// its premises fail: `|α| > n`, a general coefficient, cells out of
/// slot order, a read of two writes, a slot spanning two rows.
#[test]
fn the_slot_closing_is_the_per_cell_closing() {
    let mut r = Rng(0x5eed_0005);
    let n = 5;
    for trial in 0..6 {
        let w = random_wiring(&mut r, n, 70, 23, false);
        let lambda = r.e();
        // the index is built for the first |α| asked; ask one per wiring
        let pre = trial % (n + 1);
        let alpha: Vec<Fp3> = (0..pre).map(|_| r.e()).collect();
        let fm: Vec<Fp3> = (0..1usize << (n + CBITS - pre)).map(|_| r.e()).collect();
        let got = w.closing(n, lambda, &alpha, &fm).expect("the slot form applies");
        assert_eq!(got, per_cell(&w, n, lambda, &alpha, &fm), "pre {pre}");
        // another |α| on the same wiring: declined, never wrong
        let alpha2: Vec<Fp3> = (0..(pre + 1) % (n + 1)).map(|_| r.e()).collect();
        let fm2: Vec<Fp3> = (0..1usize << (n + CBITS - alpha2.len())).map(|_| r.e()).collect();
        if let Some(v) = w.closing(n, lambda, &alpha2, &fm2) {
            assert_eq!(v, per_cell(&w, n, lambda, &alpha2, &fm2));
        }
        // a wrong λ moves it (the batching is live)
        assert_ne!(w.closing(n, lambda + Fp3::ONE, &alpha, &fm), Some(got));
    }
    let alpha: Vec<Fp3> = (0..3).map(|_| r.e()).collect();
    let fm: Vec<Fp3> = (0..1usize << (n + CBITS - 3)).map(|_| r.e()).collect();
    let lambda = r.e();
    // |α| > n
    let w = random_wiring(&mut r, n, 30, 9, false);
    let big: Vec<Fp3> = (0..n + 1).map(|_| r.e()).collect();
    assert!(w.closing(n, lambda, &big, &fm[..1 << (CBITS - 1)]).is_none());
    // general coefficients
    let w = random_wiring(&mut r, n, 30, 9, true);
    assert!(w.read_cells.iter().chain(&w.write_cells).any(|c| matches!(c.2, Coef::Other(_))));
    assert!(w.closing(n, lambda, &alpha, &fm).is_none());
    // cells out of slot order
    let mut w = random_wiring(&mut r, n, 30, 9, false);
    w.read_cells.reverse();
    let w = Wiring::new(w.reads, w.read_cells, w.write_reads, w.write_at, w.write_cells);
    assert!(w.closing(n, lambda, &alpha, &fm).is_none());
    // a read listed by two writes
    let w = random_wiring(&mut r, n, 30, 9, false);
    let mut wr = w.write_reads.clone();
    let mut at = w.write_at.clone();
    wr.insert(0, wr[wr.len() - 1]);
    for a in at.iter_mut().skip(1) {
        *a += 1;
    }
    let w = Wiring::new(w.reads, w.read_cells, wr, at, w.write_cells);
    assert!(w.closing(n, lambda, &alpha, &fm).is_none());
    // a slot over two rows (low bits differ)
    let w = random_wiring(&mut r, n, 30, 9, false);
    let mut rc = w.read_cells.clone();
    let s0: Vec<usize> = (0..rc.len()).filter(|&i| rc[i].0 == 0).collect();
    if s0.len() >= 2 {
        rc[s0[1]].1 ^= 1;
    } else {
        rc.insert(s0[0] + 1, (0, rc[s0[0]].1 ^ 1, Coef::One));
    }
    let w = Wiring::new(w.reads, rc, w.write_reads, w.write_at, w.write_cells);
    assert!(w.closing(n, lambda, &alpha, &fm).is_none());
}

/// (4) A loaded key's successor columns and evaluated key columns are
/// its graph's: a key whose bytes send fewer successor columns than the
/// constraints read is refused on load.
#[test]
fn a_loaded_key_must_send_the_successor_columns_its_graph_reads() {
    let mut whir = crate::execution::succinct::params_for(20);
    whir.log_inv_rate = 4;
    whir.pow_bits = 24;
    let ikey = crate::recursion::ivc::key(&whir, 15).unwrap();
    let mut k = super::derive_shape_ivc(super::WrapParams { whir, n: 0, mode: Mode::Final }, &ikey).unwrap();
    let b = k.vk_bytes();
    let back = super::WrapKey::from_vk_bytes(&b).expect("a derived key loads");
    assert_eq!(back.vk_bytes(), b);
    assert_eq!(back.key_cols, k.key_cols);
    assert!(!k.next_cols.is_empty());
    // drop a successor column the graph reads
    let dropped = k.next_cols.remove(0);
    assert!(super::WrapKey::from_vk_bytes(&k.vk_bytes()).is_err(), "column {dropped} dropped");
    k.next_cols.insert(0, dropped);
    // send a column the graph does not read
    let extra = (0..V1).find(|c| !k.next_cols.contains(c)).expect("an unread column");
    k.next_cols.push(extra);
    k.next_cols.sort_unstable();
    assert!(super::WrapKey::from_vk_bytes(&k.vk_bytes()).is_err(), "column {extra} added");
}

/// (7) The recursion profile shipped since 5d7c959 (`ivc::SHIPPED_POW`,
/// rate 1/16, steps of 2^15): every row ≥ 128 with grinding priced, the
/// figures `specs/soundness.md` states, and the interactive weakest
/// (every grinding removed: the accumulation's combination and spot
/// checks, the decider's folds, shifts, final queries and combination)
/// 111.34 — the accumulation's combination after its 17 bits.
#[test]
fn the_shipped_ivc_profile_rows_and_interactive_figure() {
    let mut whir = crate::execution::succinct::params_for(20);
    whir.log_inv_rate = 4;
    whir.pow_bits = crate::recursion::ivc::SHIPPED_POW;
    let p = crate::recursion::params::Params::new(&whir, 15).unwrap();
    assert_eq!((p.cfg.queries, p.cfg.query_pow, p.cfg.comb_pow_for(crate::recursion::params::INPUTS)), (58, 16, 17));
    let rows = crate::recursion::params::ledger(&p);
    let get = |n: &str| rows.iter().find(|r| r.0 == n).map(|r| r.1).unwrap();
    assert!(rows.iter().all(|r| r.1 >= 128.0), "{rows:?}");
    for (n, want) in [("combine", 128.34), ("spot", 128.28), ("decider batch combine", 128.92), ("decider shift_2", 128.22), ("decider fin", 129.00)] {
        assert!((get(n) - want).abs() < 0.01, "{n}: {}", get(n));
    }
    let (name, inter) = rows.iter().map(|r| (r.0.clone(), r.1 - f64::from(r.2))).fold((String::new(), f64::INFINITY), |a, r| if r.1 < a.1 { r } else { a });
    assert_eq!(name, "combine");
    assert!((inter - 111.34).abs() < 0.01, "{inter}");
}
