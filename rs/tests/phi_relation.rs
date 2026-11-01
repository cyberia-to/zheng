//! What tru's epoch-engine phi* would cost as a relation zheng proves
//! SOUNDLY, measured by the cost of its primitive operations written as nox
//! programs. DIAGNOSTIC (soft3 release/director/plan.md row P7); never merged.
//!
//! # What is measured
//!
//! tru's kernel (`rs/focusing/epoch/{fixed,kernel}.rs`, tru rev 464104c) is
//! integer fixed point: phi entries are u64 at scale 2^60, and its hot
//! operations are
//!
//! * P1 `qmul(a, q) = shr_u(a * q, 32) = (a*q + 2^31) >> 32`, with `q` a Q32
//!   coefficient (`kernel.rs:200`; `shr_u` is `fixed.rs:49`, `Q_BITS = 32` is
//!   `fixed.rs:31`);
//! * P2 one sparse row `acc = sum_k w_k * x_k` in u128, then
//!   `shr_u(acc, 40) = (acc + 2^39) >> 40`, the weights at scale 2^40 (`w_k <=
//!   2^40`), `x_k` at scale 2^60 (`kernel.rs:161-167` `sym_fwd_row`, the same
//!   shape as `dir_fwd_row` at `kernel.rs:181`; `P_BITS = 40` is
//!   `fixed.rs:29`).
//!
//! P3 (`mul_shr(a, b, 60)`, `fixed.rs:43`) is NOT measured: a 124-bit product
//! of two runtime operands needs a three-level carry chain that is not cheap
//! to write soundly without a compiler to run it; P1 and P2 already price the
//! two ingredients (a limb-split product, a carry-chain division by 2^k).
//!
//! Products exceed the Goldilocks prime p = 2^64 - 2^32 + 1 (a*q is 95 bits,
//! a row sum 109), and nox has no wide arithmetic, so each program splits into
//! limbs, takes quotient and remainder limbs from the prover through pattern
//! 16 (`call`), and RANGE-CHECKS every witness with the 32-bit word patterns.
//! The output of each program is asserted bit-for-bit equal to the native Rust
//! port of tru's formula, and to native `nox::reduce`.
//!
//! # Which prover, and why it is the sound one
//!
//! The nox machine, `zheng::machine` (`specs/machine.md`): `execute_hinted`
//! runs the program natively and builds the trace (call witnesses come from
//! `Hints::witness`, `rs/src/machine/exec.rs:205-220`), `prove_run` proves the
//! AIR (`rs/src/machine/mod.rs:192`), `verify` checks it against the statement
//! (`mod.rs:264`). No `legacy` feature, nothing under `phi`, `fold`, `decide`.
//! It is public (no zero knowledge): for P7 the graph and phi_t are public and
//! nothing is secret, so the plain profile is the right one. The other
//! execution provers were rejected on size, not on soundness: `prove_zk`,
//! `certify_execution`, `prove_execution` compile the program into a CCS
//! relation (`rs/src/execution/relation.rs:179-181`) that refuses programs
//! over 4096 nodes or 4096 evaluated formulas (`MAX_CALLS`), and a statement
//! with over 64 inputs (`statement.rs:7-10`); one row of length 64 already
//! exceeds the first bound (about 100 tokens per entry), and 512 exceeds it
//! eightfold. The machine has no such bound (`MAX_TOKENS = 2^20`, any
//! number of cycles in segments of 2^14 rows).
//!
//! Soundness status of that relation, stated plainly (`specs/soundness.md:54`):
//! "tested, not proven"; the opcodes this file leans on (lt-free here: `and`,
//! `mul`, `sub`, `add`, `call`) have had no independent review beyond zheng's
//! own tests (`tests_ops.rs`, `tests_review.rs`). This file adds its own
//! checks: honest runs equal native nox on output and cycles, forged hints are
//! rejected or yield the native output, and a forged statement does not verify.
//! It does NOT re-forge the trace itself (that is the machine's own test
//! suite's job).
//!
//! # Rows
//!
//! `rows` is `run.trace.rows()`: the trace the AIR proves, `init + steps + pad
//! + perm`, rounded up to a power of two (one segment) or to a multiple of
//! 2^14 (several). Coarse, so the lines also carry `init` (one row per
//! distinct noun of the program and subject: `run.init.len()`),
//! `steps_est = start - init` (machine rows plus under 32 pad rows),
//! `perm_rows = rows - start` (hemera blocks), `cycles` (nox cost) and
//! `nox_rows` (native nox's own trace, `VecTrace`, where a word op is 32 rows).
//! `P7-fit` regresses `a + b*L` on rows, steps_est, cycles and nox_rows.
//!
//! The row's weights and phi entries enter as quoted constants of the program
//! (the machine takes at most 64 public inputs, `machine/statement.rs:12`, and
//! 512 are needed). They are NOT folded: every product `w_k * x_k` is a `mul`
//! the machine executes, and every `x_k` is range-checked against its limb
//! witness, exactly as if it had arrived from authenticated state. What the
//! numbers therefore exclude is the cost of FETCHING weights and entries
//! (a `look`, or an axis walk into a public input), which the machine prices
//! separately and which is not measured here.
//!
//! Timing: prove ms is the median of 5 (3 above 2^17 rows, to bound the run),
//! verify ms the median of 11. `ZHENG_BACKEND` (`cpu`, `metal`, `webgpu`,
//! `auto`) installs that lens prover backend for the process; unset is CPU.
//!
//! # The decompositions
//!
//! Notation: `[x]` below is "a witness the prover supplies through call, whose
//! check formula returns 0 iff its constraints hold". nox semantics used
//! (nox rev 41ba24f, `rs/patterns/*.rs`, `rs/reduce.rs`):
//!
//! * add, sub, mul are field operations mod p; the program text is a noun, a
//!   formula `[tag body]` with tags 0 axis, 1 quote, 2 compose, 3 cons,
//!   5 add, 6 sub, 7 mul, 12 and, 13 not, 16 call;
//! * the word patterns (11 xor, 12 and, 13 not, 14 shl) work on 32-bit words:
//!   `evaluate_binary_word` / `evaluate_unary_word` return TypeError unless the
//!   operand's canonical value is `< 2^32` (`rs/reduce.rs:54` `WORD_MASK`,
//!   `rs/reduce.rs:497`; patterns `and.rs`, `not.rs`). The machine proves the
//!   same: a word operand is peeled into 32 bits over 32 WBIT rows and an
//!   operand `>= 2^32` has no peel (`specs/machine.md`, WBIT). **A binary
//!   word op range-checks BOTH operands in the same 32 rows.** That is the
//!   whole range-check budget of this file: `z2(u, v) = mul(quote 0, and(u,
//!   v))`, a term that is always 0 but cannot be evaluated unless `u < 2^32`
//!   and `v < 2^32` (as integers, canonical representatives);
//! * pattern 16 is `[16 [tag check]]`: the prover injects a witness `w`, then
//!   `check` runs on `[w subject]` and must return the atom 0 (else
//!   CallRejected); the machine proves it (`CALL2 reads ATOM(val) = 0`).
//!
//! Exactness. A field equation is an integer equation only if both sides are
//! below p, so each is stated with every limb range-checked and a bound
//! computed below.
//!
//! ## P1: qmul(a, q), a < 2^63, q < 2^32
//!
//! Subject `[a [q 0]]`. Witnesses `ah` and `c1`:
//!
//! ```text
//!   al = a - 2^32*ah                    (derived, not witnessed)
//!   V  = al*q + 2^31
//!   c0 = V - 2^32*c1                    (derived)
//!   output = ah*q + c1
//! ```
//!
//! Checks: call 0 (`ah`): `z2(q, al)`, `z2(ah, ah+1)`. Call 1 (`c1`): `z2(c1,
//! c1+1)`, `z2(c0, c0)`. So `q, al, ah, c1, c0 < 2^32`, `ah+1 < 2^32`,
//! `c1+1 < 2^32`. Argument:
//!
//! * `al + 2^32*ah <= 2^32-1 + 2^32*(2^32-2) = 2^64 - 2^32 - 1 < p`, so
//!   `a = al + 2^32*ah` holds over the integers; the `+1` checks are what
//!   stop the other representative: without `ah+1 < 2^32` a forger takes
//!   `ah = 2^32-1`, `al = a + 1` (valid for any `a <= 2^32-2`), and then
//!   `al + 2^32*ah = a + p`, a different integer with the same residue. Likewise
//!   `c1 + 1 < 2^32` forbids `c1 = 2^32-1, c0 = V + 1` (`= V + p`) for small
//!   V (a real attack, tested: `a = 0` forges c1 = 2^32-1);
//! * `V = al*q + 2^31 <= (2^32-1)^2 + 2^31 < p` is exact, and
//!   `2^32*c1 + c0 <= 2^64 - 2^32 - 1 < p`, so `V = 2^32*c1 + c0` over the
//!   integers with `c0 < 2^32`: `c1 = floor(V / 2^32)`;
//! * `a*q + 2^31 = 2^32*(ah*q) + V = 2^32*(ah*q + c1) + c0`, hence
//!   `output = ah*q + c1 = floor((a*q + 2^31) / 2^32)` = tru's qmul, and
//!   `ah*q < 2^31 * 2^32 = 2^63 < p` so the output is exact (for `a >= 2^63`
//!   the output is the native value mod p; tru keeps every value below 2^63).
//!
//! `q = 2^32` (tru's Q_ONE, the coefficient 1.0) is outside the domain: the
//! `q < 2^32` check refuses it (tested). Four word checks of the seven
//! quantities come to 4 x 32 WBIT rows.
//!
//! ## P2: one row, sum_{k<L} w_k x_k, then (acc + 2^39) >> 40
//!
//! Constants: `w_k = wa_k + 2^20*wb_k` (`wa_k < 2^20`, `wb_k <= 2^20`, split
//! by the program builder). For each entry the prover supplies `xh_k`
//! (honestly `x_k >> 30`); `xl_k = x_k - 2^30*xh_k` is derived and a single
//! `z2(xh_k, xl_k)` checks both `< 2^32`. Then `x_k = xl_k + 2^30*xh_k` holds
//! over the integers (`< 2^62 + 2^32 < p`), and
//!
//! ```text
//!   A = sum wa*xl   B = sum wb*xl   C = sum wa*xh   D = sum wb*xh
//!   sum w*x = A + 2^20*B + 2^30*C + 2^50*D
//! ```
//!
//! with every sum `< L * 2^52 <= 2^61 < p` exact (L <= 512). They are
//! computed from `C` and `D` (the only ones needing the witnesses):
//! `A = SA - 2^30*C`, `B = SB - 2^30*D`, where `SA = sum wa*x`, `SB = sum
//! wb*x` are runtime muls of constants. Then the carries, with witnesses `Bh,
//! Ch, kappa, rh`:
//!
//! ```text
//!   Bl = B - 2^30*Bh     Cl = C - 2^30*Ch                 (derived)
//!   Low = A + 2^20*Bl + 2^30*Cl + 2^39                    (< 2^63 < p)
//!   rho_l = Low - 2^40*kappa - 2^32*rh                    (derived)
//!   output = 2^10*(Bh + D) + 2^20*Ch + kappa
//! ```
//!
//! Checks: `z2(Bh, Bl)`, `z2(Ch, Cl)`, `z2(kappa, 2^9*kappa)` (so `kappa <
//! 2^23`), `z2(rh, 2^24*rh)` (so `rh < 2^8`), `z2(rho_l, rho_l)`. Argument:
//! `B = 2^30*Bh + Bl` is an integer equation (`< 2^62 + 2^32`), likewise C;
//! the split need not be canonical (`Bl` may exceed 2^30) because the
//! identity `T = Low + 2^50*(Bh + D) + 2^60*Ch` for
//! `T = sum w*x + 2^39` is exact over the integers whatever the split, and
//! the two high terms are multiples of 2^40. `Low = 2^40*kappa + 2^32*rh +
//! rho_l` has right side `< 2^63 + 2^40 + 2^32 < p` and
//! `2^32*rh + rho_l < 2^40`, so `kappa = floor(Low / 2^40)`. Hence `output =
//! floor(T / 2^40) = shr_u(acc, 40)`, reduced mod p (equal to the u64 value
//! when it is below 2^63, tru's invariant). Distinct valid witnesses (a
//! different xh_k with xl_k + 2^30, a different Bh) give the SAME output;
//! the tests exercise that.
//!
//! Range checks per entry: one binary word op (32 rows). Tail: five.
//!
//! ## Alternatives considered
//!
//! * `lt(w, 2^32)` or `not(w)` per limb: one operand per 32 rows, twice the
//!   rows of `and(u, v)` for the same coverage;
//! * `shl` as a combined range/shift: no cheaper than `and`;
//! * 16-bit limbs: more witnesses per entry, no bit gadget cheaper than 32 rows;
//! * a bit-by-bit decomposition through 32 or 64 calls: orders of magnitude
//!   more rows;
//! * three 20-bit limbs for `x_k` (digit-aligned with a shift of 40): three
//!   range checks and a non-binary-checkable 20-bit top limb per entry;
//! * a single product `w*xl` without splitting `w`: `2^40 * 2^32 * L` exceeds
//!   p, so two sums must be kept (the 20/20 split of the weight);
//! * deriving `xl` and every low limb instead of witnessing it (done): halves
//!   the calls and makes the equation `x = xl + 2^30*xh` hold by construction.
//!
//! # Line formats
//!
//! `P7 program=P1|P2 L=... rows=... init=... steps_est=... perm_rows=...
//! segments=... cycles=... nox_rows=... [rows_per_entry=...] proof_bytes=...
//! prove_ms=... verify_ms=...` (plus arch, os, threads, backend), one per
//! measurement, and `P7-fit ...` once at the end. `P7-sound ...` lines count
//! the forgery attempts.
use nebu::Goldilocks;
use std::collections::HashMap;
use std::time::Instant;
use zheng::execution::ExecutionNoun as N;
use zheng::machine::{self, Hints, Run, statement};

const BUDGET: u64 = 1 << 40;
/// The field modulus.
const P: u64 = 0xFFFF_FFFF_0000_0001;

// ---- noun builders ----------------------------------------------------------

fn atom(v: u64) -> N {
    N::Atom(v)
}
fn pair(x: N, y: N) -> N {
    N::Pair(Box::new(x), Box::new(y))
}
/// `[0 a]`: the axis `a` of the subject.
fn axis(a: u64) -> N {
    pair(atom(0), atom(a))
}
/// `[1 v]`: the constant `v`.
fn quote(v: u64) -> N {
    pair(atom(1), atom(v))
}
fn op2(tag: u64, x: N, y: N) -> N {
    pair(atom(tag), pair(x, y))
}
fn add(x: N, y: N) -> N {
    op2(5, x, y)
}
fn sub(x: N, y: N) -> N {
    op2(6, x, y)
}
fn mul(x: N, y: N) -> N {
    op2(7, x, y)
}
fn cons(x: N, y: N) -> N {
    op2(3, x, y)
}
fn and(x: N, y: N) -> N {
    op2(12, x, y)
}
/// `[16 [[1 tag] check]]`: the prover injects the witness for `tag`; `check`
/// runs on `[witness subject]` and must return 0.
fn call(tag: u64, check: N) -> N {
    op2(16, quote(tag), check)
}
/// `[2 [[3 [value [0 1]]] [1 body]]]`: evaluate `value` on the subject, push
/// it on the head (`[value subject]`), and run `body` there.
fn let_(value: N, body: N) -> N {
    op2(2, cons(value, axis(1)), pair(atom(1), body))
}
/// Always 0, and evaluated only if `u < 2^32` and `v < 2^32`: the range check
/// of both operands in one 32-row word op (see the module doc).
fn z2(u: N, v: N) -> N {
    mul(quote(0), and(u, v))
}

/// The axis, in a subject whose root is at `outer`, of the node at `inner`
/// of that root's own frame.
fn compose_axis(outer: u64, inner: u64) -> u64 {
    let d = 63 - inner.leading_zeros();
    (outer << d) | (inner - (1u64 << d))
}

/// A frame: names of values and their axes in the subject. `push` models
/// `let_`: the new value at axis 2, the old subject at axis 3. The check
/// formula of a `call` sees the same frame as the `let_` that follows it.
#[derive(Clone)]
struct Fr(Vec<(&'static str, u64)>);
impl Fr {
    fn new(vars: &[(&'static str, u64)]) -> Fr {
        Fr(vars.to_vec())
    }
    fn push(&self, name: &'static str) -> Fr {
        let mut v: Vec<(&'static str, u64)> = self
            .0
            .iter()
            .map(|&(n, a)| (n, compose_axis(3, a)))
            .collect();
        v.push((name, 2));
        Fr(v)
    }
    fn axis(&self, name: &str) -> u64 {
        self.0
            .iter()
            .rev()
            .find(|e| e.0 == name)
            .map(|e| e.1)
            .unwrap_or_else(|| panic!("no variable {name} in the frame"))
    }
    fn get(&self, name: &str) -> N {
        axis(self.axis(name))
    }
}

/// `[x0 x1]` cons tree over the items, balanced; the axis of each item in the
/// tree's own frame (root 1).
fn wtree(mut items: Vec<N>) -> (N, Vec<u64>) {
    if items.len() == 1 {
        return (items.pop().unwrap(), vec![1]);
    }
    let right = items.split_off(items.len() / 2);
    let (l, la) = wtree(items);
    let (r, ra) = wtree(right);
    let axes = la
        .iter()
        .map(|&x| compose_axis(2, x))
        .chain(ra.iter().map(|&x| compose_axis(3, x)))
        .collect();
    (cons(l, r), axes)
}

/// A balanced add tree (empty is 0).
fn sum_tree(mut terms: Vec<N>) -> N {
    match terms.len() {
        0 => quote(0),
        1 => terms.pop().unwrap(),
        n => {
            let right = terms.split_off(n / 2);
            add(sum_tree(terms), sum_tree(right))
        }
    }
}

// ---- P1: qmul ---------------------------------------------------------------

/// tru `kernel.rs:200`: `shr_u(a as u128 * q as u128, 32) as u64`.
fn qmul_native(a: u64, q: u64) -> u64 {
    (((a as u128) * (q as u128) + (1u128 << 31)) >> 32) as u64
}

/// The program of the module doc; subject `[a [q 0]]`, witnesses tags 0 (`ah`)
/// and 1 (`c1`).
fn qmul_program() -> N {
    fn al(f: &Fr) -> N {
        sub(f.get("a"), mul(quote(1 << 32), f.get("ah")))
    }
    let f0 = Fr::new(&[("a", 2), ("q", 6)]);
    let f1 = f0.push("ah");
    let check_ah = add(
        z2(f1.get("q"), al(&f1)),
        z2(f1.get("ah"), add(f1.get("ah"), quote(1))),
    );
    let f2 = f1.push("c1");
    let v = add(mul(al(&f2), f2.get("q")), quote(1 << 31));
    let c0 = sub(v, mul(quote(1 << 32), f2.get("c1")));
    let check_c1 = add(
        z2(f2.get("c1"), add(f2.get("c1"), quote(1))),
        z2(c0.clone(), c0),
    );
    let body = add(mul(f2.get("ah"), f2.get("q")), f2.get("c1"));
    let_(call(0, check_ah), let_(call(1, check_c1), body))
}

/// The honest witnesses of `qmul_program`.
fn qmul_witness(a: u64, q: u64) -> HashMap<u64, u64> {
    let ah = a >> 32;
    let al = a & 0xFFFF_FFFF;
    let v = al as u128 * q as u128 + (1u128 << 31);
    HashMap::from([(0, ah), (1, ((v >> 32) as u64) % P)])
}

/// The public input vector: the subject is `[a [q 0]]` (last input at the head).
fn qmul_input(a: u64, q: u64) -> Vec<u64> {
    vec![q, a]
}

// ---- P2: one sparse row -----------------------------------------------------

const M20: u64 = (1 << 20) - 1;
/// `w = wa + 2^20 * wb`.
fn split_w(w: u64) -> (u64, u64) {
    (w & M20, w >> 20)
}

/// tru `kernel.rs:161-167` `sym_fwd_row`: `acc: u128 = sum w_k * x_k`, then
/// `shr_u(acc, 40) as u64`.
fn row_native(w: &[u64], x: &[u64]) -> u64 {
    let mut acc = 0u128;
    for k in 0..w.len() {
        acc += w[k] as u128 * x[k] as u128;
    }
    ((acc + (1u128 << 39)) >> 40) as u64
}

/// The program of the module doc for constant weights `w` and entries `x`
/// (`w_k <= 2^40`, `x_k < 2^62`, `1 <= L <= 512`), subject `0`. Witness tags:
/// `k` for `xh_k`, then `L` Bh, `L+1` Ch, `L+2` kappa, `L+3` rh.
fn row_program(w: &[u64], x: &[u64]) -> N {
    let l = w.len();
    assert!(l >= 1 && l == x.len());
    let two30 = 1u64 << 30;
    let base = Fr::new(&[]);
    // one call per entry: xh_k, with xl_k = x_k - 2^30*xh_k derived; the word
    // op checks both below 2^32
    let fc = base.push("xh");
    let calls: Vec<N> = (0..l)
        .map(|k| {
            let xl = sub(quote(x[k]), mul(quote(two30), fc.get("xh")));
            call(k as u64, z2(fc.get("xh"), xl))
        })
        .collect();
    let (tree, leaf) = wtree(calls);
    let f1 = base.push("W");
    let wleaf = |f: &Fr, k: usize| axis(compose_axis(f.axis("W"), leaf[k]));
    let (wa, wb): (Vec<u64>, Vec<u64>) = w.iter().map(|&v| split_w(v)).unzip();
    // C = sum wa*xh, D = sum wb*xh
    let c_expr = sum_tree((0..l).map(|k| mul(quote(wa[k]), wleaf(&f1, k))).collect());
    let f2 = f1.push("C");
    let d_expr = sum_tree((0..l).map(|k| mul(quote(wb[k]), wleaf(&f2, k))).collect());
    let f3 = f2.push("D");
    // A = SA - 2^30*C with SA = sum wa*x (runtime muls of constants)
    let sa = sum_tree((0..l).map(|k| mul(quote(wa[k]), quote(x[k]))).collect());
    let a_expr = sub(sa, mul(quote(two30), f3.get("C")));
    let f4 = f3.push("A");
    let sb = sum_tree((0..l).map(|k| mul(quote(wb[k]), quote(x[k]))).collect());
    let b_expr = sub(sb, mul(quote(two30), f4.get("D")));
    let f5 = f4.push("B");
    // the carries
    let bl = |f: &Fr| -> N { sub(f.get("B"), mul(quote(two30), f.get("Bh"))) };
    let cl = |f: &Fr| -> N { sub(f.get("C"), mul(quote(two30), f.get("Ch"))) };
    let low = |f: &Fr| -> N {
        add(
            f.get("A"),
            add(
                mul(quote(1 << 20), bl(f)),
                add(mul(quote(two30), cl(f)), quote(1 << 39)),
            ),
        )
    };
    let f6 = f5.push("Bh");
    let check_bh = z2(f6.get("Bh"), bl(&f6));
    let f7 = f6.push("Ch");
    let check_ch = z2(f7.get("Ch"), cl(&f7));
    let f8 = f7.push("k");
    let check_k = z2(f8.get("k"), mul(quote(1 << 9), f8.get("k")));
    let f9 = f8.push("rh");
    let rho_l = sub(
        sub(low(&f9), mul(quote(1 << 40), f9.get("k"))),
        mul(quote(1 << 32), f9.get("rh")),
    );
    let check_rh = add(
        z2(f9.get("rh"), mul(quote(1 << 24), f9.get("rh"))),
        z2(rho_l.clone(), rho_l),
    );
    let out = add(
        mul(quote(1 << 10), add(f9.get("Bh"), f9.get("D"))),
        add(mul(quote(1 << 20), f9.get("Ch")), f9.get("k")),
    );
    let lt = l as u64;
    let tail = let_(
        call(lt, check_bh),
        let_(
            call(lt + 1, check_ch),
            let_(call(lt + 2, check_k), let_(call(lt + 3, check_rh), out)),
        ),
    );
    let with_b = let_(b_expr, tail);
    let with_a = let_(a_expr, with_b);
    let with_d = let_(d_expr, with_a);
    let with_c = let_(c_expr, with_d);
    let_(tree, with_c)
}

/// The prover's witnesses for `row_program`. `xh_adj[k]`, `bh_adj`, `ch_adj`
/// move a limb off its canonical value (the limbs below stay consistent);
/// `None` if the move leaves a range.
fn row_witness(
    w: &[u64],
    x: &[u64],
    xh_adj: &[i64],
    bh_adj: i64,
    ch_adj: i64,
) -> Option<HashMap<u64, u64>> {
    let l = w.len();
    let mut map = HashMap::new();
    let (mut c, mut d, mut sa, mut sb) = (0u128, 0u128, 0u128, 0u128);
    let lim = 1i128 << 32;
    for k in 0..l {
        let (wa, wb) = split_w(w[k]);
        let xh = (x[k] >> 30) as i128 + xh_adj.get(k).copied().unwrap_or(0) as i128;
        let xl = x[k] as i128 - (xh << 30);
        if xh < 0 || xh >= lim || xl < 0 || xl >= lim {
            return None;
        }
        map.insert(k as u64, xh as u64);
        c += wa as u128 * xh as u128;
        d += wb as u128 * xh as u128;
        sa += wa as u128 * x[k] as u128;
        sb += wb as u128 * x[k] as u128;
    }
    let a = sa.checked_sub(c << 30)? as i128;
    let b = sb.checked_sub(d << 30)? as i128;
    let bh = (b >> 30) + bh_adj as i128;
    let ch = ((c as i128) >> 30) + ch_adj as i128;
    let bl = b - (bh << 30);
    let cl = c as i128 - (ch << 30);
    if bh < 0 || bh >= lim || ch < 0 || ch >= lim || bl < 0 || bl >= lim || cl < 0 || cl >= lim {
        return None;
    }
    let low = a + (bl << 20) + (cl << 30) + (1i128 << 39);
    let kappa = low >> 40;
    let rho = low & ((1i128 << 40) - 1);
    let rh = rho >> 32;
    if kappa >= 1 << 23 {
        return None;
    }
    let lt = l as u64;
    map.insert(lt, bh as u64);
    map.insert(lt + 1, ch as u64);
    map.insert(lt + 2, kappa as u64);
    map.insert(lt + 3, rh as u64);
    Some(map)
}

// ---- running, native nox, forgeries -----------------------------------------

fn run_hinted(
    prog: &N,
    input: &[u64],
    w: &HashMap<u64, u64>,
) -> Result<Run, machine::MachineError> {
    let f = |tag: u64, _subject: &N| -> Option<N> { w.get(&tag).map(|&v| N::Atom(v)) };
    machine::execute_hinted(
        prog,
        input,
        BUDGET,
        machine::SEGMENT_LOG_ROWS,
        &Hints {
            witness: Some(&f),
            state: None,
        },
    )
}

fn out_atom(run: &Run) -> u64 {
    match statement::parse(&run.statement.output).expect("a parsable output") {
        N::Atom(v) => v,
        other => panic!("the output is not an atom: {other:?}"),
    }
}

/// nox's call provider for the cross-check: the witness for a tag.
struct Native<'a> {
    w: &'a HashMap<u64, u64>,
}
impl nox::LookProvider for Native<'_> {
    fn look(&self, _c: Goldilocks, _n: Goldilocks, _k: Goldilocks) -> Option<Goldilocks> {
        None
    }
}
impl<const M: usize> nox::CallProvider<M> for Native<'_> {
    fn provide(
        &self,
        r: &mut nox::Reduction<M>,
        tag: Goldilocks,
        _object: nox::Order,
    ) -> Option<nox::Order> {
        let v = *self.w.get(&tag.as_u64())?;
        r.atom(Goldilocks::new(v))
    }
}

fn arena<const M: usize>(r: &mut nox::Reduction<M>, n: &N) -> nox::Order {
    match n {
        N::Atom(v) => r.atom(Goldilocks::new(*v)).unwrap(),
        N::Pair(a, b) => {
            let a = arena::<M>(r, a);
            let b = arena::<M>(r, b);
            r.pair(a, b).unwrap()
        }
    }
}

fn back<const M: usize>(r: &nox::Reduction<M>, o: nox::Order) -> N {
    match r.get(o).unwrap().inner {
        nox::data::Data::Atom { value } => N::Atom(value.as_u64()),
        nox::data::Data::Pair { left, right } => N::Pair(
            Box::new(back::<M>(r, left)),
            Box::new(back::<M>(r, right)),
        ),
    }
}

/// Native `nox::reduce` with the call witnesses: output, cycles, trace rows.
/// Runs on a big stack (the arena is built by value); `None` if the run
/// fails or the arena of `M` nouns is too small.
fn native_nox<const M: usize>(
    prog: &N,
    input: &[u64],
    w: &HashMap<u64, u64>,
) -> Option<(N, u64, usize)> {
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(1 << 29)
            .spawn_scoped(s, || {
                let mut r = Box::new(nox::Reduction::<M>::new());
                let subject = arena::<M>(&mut r, &statement::subject(input));
                let formula = arena::<M>(&mut r, prog);
                let mut tr = nox::VecTrace::default();
                match nox::reduce(&mut r, subject, formula, BUDGET, &Native { w }, &mut tr) {
                    nox::Outcome::Ok(o, rem) => Some((back::<M>(&r, o), BUDGET - rem, tr.0.len())),
                    _ => None,
                }
            })
            .expect("spawn the native nox thread")
            .join()
            .ok()
            .flatten()
    })
}

/// The machine run of an honest instance: output equals `expect` and native
/// nox (output, cycles). Returns the run and native nox's trace rows.
fn honest<const M: usize>(
    prog: &N,
    input: &[u64],
    w: &HashMap<u64, u64>,
    expect: u64,
    must_native: bool,
) -> (Run, Option<usize>) {
    let run = run_hinted(prog, input, w).expect("the honest witnesses are accepted");
    assert_eq!(out_atom(&run), expect, "machine output vs tru's formula");
    match native_nox::<M>(prog, input, w) {
        Some((out, cycles, rows)) => {
            assert_eq!(out, N::Atom(expect), "native nox vs tru's formula");
            assert_eq!(cycles, run.statement.cycles, "machine vs native cycles");
            (run, Some(rows))
        }
        None => {
            assert!(!must_native, "native nox failed on an honest instance");
            (run, None)
        }
    }
}

/// `v + d` mod p.
fn bump(v: u64, d: i128) -> u64 {
    (v as i128 + d).rem_euclid(P as i128) as u64
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Run a forged witness map. The soundness property: the run is rejected, or
/// it is accepted and its output is still `expect`. Returns true if accepted.
fn forged_run(
    prog: &N,
    input: &[u64],
    forged: &HashMap<u64, u64>,
    expect: u64,
    what: &str,
) -> bool {
    match run_hinted(prog, input, forged) {
        Err(_) => false,
        Ok(run) => {
            assert_eq!(
                out_atom(&run),
                expect,
                "a forged witness ({what}) was accepted with a different output"
            );
            true
        }
    }
}

/// Single-slot and two-slot forgeries of an honest witness map. Returns
/// (attempts, accepted-with-the-same-output).
fn forgeries(
    prog: &N,
    input: &[u64],
    honest: &HashMap<u64, u64>,
    expect: u64,
    rng: &mut Rng,
) -> (usize, usize) {
    let mut tags: Vec<u64> = honest.keys().copied().collect();
    tags.sort();
    let mut deltas: Vec<i128> = vec![
        1,
        -1,
        2,
        -2,
        1 << 10,
        -(1 << 10),
        1 << 30,
        -(1 << 30),
        1 << 31,
        -(1 << 31),
        1 << 32,
        -(1 << 32),
        (1 << 32) - 1,
        -((1 << 32) - 1),
    ];
    for _ in 0..4 {
        deltas.push((rng.next() % P) as i128);
    }
    let (mut tried, mut same) = (0usize, 0usize);
    for &t in &tags {
        for &d in &deltas {
            let nv = bump(honest[&t], d);
            if nv == honest[&t] {
                continue;
            }
            let mut f = honest.clone();
            f.insert(t, nv);
            tried += 1;
            if forged_run(prog, input, &f, expect, &format!("slot {t} delta {d}")) {
                same += 1;
            }
        }
    }
    for _ in 0..(40 * tags.len()).min(400) {
        let mut f = honest.clone();
        for _ in 0..2 {
            let t = tags[(rng.next() % tags.len() as u64) as usize];
            let d = (rng.next() % P) as i128 - (P / 2) as i128;
            let nv = bump(f[&t], d);
            f.insert(t, nv);
        }
        if &f == honest {
            continue;
        }
        tried += 1;
        if forged_run(prog, input, &f, expect, "two random slots") {
            same += 1;
        }
    }
    (tried, same)
}

fn random_row(rng: &mut Rng, l: usize) -> (Vec<u64>, Vec<u64>) {
    let us: Vec<u64> = (0..l).map(|_| (rng.next() >> 40) | 1).collect();
    let total: u128 = us.iter().map(|&u| u as u128).sum();
    // sum w <= 2^40: a column-normalised row of tru's graph
    let w: Vec<u64> = us
        .iter()
        .map(|&u| (((u as u128) << 40) / total) as u64)
        .collect();
    let x: Vec<u64> = (0..l).map(|_| rng.next() % ((1u64 << 60) + 1)).collect();
    (w, x)
}

// ---- tests ------------------------------------------------------------------

#[test]
fn qmul_equals_tru_and_forged_hints_are_rejected() {
    let prog = qmul_program();
    let mut rng = Rng(0x7051);
    let edge_a: [u64; 12] = [
        0,
        1,
        2,
        (1 << 31) - 1,
        1 << 31,
        (1 << 32) - 1,
        1 << 32,
        (1 << 32) + 1,
        1 << 60,
        1 << 62,
        (1 << 63) - 1,
        0x0123_4567_89AB_CDEF,
    ];
    let edge_q: [u64; 7] = [
        0,
        1,
        1 << 30,
        (1 << 31) - 1,
        1 << 31,
        (1 << 31) + 1,
        (1 << 32) - 1,
    ];
    let mut cases: Vec<(u64, u64)> = vec![];
    for &a in &edge_a {
        for &q in &edge_q {
            cases.push((a, q));
        }
    }
    // rounding boundaries: a*q + 2^31 exactly a multiple of 2^32 and one below
    cases.extend([(1, 1 << 31), (1, (1 << 31) - 1), (3, 1 << 31), (2, 1 << 31)]);
    for _ in 0..60 {
        cases.push((rng.next() >> 1, rng.next() & 0xFFFF_FFFF));
    }
    for &(a, q) in &cases {
        let w = qmul_witness(a, q);
        let (run, _) = honest::<{ 1 << 15 }>(&prog, &qmul_input(a, q), &w, qmul_native(a, q), true);
        assert!(run.statement.cycles > 0);
    }

    // forged hints
    let (mut tried, mut same) = (0, 0);
    for &(a, q) in &[
        (0u64, 12345u64),
        (0, 0),
        (1, 1 << 31),
        (0x0123_4567_89AB_CDEF, 0x9E37_79B9),
        ((1 << 63) - 1, (1 << 32) - 1),
        (1 << 32, 1),
    ] {
        let input = qmul_input(a, q);
        let expect = qmul_native(a, q);
        let h = qmul_witness(a, q);
        // every +-1 on the two witnesses is rejected outright
        for tag in [0u64, 1] {
            for d in [1i128, -1] {
                let mut f = h.clone();
                f.insert(tag, bump(h[&tag], d));
                assert!(
                    run_hinted(&prog, &input, &f).is_err(),
                    "a={a} q={q}: witness {tag} moved by {d} was accepted"
                );
            }
        }
        // the wrap forgery: c1 = 2^32-1 with c0 = V+1 (= V + p) for small V
        let mut f = h.clone();
        f.insert(1, (1 << 32) - 1);
        assert!(
            run_hinted(&prog, &input, &f).is_err(),
            "a={a} q={q}: c1 = 2^32-1 accepted"
        );
        let (t, s) = forgeries(&prog, &input, &h, expect, &mut rng);
        tried += t;
        same += s;
    }
    println!("P7-sound program=P1 forgeries={tried} accepted_same_output={same}");

    // outside the domain: q = 2^32 (Q_ONE) and q = p-1 have no accepted witness
    for q in [1u64 << 32, P - 1] {
        let a = 0x0123_4567_89AB_CDEF;
        assert!(
            run_hinted(&prog, &qmul_input(a, q), &qmul_witness(a, q)).is_err(),
            "q = {q} accepted"
        );
    }
}

#[test]
fn sparse_row_equals_tru_and_forged_hints_are_rejected() {
    let mut rng = Rng(0x7052);
    let one = 1u64 << 40;
    let top = 1u64 << 60;
    // edge rows: (weights, entries)
    let mut rows: Vec<(Vec<u64>, Vec<u64>)> = vec![
        (vec![one], vec![top]),                       // identity: output 2^60
        (vec![0], vec![top]),                         // zero weight
        (vec![one], vec![0]),                         // zero entry
        (vec![1 << 39], vec![1]),                     // rounds up to 1 (acc + 2^39 = 2^40)
        (vec![(1 << 39) - 1], vec![1]),               // rounds down to 0
        (vec![one - 1], vec![top - 1]),               // wa = 2^20-1, wb = 2^20-1
        (vec![1 << 20], vec![(1 << 30) - 1]),         // wa = 0, xh = 0
        (vec![(1 << 20) - 1], vec![1 << 30]),         // wb = 0, xl = 0
        (vec![1 << 37; 8], vec![top; 8]),             // eight maximal entries, sum w = 2^40
        (vec![one / 3, one / 3, one / 3], vec![top, top - 1, 1]),
    ];
    for l in [1usize, 2, 3, 5, 8, 13] {
        rows.push(random_row(&mut rng, l));
    }
    for (w, x) in &rows {
        let prog = row_program(w, x);
        let wit = row_witness(w, x, &[], 0, 0).expect("honest witnesses");
        honest::<{ 1 << 16 }>(&prog, &[], &wit, row_native(w, x), true);
    }

    // alternative valid witnesses give the same output: xh_k - 1 (xl_k + 2^30),
    // Bh - 1, Ch - 1
    let (w, x) = random_row(&mut rng, 4);
    let prog = row_program(&w, &x);
    let expect = row_native(&w, &x);
    let mut alts = 0;
    for k in 0..4 {
        let mut adj = vec![0i64; 4];
        adj[k] = -1;
        if let Some(wit) = row_witness(&w, &x, &adj, 0, 0) {
            let run = run_hinted(&prog, &[], &wit).expect("an alternative valid xh");
            assert_eq!(out_atom(&run), expect);
            alts += 1;
        }
    }
    for (bh, ch) in [(-1, 0), (0, -1), (-1, -1)] {
        if let Some(wit) = row_witness(&w, &x, &[], bh, ch) {
            let run = run_hinted(&prog, &[], &wit).expect("an alternative valid carry");
            assert_eq!(out_atom(&run), expect);
            alts += 1;
        }
    }
    assert!(alts >= 3, "alternative witnesses exercised: {alts}");

    // forged hints on several rows: rejected, or accepted with the native output
    let (mut tried, mut same) = (0, 0);
    for l in [1usize, 3, 4] {
        let (w, x) = random_row(&mut rng, l);
        let prog = row_program(&w, &x);
        let expect = row_native(&w, &x);
        let h = row_witness(&w, &x, &[], 0, 0).unwrap();
        // the first-order forgeries of each tail witness are never accepted
        let lt = l as u64;
        for tag in lt..lt + 4 {
            for d in [1i128, -1] {
                let mut f = h.clone();
                f.insert(tag, bump(h[&tag], d));
                // +-1 on kappa or rh shifts rho_l out of its range; on Bh or Ch
                // it moves Bl or Cl by 2^30 and Low with it
                assert!(
                    !forged_run(&prog, &[], &f, expect, "tail +-1"),
                    "tail slot {tag} moved by {d} was accepted"
                );
            }
        }
        let (t, s) = forgeries(&prog, &[], &h, expect, &mut rng);
        tried += t;
        same += s;
    }
    println!("P7-sound program=P2 forgeries={tried} accepted_same_output={same}");
}

struct Meas {
    rows: usize,
    init: usize,
    steps_est: usize,
    perm_rows: usize,
    segments: usize,
    cycles: u64,
    nox_rows: Option<usize>,
    proof_bytes: usize,
    prove_ms: f64,
    verify_ms: f64,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

/// Run, cross-check, prove, verify, and check that a forged statement does not
/// verify.
fn measure<const M: usize>(
    prog: &N,
    input: &[u64],
    w: &HashMap<u64, u64>,
    expect: u64,
    must_native: bool,
) -> Meas {
    let (run, nox_rows) = honest::<M>(prog, input, w, expect, must_native);
    let whir = zheng::execution::succinct::params_for(20);
    let rows = run.trace.rows();
    let reps = if rows > 1 << 17 { 3 } else { 5 };
    let mut prove = vec![];
    let mut last = None;
    for _ in 0..reps {
        let t = Instant::now();
        let proof = machine::prove_run(&run, &whir).expect("the machine proves the run");
        prove.push(ms(t));
        last = Some(proof);
    }
    let proof = last.unwrap();
    machine::verify(&run.statement, &proof, &whir).expect("the proof verifies");
    let verify = median(
        (0..11)
            .map(|_| {
                let t = Instant::now();
                machine::verify(&run.statement, &proof, &whir).unwrap();
                ms(t)
            })
            .collect(),
    );
    // a forged statement does not verify: another output, another cycle count
    let mut bad = run.statement.clone();
    bad.output = statement::tokens(&N::Atom((expect + 1) % P));
    assert!(
        machine::verify(&bad, &proof, &whir).is_err(),
        "a forged output verified"
    );
    let mut bad = run.statement.clone();
    bad.cycles += 1;
    bad.budget += 1;
    assert!(
        machine::verify(&bad, &proof, &whir).is_err(),
        "a forged cycle count verified"
    );
    Meas {
        rows,
        init: run.init.len(),
        steps_est: run.start.saturating_sub(run.init.len()),
        perm_rows: rows - run.start,
        segments: run.segments(),
        cycles: run.statement.cycles,
        nox_rows,
        proof_bytes: proof.to_bytes().len(),
        prove_ms: median(prove),
        verify_ms: verify,
    }
}

fn report(program: &str, l: Option<usize>, m: &Meas, backend: &str) {
    let threads = std::env::var("ZHENG_THREADS").unwrap_or_else(|_| "unset".into());
    let lv = l.map_or("-".to_string(), |l| l.to_string());
    let per = l.map_or(String::new(), |l| {
        format!(" rows_per_entry={:.1}", m.rows as f64 / l as f64)
    });
    let nr = m.nox_rows.map_or("na".to_string(), |r| r.to_string());
    println!(
        "P7 program={program} L={lv} rows={} init={} steps_est={} perm_rows={} segments={} cycles={} \
         nox_rows={nr}{per} proof_bytes={} prove_ms={:.1} verify_ms={:.2} arch={} os={} \
         ZHENG_THREADS={threads} backend={backend}",
        m.rows,
        m.init,
        m.steps_est,
        m.perm_rows,
        m.segments,
        m.cycles,
        m.proof_bytes,
        m.prove_ms,
        m.verify_ms,
        std::env::consts::ARCH,
        std::env::consts::OS,
    );
}

/// Least squares `y = a + b x`; also the largest absolute residual.
fn fit(pts: &[(f64, f64)]) -> (f64, f64, f64) {
    let n = pts.len() as f64;
    let sx: f64 = pts.iter().map(|p| p.0).sum();
    let sy: f64 = pts.iter().map(|p| p.1).sum();
    let sxx: f64 = pts.iter().map(|p| p.0 * p.0).sum();
    let sxy: f64 = pts.iter().map(|p| p.0 * p.1).sum();
    let b = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    let a = (sy - b * sx) / n;
    let resid = pts
        .iter()
        .map(|p| (p.1 - (a + b * p.0)).abs())
        .fold(0.0, f64::max);
    (a, b, resid)
}

#[test]
fn phi_primitives_are_measured() {
    // the prover backend: the CPU unless `ZHENG_BACKEND` (cpu, metal, webgpu,
    // auto) installs another one for the process (an explicit choice that is
    // unavailable fails the test)
    let (backend, device) = match std::env::var("ZHENG_BACKEND") {
        Ok(choice) => cyber_lens_gpu::install(choice.parse::<cyber_lens_gpu::Choice>().unwrap())
            .unwrap_or_else(|e| panic!("backend `{choice}`: {e}")),
        Err(_) => ("cpu", "default".to_string()),
    };
    println!("backend: {backend} ({device})");

    // P1
    let (a, q) = (0x0123_4567_89AB_CDEFu64, 0x9E37_79B9u64);
    let m = measure::<{ 1 << 15 }>(
        &qmul_program(),
        &qmul_input(a, q),
        &qmul_witness(a, q),
        qmul_native(a, q),
        true,
    );
    report("P1", None, &m, backend);

    // P2: L = 1, 8, 64, 512 (fixed seed)
    let mut rng = Rng(0x7053);
    let mut pts_rows = vec![];
    let mut pts_steps = vec![];
    let mut pts_cycles = vec![];
    let mut pts_nox = vec![];
    for &l in &[1usize, 8, 64, 512] {
        let (w, x) = random_row(&mut rng, l);
        let prog = row_program(&w, &x);
        let wit = row_witness(&w, &x, &[], 0, 0).expect("honest witnesses");
        let m = match l {
            0..=8 => measure::<{ 1 << 16 }>(&prog, &[], &wit, row_native(&w, &x), true),
            9..=64 => measure::<{ 1 << 18 }>(&prog, &[], &wit, row_native(&w, &x), true),
            _ => measure::<{ 1 << 21 }>(&prog, &[], &wit, row_native(&w, &x), false),
        };
        report("P2", Some(l), &m, backend);
        let lf = l as f64;
        pts_rows.push((lf, m.rows as f64));
        pts_steps.push((lf, m.steps_est as f64));
        pts_cycles.push((lf, m.cycles as f64));
        if let Some(r) = m.nox_rows {
            pts_nox.push((lf, r as f64));
        }
    }
    let (ra, rb, rr) = fit(&pts_rows);
    let (sa, sb, sr) = fit(&pts_steps);
    let (ca, cb, cr) = fit(&pts_cycles);
    let nox = if pts_nox.len() >= 2 {
        let (na, nb, nr) = fit(&pts_nox);
        format!("nox_rows_a={na:.1} nox_rows_b={nb:.2} nox_rows_resid={nr:.1}")
    } else {
        "nox_rows_a=na nox_rows_b=na nox_rows_resid=na".to_string()
    };
    println!(
        "P7-fit program=P2 points={} rows_a={ra:.1} rows_b={rb:.2} rows_resid={rr:.1} \
         steps_est_a={sa:.1} steps_est_b={sb:.2} steps_est_resid={sr:.1} \
         cycles_a={ca:.1} cycles_b={cb:.2} cycles_resid={cr:.1} {nox}",
        pts_rows.len()
    );
}
