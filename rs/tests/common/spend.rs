//! A SPEND-shaped nox program (soft3 `proposals/privacy-frozen.md` §2):
//! two inputs, two outputs, every record and key a secret.
//!
//! Per input `i`: four record digests `D1..D4` (token, value, predicate,
//! data · owner · rho · r), the key `sk` (one digest), the commitment
//! `cm = node(node(D1, D2), node(D3, D4))`, the owner check
//! `node(sk, OWNER) = D2`, the nullifier `node(sk, D3)`, and the
//! membership of `cm` under a depth-`d` hemera tree whose siblings and
//! directions are secrets (one node-jet call a level, the root flag on the
//! last). Per output `j`: four digests and `node(node(E1, E2), node(E3,
//! E4))`. The balance `v1 + v2 = w1 + w2 + fee` (fee public), every value
//! below 2^62 (`lt`), and per input a predicate `data·token = pred`.
//! Output: `[root1 [root2 [nf1 [nf2 [cmo1 [cmo2 check]]]]]]`, `check = 0`
//! iff every check holds. Digests are compared limb by limb.
//!
//! The commitment and nullifier encodings are this fixture's, not the
//! frozen formats of `specs/chain.md` §11: the fixture measures the
//! relation's size and the proof's, nothing it encodes is normative.

use zheng::execution::ExecutionNoun as N;
use zheng::execution::node;

fn pr(a: N, b: N) -> N {
    N::Pair(Box::new(a), Box::new(b))
}
fn at(v: u64) -> N {
    N::Atom(v)
}
fn ax(n: u64) -> N {
    pr(at(0), at(n))
}
fn quote(n: N) -> N {
    pr(at(1), n)
}
fn op(t: u64, a: N, b: N) -> N {
    pr(at(t), pr(a, b))
}
/// One secret (tag 1, no check).
fn call() -> N {
    op(16, quote(at(1)), quote(at(0)))
}
fn digest_call() -> N {
    op(3, op(3, call(), call()), op(3, call(), call()))
}

/// Axis `p` inside the noun at axis `a`.
fn compose_axis(a: u64, p: u64) -> u64 {
    let d = 63 - p.leading_zeros();
    (a << d) | (p & ((1u64 << d) - 1))
}

/// Values pushed on the subject, most recent first; each push is a noun
/// whose named parts sit at fixed axes inside it.
struct Env {
    pushes: Vec<Vec<(&'static str, u64)>>,
}

impl Env {
    fn axis(&self, name: &str) -> u64 {
        for (i, parts) in self.pushes.iter().enumerate() {
            if let Some(&(_, p)) = parts.iter().find(|(n, _)| *n == name) {
                return compose_axis((1u64 << (i + 2)) - 2, p);
            }
        }
        panic!("no {name}")
    }
    fn get(&self, name: &str) -> N {
        ax(self.axis(name))
    }
    /// Limb `l` of a digest `[[a b] [c d]]`.
    fn limb(&self, name: &str, l: u64) -> N {
        ax(4 * self.axis(name) + l)
    }
    /// The original subject's head (the first public input).
    fn input0(&self) -> N {
        ax(2 * ((1u64 << (self.pushes.len() + 1)) - 1))
    }
    fn node(&self, l: N, r: N, flags: u64) -> N {
        op(2, op(3, op(3, l, r), quote(at(flags))), self.get("NODE"))
    }
    fn digest(&self) -> N {
        op(2, ax(1), self.get("DIG"))
    }
}

/// Push a value with named parts: run `rest` on `[value subject]`.
fn push(env: &mut Env, parts: &[(&'static str, u64)], value: N, rest: impl FnOnce(&mut Env) -> N) -> N {
    env.pushes.insert(0, parts.to_vec());
    let body = rest(env);
    env.pushes.remove(0);
    op(2, op(3, value, ax(1)), quote(body))
}

/// `[a [b [c …]]]` of formulas.
fn list(items: Vec<N>) -> N {
    let mut it = items.into_iter().rev();
    let last = it.next().expect("non-empty");
    it.fold(last, |acc, x| op(3, x, acc))
}

/// LIB = `[NODE [STEP [STEPR [DIG PATH]]]]`. The level formulas run on
/// the state `[cur LIB]` (cur 2, LIB 3, NODE 6): read `dir` (1 secret) as
/// the branch test, then in the taken branch `sib` (4 secrets), and
/// `cur ← node(dir = 0 ? [cur sib] : [sib cur], flags)`. One read of each
/// secret, no push: the relation compiler's evaluation budget (4,096
/// formula evaluations) holds two depth-40 paths only this lean.
fn level(flags: u64) -> N {
    let children = pr(at(4), pr(call(), pr(op(3, ax(2), digest_call()), op(3, digest_call(), ax(2)))));
    let next = op(2, op(3, children, quote(at(flags))), ax(6));
    op(3, next, ax(3))
}

/// Apply `f` `k` times, composed as a balanced tree (formula depth
/// `O(log k)` within the statement's depth limit).
fn repeat(f: &N, k: usize) -> N {
    if k == 1 {
        return f.clone();
    }
    op(2, repeat(f, k / 2), quote(repeat(f, k - k / 2)))
}

/// The path of `depth` levels from the state `[cm LIB]`; returns the root.
fn path(depth: usize) -> N {
    // in the state: LIB 3, STEP 14, STEPR 30
    let step = |a: u64| op(2, ax(1), ax(a));
    let mut steps = step(30);
    if depth > 1 {
        steps = op(2, repeat(&step(14), depth - 1), quote(steps));
    }
    op(2, steps, quote(ax(2)))
}

fn eq4(env: &Env, a: &str, b: &str) -> N {
    let e = |l| op(9, env.limb(a, l), env.limb(b, l));
    op(5, op(5, e(0), e(1)), op(5, e(2), e(3)))
}

const RECORD: [u64; 5] = [2, 6, 14, 30, 31];
const DERIVED: [u64; 3] = [2, 6, 7];
const OUT: [u64; 4] = [2, 6, 14, 15];

/// The program over the public input `[fee 0]`; secrets in call order
/// come from [`secrets`].
pub fn program(depth: usize) -> N {
    let lib = pr(
        node::formula().clone(),
        pr(level(node::FLAGS_NODE), pr(level(node::FLAGS_ROOT), pr(digest_call(), path(depth)))),
    );
    let mut env = Env { pushes: vec![] };
    push(&mut env, &[("LIB", 1), ("NODE", 2), ("DIG", 30), ("PATH", 31)], quote(lib), |env| {
        input(env, 1, |env| {
            input(env, 2, |env| {
                output(env, 1, |env| {
                    output(env, 2, |env| {
                        let v = |env: &Env, d: &str| env.limb(d, 1);
                        let lhs = op(5, v(env, "D1_1"), v(env, "D1_2"));
                        let rhs = op(5, op(5, v(env, "E1_1"), v(env, "E1_2")), env.input0());
                        let bound = quote(at(1 << 62));
                        let range = ["D1_1", "D1_2", "E1_1", "E1_2"]
                            .iter()
                            .map(|d| op(10, v(env, d), bound.clone()))
                            .reduce(|a, b| op(5, a, b))
                            .expect("four");
                        // D1 = [token value pred data]: data·token = pred
                        let pred = |i: &str| op(9, op(7, env.limb(i, 3), env.limb(i, 0)), env.limb(i, 2));
                        let check = op(
                            5,
                            op(5, eq4(env, "OWN_1", "D2_1"), eq4(env, "OWN_2", "D2_2")),
                            op(5, op(9, lhs, rhs), op(5, range, op(5, pred("D1_1"), pred("D1_2")))),
                        );
                        let outs = ["ROOT_1", "ROOT_2", "NF_1", "NF_2", "CMO_1", "CMO_2"];
                        let mut items: Vec<N> = outs.iter().map(|n| env.get(n)).collect();
                        items.push(check);
                        list(items)
                    })
                })
            })
        })
    })
}

fn input(env: &mut Env, i: usize, rest: impl FnOnce(&mut Env) -> N) -> N {
    let n = |base: &'static str| -> &'static str {
        let table: [(&str, &str, &str); 9] = [
            ("D1", "D1_1", "D1_2"),
            ("D2", "D2_1", "D2_2"),
            ("D3", "D3_1", "D3_2"),
            ("D4", "D4_1", "D4_2"),
            ("SK", "SK_1", "SK_2"),
            ("CM", "CM_1", "CM_2"),
            ("OWN", "OWN_1", "OWN_2"),
            ("NF", "NF_1", "NF_2"),
            ("ROOT", "ROOT_1", "ROOT_2"),
        ];
        let row = table.iter().find(|r| r.0 == base).expect("name");
        if i == 1 { row.1 } else { row.2 }
    };
    let rec: Vec<(&'static str, u64)> = ["D1", "D2", "D3", "D4", "SK"].iter().zip(RECORD).map(|(b, p)| (n(b), p)).collect();
    let reads = list((0..5).map(|_| env.digest()).collect());
    push(env, &rec, reads, |env| {
        let cmv = env.node(
            env.node(env.get(n("D1")), env.get(n("D2")), node::FLAGS_NODE),
            env.node(env.get(n("D3")), env.get(n("D4")), node::FLAGS_NODE),
            node::FLAGS_NODE,
        );
        push(env, &[(n("CM"), 1)], cmv, |env| {
            let owner = node::digest_noun([1, 2, 3, 4]);
            let own = env.node(env.get(n("SK")), quote(owner), node::FLAGS_NODE);
            let nf = env.node(env.get(n("SK")), env.get(n("D3")), node::FLAGS_NODE);
            let root = op(2, op(3, env.get(n("CM")), env.get("LIB")), env.get("PATH"));
            let parts: Vec<(&'static str, u64)> = ["OWN", "NF", "ROOT"].iter().zip(DERIVED).map(|(b, p)| (n(b), p)).collect();
            push(env, &parts, list(vec![own, nf, root]), rest)
        })
    })
}

fn output(env: &mut Env, j: usize, rest: impl FnOnce(&mut Env) -> N) -> N {
    let names: [&'static str; 5] = if j == 1 {
        ["E1_1", "E2_1", "E3_1", "E4_1", "CMO_1"]
    } else {
        ["E1_2", "E2_2", "E3_2", "E4_2", "CMO_2"]
    };
    let parts: Vec<(&'static str, u64)> = names[..4].iter().copied().zip(OUT).collect();
    let reads = list((0..4).map(|_| env.digest()).collect());
    push(env, &parts, reads, |env| {
        let v = env.node(
            env.node(env.get(names[0]), env.get(names[1]), node::FLAGS_NODE),
            env.node(env.get(names[2]), env.get(names[3]), node::FLAGS_NODE),
            node::FLAGS_NODE,
        );
        push(env, &[(names[4], 1)], v, rest)
    })
}

/// Secrets in call order for a valid spend of depth `depth` with `fee`:
/// values 1000 + 2000 in, 2500 + (500 − fee) out.
pub fn secrets(depth: usize, fee: u64) -> Vec<u64> {
    let mut s = Vec::new();
    let mut x = 0x5eed_u64;
    let mut rnd = || {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (x >> 1) % 0xFFFF_FFFF_0000_0001
    };
    let owner = [1u64, 2, 3, 4];
    for (value, tok, data) in [(1000u64, 7u64, 11u64), (2000, 7, 13)] {
        let sk = [rnd(), rnd(), rnd(), rnd()];
        let own = node::native(sk, owner, node::FLAGS_NODE);
        s.extend([tok, value, data * tok, data]); // D1 = token value pred data
        s.extend(own); // D2 = owner
        s.extend([rnd(), rnd(), rnd(), rnd()]); // D3 = rho
        s.extend([rnd(), rnd(), rnd(), rnd()]); // D4 = r
        s.extend(sk);
        for level in 0..depth {
            s.push((level % 2) as u64);
            s.extend([rnd(), rnd(), rnd(), rnd()]);
        }
    }
    for w in [2500u64, 500 - fee] {
        s.extend([7, w, rnd(), rnd()]);
        for _ in 0..3 {
            s.extend([rnd(), rnd(), rnd(), rnd()]);
        }
    }
    s
}
