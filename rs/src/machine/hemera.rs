//! Hemera's permutation as the machine's row function: the initial linear
//! layer, 4 full rounds, 16 partial rounds (inverse S-box on lane 0), 4 full
//! rounds — one row per round — and the three permutation inputs nox's
//! noun identity uses (atom leaf sponge + chunk node, parent node, the hash
//! opcode's plain absorb). Every matrix and constant is read from hemera
//! itself; `tests` check the row function against `hemera::permutation` and
//! the digests against `nox::data::hash`.

use hemera::field::Goldilocks as HG;
use nebu::Goldilocks;

pub const WIDTH: usize = 16;
pub const ROUNDS: usize = 24;

#[cfg(test)]
fn to_h(x: Goldilocks) -> HG {
    HG::new(x.as_u64())
}
fn from_h(x: HG) -> Goldilocks {
    Goldilocks::new(x.as_canonical_u64())
}

fn matrix(f: fn(&mut [HG; 16])) -> [[Goldilocks; 16]; 16] {
    let mut m = [[Goldilocks::ZERO; 16]; 16];
    for (i, col) in (0..16).map(|i| {
        let mut e = [HG::ZERO; 16];
        e[i] = HG::new(1);
        f(&mut e);
        (i, e)
    }) {
        for (j, v) in col.iter().enumerate() {
            m[j][i] = from_h(*v);
        }
    }
    m
}

/// The external (full-round and initial) linear layer.
pub fn mds() -> [[Goldilocks; 16]; 16] {
    matrix(hemera::field::mds_light_permutation)
}

/// The internal (partial-round) linear layer.
pub fn internal() -> [[Goldilocks; 16]; 16] {
    matrix(hemera::field::matmul_internal)
}

/// Round `k`'s constants: 16 for a full round, lane 0 for a partial one.
pub fn round_constants() -> [[Goldilocks; 16]; ROUNDS] {
    let rc = hemera::constants::ROUND_CONSTANTS;
    let mut out = [[Goldilocks::ZERO; 16]; ROUNDS];
    for (k, row) in out.iter_mut().enumerate() {
        if k < 4 {
            for i in 0..16 {
                row[i] = from_h(rc[k * 16 + i]);
            }
        } else if k < 20 {
            row[0] = from_h(rc[128 + (k - 4)]);
        } else {
            for i in 0..16 {
                row[i] = from_h(rc[64 + (k - 20) * 16 + i]);
            }
        }
    }
    out
}

pub fn is_full(k: usize) -> bool {
    !(4..20).contains(&k)
}

fn apply(m: &[[Goldilocks; 16]; 16], s: &[Goldilocks; 16]) -> [Goldilocks; 16] {
    let mut out = [Goldilocks::ZERO; 16];
    for (o, row) in out.iter_mut().zip(m) {
        *o = row.iter().zip(s).fold(Goldilocks::ZERO, |a, (&c, &x)| a + c * x);
    }
    out
}

fn pow7(x: Goldilocks) -> Goldilocks {
    let x2 = x * x;
    let x3 = x2 * x;
    x3 * x2 * x2
}

/// Precomputed tables for the row function.
pub struct Tables {
    pub mds: [[Goldilocks; 16]; 16],
    pub internal: [[Goldilocks; 16]; 16],
    pub rc: [[Goldilocks; 16]; ROUNDS],
}

impl Default for Tables {
    fn default() -> Self {
        Self {
            mds: mds(),
            internal: internal(),
            rc: round_constants(),
        }
    }
}

impl Tables {
    /// The initial linear layer.
    pub fn pre(&self, s: &[Goldilocks; 16]) -> [Goldilocks; 16] {
        apply(&self.mds, s)
    }
    /// Round `k`: the next state and the partial round's inverse witness.
    pub fn round(&self, s: &[Goldilocks; 16], k: usize) -> ([Goldilocks; 16], Goldilocks) {
        let rc = &self.rc[k];
        if is_full(k) {
            let mut u = [Goldilocks::ZERO; 16];
            for i in 0..16 {
                u[i] = pow7(s[i] + rc[i]);
            }
            (apply(&self.mds, &u), Goldilocks::ZERO)
        } else {
            let mut u = *s;
            let x = s[0] + rc[0];
            let inv = if x == Goldilocks::ZERO { Goldilocks::ZERO } else { x.inv() };
            u[0] = inv;
            (apply(&self.internal, &u), inv)
        }
    }
    /// The whole permutation, row by row: the state before every round
    /// (`ROUNDS + 1` states, the last is the output) and the inverses.
    pub fn trace(&self, input: &[Goldilocks; 16]) -> (Vec<[Goldilocks; 16]>, Vec<Goldilocks>) {
        let mut states = Vec::with_capacity(ROUNDS + 1);
        let mut invs = Vec::with_capacity(ROUNDS);
        let mut s = self.pre(input);
        for k in 0..ROUNDS {
            states.push(s);
            let (n, inv) = self.round(&s, k);
            invs.push(inv);
            s = n;
        }
        states.push(s);
        (states, invs)
    }
    pub fn permute(&self, input: &[Goldilocks; 16]) -> [Goldilocks; 16] {
        *self.trace(input).0.last().expect("output")
    }
}

/// `nox::data::hash_pair`'s permutation input.
pub fn pair_input(l: [Goldilocks; 4], r: [Goldilocks; 4]) -> [Goldilocks; 16] {
    let mut s = [Goldilocks::ZERO; 16];
    s[..4].copy_from_slice(&l);
    s[4..8].copy_from_slice(&r);
    s[9] = Goldilocks::new(FLAG_PARENT);
    s
}

/// The hash opcode's permutation input.
pub fn hop_input(d: [Goldilocks; 4]) -> [Goldilocks; 16] {
    let mut s = [Goldilocks::ZERO; 16];
    s[..4].copy_from_slice(&d);
    s
}

/// The atom leaf's sponge input for `e0 = v mod 2^56`, `e1 = (v>>56) + 256`.
pub fn atom1_input(v: u64) -> [Goldilocks; 16] {
    let mut s = [Goldilocks::ZERO; 16];
    s[0] = Goldilocks::new(v & ((1 << 56) - 1));
    s[1] = Goldilocks::new((v >> 56) + 256);
    s[10] = Goldilocks::new(ATOM_LEN);
    s[11] = Goldilocks::new(DOMAIN_HASH);
    s
}

/// The chunk node over the sponge's base digest.
pub fn atom2_input(base: [Goldilocks; 4]) -> [Goldilocks; 16] {
    let mut s = [Goldilocks::ZERO; 16];
    s[..4].copy_from_slice(&base);
    s[9] = Goldilocks::new(FLAG_CHUNK);
    s
}

/// hemera tree flags and sponge constants used by nox's identities.
pub const FLAG_PARENT: u64 = 1 << 1;
pub const FLAG_CHUNK: u64 = 1 << 2;
pub const ATOM_LEN: u64 = 8;
pub const DOMAIN_HASH: u64 = 0;

pub fn head4(s: &[Goldilocks; 16]) -> [Goldilocks; 4] {
    [s[0], s[1], s[2], s[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_function_is_hemeras_permutation() {
        let t = Tables::default();
        for seed in 0..5u64 {
            let input: [Goldilocks; 16] =
                core::array::from_fn(|i| Goldilocks::new(seed * 1000 + i as u64 * 7919));
            let mut h: [HG; 16] = core::array::from_fn(|i| to_h(input[i]));
            hemera::permutation::permute(&mut h);
            let want: [Goldilocks; 16] = core::array::from_fn(|i| from_h(h[i]));
            assert_eq!(t.permute(&input), want);
        }
        // the partial round's inverse of zero is zero
        let mut z = [Goldilocks::ZERO; 16];
        z[0] = Goldilocks::ZERO - t.rc[4][0];
        let (_, inv) = t.round(&z, 4);
        assert_eq!(inv, Goldilocks::ZERO);
    }

    #[test]
    fn noun_identities_match_nox() {
        let t = Tables::default();
        for v in [0u64, 1, 7, 255, 256, 1 << 56, (1 << 63) + 5, nebu::field::P - 1] {
            let base = head4(&t.permute(&atom1_input(v)));
            let dig = head4(&t.permute(&atom2_input(base)));
            assert_eq!(dig, nox::data::hash_atom(Goldilocks::new(v)), "atom {v}");
        }
        let a = nox::data::hash_atom(Goldilocks::new(3));
        let b = nox::data::hash_atom(Goldilocks::new(4));
        assert_eq!(head4(&t.permute(&pair_input(a, b))), nox::data::hash_pair(&a, &b));
        // the hash opcode: StepSponge over the digest = plain permutation
        let mut sp = hemera::StepSponge::absorb(&a.map(to_h));
        while !sp.done() {
            sp.step();
        }
        let mut st = [HG::ZERO; 16];
        st[..4].copy_from_slice(&a.map(to_h));
        hemera::permutation::permute(&mut st);
        assert_eq!(from_h(sp.squeeze()), from_h(st[0]));
        assert_eq!(head4(&t.permute(&hop_input(a)))[0], from_h(st[0]));
    }
}
