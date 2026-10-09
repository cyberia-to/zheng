//! The step relation: the nox machine's row relation on one segment and
//! the recursion circuit, side by side over one row index, as one AIR
//! with three committed words of 64 columns each:
//!
//! ```text
//! word a   nox phase 1 (64)                         committed before the run's challenges
//! word b   nox phase 2 (15) ‖ circuit phase 1 (49)  committed at the step
//! word c   circuit phase 2 (54) ‖ zero (10)          after the circuit's challenges
//! ```
//!
//! Constraints: the machine's (`machine::air`, with the run's memory
//! challenges `(α, β)`) followed by the circuit's (with the step's
//! `(α_V, β_V)`). The verifier of a step never evaluates them: it carries
//! the evaluation `G(point) = c` as a deferred claim
//! (`specs/recursion.md` § deferred claims), with
//!
//! ```text
//! point = (local[192], next[192], nox publics[31], circuit publics[107],
//!          public input[4], α_V, β_V, μ1, μ2, μ3)
//! G     = Σ_k μ1^{k mod B}·μ2^{⌊k/B⌋ mod B}·μ3^{⌊k/B²⌋}·C_k
//! ```

use nebu::Fp3;

use super::circuit::air::{CircuitAir, Row, Sink};
use super::circuit::layout::{self as cl, PIN};
use crate::air::{Air, Public, Shape, Vals};
use crate::machine::air::{Machine, PUBLICS};
use crate::machine::layout::{W1, W2};

/// Columns of each committed word.
pub const WORD: usize = 64;
pub const COLS: usize = 3 * WORD;
/// Where the circuit's phase-1 columns start (after nox phase 2).
pub const V1_AT: usize = WORD + W2;
pub const V2_AT: usize = 2 * WORD;
/// Publics: nox, circuit key, public input.
pub const PUB_NOX: usize = PUBLICS;
pub const PUB_V: usize = cl::pre::COUNT;
pub const PUBS: usize = PUB_NOX + PUB_V + PIN;
/// Coordinates of the deferred constraint claim.
pub const SEEDS: usize = 3;
pub const G_POINT: usize = 2 * COLS + PUBS + 2 + SEEDS;

const _: () = assert!(W1 == WORD && W2 + cl::V1 <= WORD && cl::V2 <= WORD);

pub struct Relation {
    pub machine: Machine,
    pub circuit: CircuitAir,
    /// The run's memory challenges.
    pub ch: [Fp3; 2],
    constraints: usize,
    /// Base of the batching powers.
    pub base: usize,
}

impl Relation {
    pub fn new(machine: Machine, ch: [Fp3; 2]) -> Self {
        let circuit = CircuitAir::default();
        let constraints = machine.shape().constraints + circuit.constraints();
        let mut base = 2;
        while base * base * base < constraints {
            base += 1;
        }
        Self { machine, circuit, ch, constraints, base }
    }
    pub fn constraints(&self) -> usize {
        self.constraints
    }
    pub fn degree(&self) -> usize {
        8
    }
    /// The degree of `G` along a line: the constraints' and the powers'.
    pub fn g_degree(&self) -> usize {
        self.degree() + SEEDS * (self.base - 1)
    }

    /// The batching vector `μ1^a μ2^b μ3^c` of constraint `k = a + bB + cB²`.
    pub fn mu(&self, seeds: &[Fp3]) -> Vec<Fp3> {
        let b = self.base;
        let pw = |x: Fp3| {
            let mut v = Vec::with_capacity(b);
            let mut c = Fp3::ONE;
            for _ in 0..b {
                v.push(c);
                c *= x;
            }
            v
        };
        let (p1, p2, p3) = (pw(seeds[0]), pw(seeds[1]), pw(seeds[2]));
        (0..self.constraints).map(|k| p1[k % b] * p2[(k / b) % b] * p3[k / (b * b)]).collect()
    }

    /// Every constraint at one assignment.
    pub fn eval(&self, local: &[Fp3], next: &[Fp3], pubs: &[Fp3], ch_v: &[Fp3], out: &mut [Fp3]) {
        let km = self.machine.shape().constraints;
        let v = Vals {
            local: &local[..W1 + W2],
            next: &next[..W1 + W2],
            publics: &pubs[..PUB_NOX],
        };
        self.machine.eval(&v, &self.ch, &mut out[..km]);
        let row = Row {
            l1: &local[V1_AT..V1_AT + cl::V1],
            l2: &local[V2_AT..V2_AT + cl::V2],
            n1: &next[V1_AT..V1_AT + cl::V1],
            n2: &next[V2_AT..V2_AT + cl::V2],
            p: &pubs[PUB_NOX..PUB_NOX + PUB_V],
            pin: &pubs[PUB_NOX + PUB_V..],
            alpha: ch_v[0],
            beta: ch_v[1],
        };
        let mut s = Sink { buf: &mut out[km..], i: 0 };
        self.circuit.eval(&row, &mut s);
    }

    /// `G` at a deferred point.
    pub fn g(&self, point: &[Fp3]) -> Fp3 {
        assert_eq!(point.len(), G_POINT);
        let (local, next, pubs) = (&point[..COLS], &point[COLS..2 * COLS], &point[2 * COLS..2 * COLS + PUBS]);
        let ch_v = &point[2 * COLS + PUBS..2 * COLS + PUBS + 2];
        let seeds = &point[2 * COLS + PUBS + 2..];
        let mut out = vec![Fp3::ZERO; self.constraints];
        self.eval(local, next, pubs, ch_v, &mut out);
        out.iter().zip(self.mu(seeds)).fold(Fp3::ZERO, |a, (&c, m)| a + c * m)
    }
}

/// The relation as an [`Air`] for the zerocheck prover (`challenges` =
/// the circuit's `(α_V, β_V)`).
pub struct View<'a>(pub &'a Relation);

impl Air for View<'_> {
    fn shape(&self) -> Shape {
        Shape {
            w1: COLS,
            w2: 0,
            challenges: 2,
            constraints: self.0.constraints,
            degree: self.0.degree(),
        }
    }
    fn publics(&self) -> &[Public] {
        &[]
    }
    fn eval(&self, v: &Vals<'_>, challenges: &[Fp3], out: &mut [Fp3]) {
        self.0.eval(v.local, v.next, v.publics, challenges, out);
    }
}
