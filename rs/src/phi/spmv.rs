// ---
// tags: zheng, rust, spmv
// crystal-type: source
// crystal-domain: comp
// ---
//! Sparse matrix-vector multiply as multi-row linear CCS.
//!
//! Public: adjacency edges (i, j, w) meaning y[i] += w · x[j].
//! Witness: x[0..n), y[0..n).
//! Constraint row r:  (Σ_j A[r,j] · x[j]) − y[r] = 0.
//!
//! Encoded as single matrix M with M·z = 0, z = [x ‖ y], num_rows = n
//! (padded to power of two for outer sumcheck).

use hemera::hash as hemera_hash;
use lens::brakedown::Brakedown;
use nebu::Goldilocks;

use crate::ccs::selector::is_satisfied;
use crate::spartan::verifier::SpartanVerifier;
use crate::transcript::Transcript;
use crate::types::{
    Accumulator, CCSInstance, CCSWitness, Proof, ProofParams, SparseMatrix, Statement,
};
use crate::{decide, fold};

/// Directed weighted edge: contribution `w * x[col]` added into `y[row]`.
#[derive(Clone, Debug)]
pub struct SparseGraph {
    pub n: usize,
    pub edges: Vec<(usize, usize, Goldilocks)>, // (row, col, weight)
}

impl SparseGraph {
    pub fn empty(n: usize) -> Self {
        Self {
            n,
            edges: Vec::new(),
        }
    }

    pub fn add(&mut self, row: usize, col: usize, w: Goldilocks) {
        debug_assert!(row < self.n && col < self.n);
        self.edges.push((row, col, w));
    }

    /// Content hash of the public graph (binds the proof statement).
    pub fn commitment(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(8 + self.edges.len() * 24);
        buf.extend_from_slice(&(self.n as u64).to_le_bytes());
        for &(r, c, w) in &self.edges {
            buf.extend_from_slice(&(r as u64).to_le_bytes());
            buf.extend_from_slice(&(c as u64).to_le_bytes());
            buf.extend_from_slice(&w.as_u64().to_le_bytes());
        }
        *hemera_hash(&buf)
            .as_bytes()
            .first_chunk::<32>()
            .unwrap_or(&[0u8; 32])
    }
}

/// Host-side SpMV: y = A · x.
pub fn spmv_native(graph: &SparseGraph, x: &[Goldilocks]) -> Vec<Goldilocks> {
    assert_eq!(x.len(), graph.n);
    let mut y = vec![Goldilocks::ZERO; graph.n];
    for &(r, c, w) in &graph.edges {
        y[r] += w * x[c];
    }
    y
}

/// Build CCS for A·x − y = 0 with public A.
pub fn spmv_ccs(graph: &SparseGraph) -> CCSInstance {
    let n = graph.n;
    let rows = n.next_power_of_two().max(1);
    let cols = (2 * n).next_power_of_two().max(2);
    let mut m = SparseMatrix::new(rows, cols);
    let neg_one = Goldilocks::ZERO - Goldilocks::ONE;
    for &(r, c, w) in &graph.edges {
        // accumulate if duplicate (row,col)
        // SparseMatrix::set always pushes; duplicate cols in same row are summed in mul
        m.set(r, c, w);
    }
    for i in 0..n {
        m.set(i, n + i, neg_one);
    }
    // padding rows stay zero → always satisfied
    CCSInstance {
        matrices: vec![m],
        multisets: vec![vec![0]],
        coeffs: vec![Goldilocks::ONE],
        num_rows: rows,
        num_cols: cols,
    }
}

/// Witness z = [x ‖ y ‖ 0-pad].
pub fn spmv_witness(graph: &SparseGraph, x: &[Goldilocks], y: &[Goldilocks]) -> CCSWitness {
    let n = graph.n;
    let cols = (2 * n).next_power_of_two().max(2);
    let mut z = vec![Goldilocks::ZERO; cols];
    z[..n].copy_from_slice(x);
    z[n..2 * n].copy_from_slice(y);
    CCSWitness { z }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SpmvError {
    DimMismatch,
    Unsatisfied,
    FoldFailed,
    DecideFailed,
    VerifyFailed,
}

/// Public claim: graph G, vector x_commit, y = A x.
#[derive(Clone, Debug)]
pub struct SpmvStatement {
    pub graph_commit: [u8; 32],
    pub x_hash: [u8; 32],
    pub y_hash: [u8; 32],
    pub n: usize,
}

impl SpmvStatement {
    pub fn new(graph: &SparseGraph, x: &[Goldilocks], y: &[Goldilocks]) -> Self {
        Self {
            graph_commit: graph.commitment(),
            x_hash: vec_hash(x),
            y_hash: vec_hash(y),
            n: graph.n,
        }
    }

    pub fn to_zheng(&self) -> Statement {
        let mut input = [0u8; 32];
        input[..8].copy_from_slice(&(self.n as u64).to_le_bytes());
        Statement {
            program_hash: {
                let mut h = [0u8; 32];
                let tag = b"zheng-spmv-v0";
                h[..tag.len()].copy_from_slice(tag);
                h
            },
            input_hash: input,
            output_hash: {
                let mut b = [0u8; 32];
                let mut buf = [0u8; 96];
                buf[..32].copy_from_slice(&self.graph_commit);
                buf[32..64].copy_from_slice(&self.x_hash);
                buf[64..].copy_from_slice(&self.y_hash);
                let h = hemera_hash(&buf);
                b.copy_from_slice(h.as_bytes().first_chunk::<32>().unwrap_or(&[0u8; 32]));
                b
            },
            focus_bound: self.n as u64,
        }
    }
}

pub struct SpmvProof {
    pub proof: Proof,
    pub statement: SpmvStatement,
}

/// Prove y = A·x for public sparse A.
pub fn prove_spmv(
    graph: &SparseGraph,
    x: &[Goldilocks],
    y: &[Goldilocks],
) -> Result<SpmvProof, SpmvError> {
    if x.len() != graph.n || y.len() != graph.n {
        return Err(SpmvError::DimMismatch);
    }
    // Sanity: host SpMV must match claimed y
    let y_check = spmv_native(graph, x);
    if y_check != y {
        return Err(SpmvError::Unsatisfied);
    }
    let instance = spmv_ccs(graph);
    let witness = spmv_witness(graph, x, y);
    if !is_satisfied(&instance, &witness) {
        return Err(SpmvError::Unsatisfied);
    }
    let stmt = SpmvStatement::new(graph, x, y);
    let zheng_stmt = stmt.to_zheng();
    let mut acc = blank_acc(&instance);
    let mut t = Transcript::new();
    fold(&mut acc, &instance, &witness, &mut t).map_err(|_| SpmvError::FoldFailed)?;
    let proof =
        decide(&acc, &zheng_stmt, &ProofParams::default()).map_err(|_| SpmvError::DecideFailed)?;
    Ok(SpmvProof {
        proof,
        statement: stmt,
    })
}

/// Verify an SpMV proof. Re-folds from public graph + claimed x,y hashes
/// require the verifier to hold (graph, x, y) or open them from commitments;
/// this API takes the same public inputs as prove for domain-local use.
pub fn verify_spmv(
    graph: &SparseGraph,
    x: &[Goldilocks],
    y: &[Goldilocks],
    proof: &SpmvProof,
) -> bool {
    if x.len() != graph.n || y.len() != graph.n {
        return false;
    }
    if graph.commitment() != proof.statement.graph_commit {
        return false;
    }
    if vec_hash(x) != proof.statement.x_hash || vec_hash(y) != proof.statement.y_hash {
        return false;
    }
    if spmv_native(graph, x) != y {
        return false;
    }
    let instance = spmv_ccs(graph);
    let witness = spmv_witness(graph, x, y);
    if !is_satisfied(&instance, &witness) {
        return false;
    }
    let zheng_stmt = proof.statement.to_zheng();
    let mut acc = blank_acc(&instance);
    let mut t = Transcript::new();
    if fold(&mut acc, &instance, &witness, &mut t).is_err() {
        return false;
    }
    let mut vt = Transcript::new_recursive();
    vt.absorb_statement(&zheng_stmt);
    vt.absorb(acc.witness_commitment.as_bytes());
    for &e in &acc.error_evals {
        vt.absorb(&e.as_u64().to_le_bytes());
    }
    vt.absorb(&acc.step_count.to_le_bytes());
    SpartanVerifier::verify(
        &acc.committed_instance,
        &proof.proof,
        &acc.error_evals,
        &mut vt,
    )
    .is_ok()
}

fn blank_acc(instance: &CCSInstance) -> Accumulator {
    let z = vec![Goldilocks::ZERO; instance.num_cols.max(64)];
    Accumulator {
        committed_instance: instance.clone(),
        folded_witness: CCSWitness { z: z.clone() },
        witness_commitment: Brakedown::commit_raw(&z),
        error_evals: vec![Goldilocks::ZERO; instance.num_rows],
        step_count: 0,
    }
}

fn vec_hash(v: &[Goldilocks]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + v.len() * 8);
    buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
    for x in v {
        buf.extend_from_slice(&x.as_u64().to_le_bytes());
    }
    *hemera_hash(&buf)
        .as_bytes()
        .first_chunk::<32>()
        .unwrap_or(&[0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    #[test]
    fn spmv_native_2x2() {
        let mut graph = SparseGraph::empty(2);
        graph.add(0, 0, g(2));
        graph.add(0, 1, g(3));
        graph.add(1, 0, g(4));
        let x = vec![g(5), g(6)];
        let y = spmv_native(&graph, &x);
        // y0 = 2*5+3*6 = 28, y1 = 4*5 = 20
        assert_eq!(y[0], g(28));
        assert_eq!(y[1], g(20));
    }

    #[test]
    fn spmv_ccs_satisfied() {
        let mut graph = SparseGraph::empty(3);
        graph.add(0, 1, g(2));
        graph.add(1, 2, g(3));
        graph.add(2, 0, g(5));
        graph.add(2, 2, g(1));
        let x = vec![g(1), g(2), g(3)];
        let y = spmv_native(&graph, &x);
        let ccs = spmv_ccs(&graph);
        let w = spmv_witness(&graph, &x, &y);
        assert!(is_satisfied(&ccs, &w));
        let mut y_bad = y.clone();
        y_bad[0] += g(1);
        let w_bad = spmv_witness(&graph, &x, &y_bad);
        assert!(!is_satisfied(&ccs, &w_bad));
    }

    #[test]
    fn prove_verify_spmv() {
        let mut graph = SparseGraph::empty(4);
        graph.add(0, 1, g(1));
        graph.add(1, 2, g(2));
        graph.add(2, 3, g(3));
        graph.add(3, 0, g(4));
        graph.add(1, 1, g(1));
        let x = vec![g(1), g(2), g(3), g(4)];
        let y = spmv_native(&graph, &x);
        let proof = prove_spmv(&graph, &x, &y).unwrap();
        assert!(verify_spmv(&graph, &x, &y, &proof));
        let mut y2 = y.clone();
        y2[0] = g(0);
        assert!(!verify_spmv(&graph, &x, &y2, &proof));
    }
}
