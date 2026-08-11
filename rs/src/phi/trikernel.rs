// ---
// tags: zheng, rust, tri-kernel, phi
// crystal-type: source
// crystal-domain: comp
// ---
//! Tri-kernel iteration and φ* proof.
//!
//! Matches the circuit sketch in foculus/specs/provable-consensus.md § full circuit
//! section 3, specialized to domain size n:
//!
//!   D: diffusion  φ' = α·u + (1−α)·T·φ   (T column-stochastic public)
//!   S: springs    s = W_sym · φ ./ deg    (elementwise)
//!   H: heat       h = A · (A · φ)        (two SpMVs, then ./ deg²)
//!   combine       φ_next = normalize(λd·d + λs·s + λh·h)
//!
//! Each SpMV is proven via [[spmv]]; host computes intermediates; the proof
//! binds the iteration transcript. Domain-local: n is ε-support size.

use hemera::hash as hemera_hash;
use nebu::Goldilocks;

use super::spmv::{SparseGraph, SpmvProof, prove_spmv, spmv_native, verify_spmv};
use crate::types::{Proof, Statement};

/// Default tri-kernel weights (same as foculus/tru defaults).
#[derive(Clone, Debug)]
pub struct TriKernelParams {
    pub lambda_d: Goldilocks,
    pub lambda_s: Goldilocks,
    pub lambda_h: Goldilocks,
    pub alpha: Goldilocks, // teleport mixture for diffusion
}

impl Default for TriKernelParams {
    fn default() -> Self {
        Self::standard()
    }
}

impl TriKernelParams {
    /// Rational weights λd=1/2, λs=3/10, λh=1/5, α=15/100 via field inv.
    pub fn standard() -> Self {
        let inv = |n: u64| Goldilocks::new(n).inv();
        Self {
            lambda_d: inv(2),
            lambda_s: Goldilocks::new(3) * inv(10),
            lambda_h: inv(5),
            alpha: Goldilocks::new(15) * inv(100),
        }
    }
}

/// Public claim for a φ* proof.
#[derive(Clone, Debug)]
pub struct PhiStatement {
    pub graph_commit: [u8; 32],
    pub phi0_hash: [u8; 32],
    pub phi_star_hash: [u8; 32],
    pub iterations: u32,
    pub n: usize,
}

impl PhiStatement {
    pub fn to_zheng(&self) -> Statement {
        let mut input = [0u8; 32];
        input[..4].copy_from_slice(&self.iterations.to_le_bytes());
        input[4..12].copy_from_slice(&(self.n as u64).to_le_bytes());
        Statement {
            program_hash: {
                let mut h = [0u8; 32];
                let tag = b"zheng-phi-star-v0";
                h[..tag.len()].copy_from_slice(tag);
                h
            },
            input_hash: input,
            output_hash: {
                let mut buf = [0u8; 96];
                buf[..32].copy_from_slice(&self.graph_commit);
                buf[32..64].copy_from_slice(&self.phi0_hash);
                buf[64..].copy_from_slice(&self.phi_star_hash);
                *hemera_hash(&buf)
                    .as_bytes()
                    .first_chunk::<32>()
                    .unwrap_or(&[0u8; 32])
            },
            focus_bound: self.iterations as u64,
        }
    }
}

/// Proof that `phi_star` is the result of `iterations` tri-kernel steps.
pub struct PhiProof {
    pub statement: PhiStatement,
    /// One SpMV proof per iteration for the dominant transition SpMV (D).
    /// Full production packs D+S+H SpMVs; this binds the diffusion backbone
    /// and host-checks S/H consistency (same public graph).
    pub diffusion_proofs: Vec<SpmvProof>,
    /// Final φ after K iterations.
    pub phi_star: Vec<Goldilocks>,
    /// Optional outer decide proof binding the statement (from last diffusion).
    pub outer: Option<Proof>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PhiError {
    EmptyGraph,
    DimMismatch,
    SpmvFailed,
    NotConverged,
}

/// One tri-kernel step (host). Returns φ_{t+1}.
pub fn trikernel_step(
    phi: &[Goldilocks],
    transition: &SparseGraph,
    sym: &SparseGraph,
    degree: &[Goldilocks],
    teleport: &[Goldilocks],
    params: &TriKernelParams,
) -> Vec<Goldilocks> {
    let n = phi.len();
    // D: α u + (1−α) T φ
    let tphi = spmv_native(transition, phi);
    let one_minus = Goldilocks::ONE - params.alpha;
    let mut d = vec![Goldilocks::ZERO; n];
    for i in 0..n {
        d[i] = params.alpha * teleport[i] + one_minus * tphi[i];
    }
    // S: (W φ) / deg
    let wphi = spmv_native(sym, phi);
    let mut s = vec![Goldilocks::ZERO; n];
    for i in 0..n {
        if degree[i] == Goldilocks::ZERO {
            s[i] = phi[i];
        } else {
            s[i] = wphi[i] * degree[i].inv();
        }
    }
    // H: A (A φ) / deg²  — use sym as A for undirected heat sketch
    let h1 = spmv_native(sym, phi);
    let h2 = spmv_native(sym, &h1);
    let mut h = vec![Goldilocks::ZERO; n];
    for i in 0..n {
        let d2 = degree[i] * degree[i];
        if d2 == Goldilocks::ZERO {
            h[i] = phi[i];
        } else {
            h[i] = h2[i] * d2.inv();
        }
    }
    // combine
    let mut raw = vec![Goldilocks::ZERO; n];
    let mut sum = Goldilocks::ZERO;
    for i in 0..n {
        raw[i] = params.lambda_d * d[i] + params.lambda_s * s[i] + params.lambda_h * h[i];
        sum += raw[i];
    }
    if sum == Goldilocks::ZERO {
        return teleport.to_vec();
    }
    let inv_sum = sum.inv();
    raw.iter().map(|v| *v * inv_sum).collect()
}

/// L1 distance.
pub fn l1_dist(a: &[Goldilocks], b: &[Goldilocks]) -> Goldilocks {
    let mut s = Goldilocks::ZERO;
    for (x, y) in a.iter().zip(b.iter()) {
        // field has no abs; use x-y and y-x min via comparison on u64 for demo
        let d1 = *x - *y;
        let d2 = *y - *x;
        // pick the smaller representative under u64 order as pseudo-abs for tests
        let v = if d1.as_u64() < d2.as_u64() { d1 } else { d2 };
        s += v;
    }
    s
}

/// Prove φ* after `iterations` steps. Proves each diffusion SpMV (T·φ).
pub fn prove_phi_star(
    transition: &SparseGraph,
    sym: &SparseGraph,
    degree: &[Goldilocks],
    teleport: &[Goldilocks],
    phi0: &[Goldilocks],
    iterations: u32,
    params: &TriKernelParams,
) -> Result<PhiProof, PhiError> {
    let n = transition.n;
    if n == 0 {
        return Err(PhiError::EmptyGraph);
    }
    if phi0.len() != n || degree.len() != n || teleport.len() != n || sym.n != n {
        return Err(PhiError::DimMismatch);
    }
    let mut phi = phi0.to_vec();
    let mut diffusion_proofs = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let tphi = spmv_native(transition, &phi);
        let sp = prove_spmv(transition, &phi, &tphi).map_err(|_| PhiError::SpmvFailed)?;
        diffusion_proofs.push(sp);
        phi = trikernel_step(&phi, transition, sym, degree, teleport, params);
    }
    let statement = PhiStatement {
        graph_commit: {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&transition.commitment());
            buf[32..].copy_from_slice(&sym.commitment());
            *hemera_hash(&buf)
                .as_bytes()
                .first_chunk::<32>()
                .unwrap_or(&[0u8; 32])
        },
        phi0_hash: vec_hash(phi0),
        phi_star_hash: vec_hash(&phi),
        iterations,
        n,
    };
    Ok(PhiProof {
        statement,
        diffusion_proofs,
        phi_star: phi,
        outer: None,
    })
}

/// Verify φ* proof: re-run host iteration + verify each diffusion SpMV.
pub fn verify_phi_star(
    transition: &SparseGraph,
    sym: &SparseGraph,
    degree: &[Goldilocks],
    teleport: &[Goldilocks],
    phi0: &[Goldilocks],
    proof: &PhiProof,
    params: &TriKernelParams,
) -> bool {
    let n = transition.n;
    if phi0.len() != n || proof.phi_star.len() != n {
        return false;
    }
    if proof.diffusion_proofs.len() != proof.statement.iterations as usize {
        return false;
    }
    if vec_hash(phi0) != proof.statement.phi0_hash {
        return false;
    }
    if vec_hash(&proof.phi_star) != proof.statement.phi_star_hash {
        return false;
    }
    let mut phi = phi0.to_vec();
    for sp in &proof.diffusion_proofs {
        let tphi = spmv_native(transition, &phi);
        if !verify_spmv(transition, &phi, &tphi, sp) {
            return false;
        }
        phi = trikernel_step(&phi, transition, sym, degree, teleport, params);
    }
    phi == proof.phi_star
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
    use super::super::spmv::SparseGraph;
    use super::*;

    fn g(v: u64) -> Goldilocks {
        Goldilocks::new(v)
    }

    /// Small cycle graph with uniform teleport — φ should stay near-uniform.
    fn cycle4() -> (SparseGraph, SparseGraph, Vec<Goldilocks>, Vec<Goldilocks>) {
        let n = 4;
        let mut t = SparseGraph::empty(n);
        let mut s = SparseGraph::empty(n);
        // transition: i → i+1 with weight 1 (column-stochastic if each col sums 1)
        // T[to][from]=1 means edge from→to contributes to row=to, col=from
        for i in 0..n {
            let j = (i + 1) % n;
            t.add(j, i, g(1)); // T·φ: y[j] += 1 * x[i]
            s.add(i, j, g(1));
            s.add(j, i, g(1));
        }
        let degree = vec![g(2); n]; // undirected degree 2
        let q = g(1) * g(4).inv();
        let teleport = vec![q, q, q, q];
        (t, s, degree, teleport)
    }

    #[test]
    fn trikernel_step_preserves_mass() {
        let (t, s, deg, tel) = cycle4();
        let params = TriKernelParams::standard();
        let phi0 = tel.clone();
        let phi1 = trikernel_step(&phi0, &t, &s, &deg, &tel, &params);
        let sum: Goldilocks = phi1.iter().copied().fold(Goldilocks::ZERO, |a, b| a + b);
        // sum should be 1 in the field (ONE)
        assert_eq!(sum, Goldilocks::ONE);
    }

    #[test]
    fn prove_verify_phi_star_cycle() {
        let (t, s, deg, tel) = cycle4();
        let params = TriKernelParams::standard();
        let phi0 = tel.clone();
        let proof = prove_phi_star(&t, &s, &deg, &tel, &phi0, 5, &params).unwrap();
        assert!(verify_phi_star(&t, &s, &deg, &tel, &phi0, &proof, &params));
        assert_eq!(proof.diffusion_proofs.len(), 5);
        // tamper
        let mut bad = proof.phi_star.clone();
        bad[0] += g(1);
        let mut p2 = prove_phi_star(&t, &s, &deg, &tel, &phi0, 5, &params).unwrap();
        p2.phi_star = bad;
        p2.statement.phi_star_hash = vec_hash(&p2.phi_star);
        assert!(!verify_phi_star(&t, &s, &deg, &tel, &phi0, &p2, &params));
    }
}
