---
tags: zheng, specs, phi, spmv, tri-kernel
crystal-type: spec
crystal-domain: comp
status: draft
---

# φ* SpMV circuit (zheng)

implements the algebraic core of foculus [[provable consensus]]: sparse
matrix-vector multiply as multi-row CCS, then tri-kernel iteration proven
by folding diffusion SpMVs.

## layout

```
zheng/rs/src/phi/
  mod.rs
  spmv.rs        SparseGraph, spmv_ccs, prove_spmv, verify_spmv
  trikernel.rs   trikernel_step, prove_phi_star, verify_phi_star
```

## SpMV CCS

public: edges `(row, col, w)` meaning `y[row] += w · x[col]`  
witness: `z = [x ‖ y]`  
constraint row `r`:

```
(Σ_j A[r,j] · x[j]) − y[r] = 0
```

single matrix `M`, multiset `{0}`, coeff `1` → `M·z = 0`.  
`num_rows` / `num_cols` padded to powers of two for SuperSpartan outer sumcheck.

prove: fold one CCS instance → decide → `Proof`.  
verify: re-check host SpMV, CCS satisfaction, SuperSpartan transcript.

## tri-kernel step (host + diffusion proofs)

```
D:  d = α·u + (1−α)·T·φ
S:  s = (W_sym · φ) ./ deg
H:  h = (W_sym · (W_sym · φ)) ./ deg²
φ' = normalize(λd·d + λs·s + λh·h)
```

defaults: λd=1/2, λs=3/10, λh=1/5, α=15/100 (field inv).

`prove_phi_star` issues one `prove_spmv` per iteration for the diffusion
backbone `T·φ`. host recomputes S/H on the same public graphs; verifier
re-runs the step and checks each diffusion proof.

## domain localization

intended prove size is the ε-support domain (foculus finality), not planetary
`N`. full-graph 1.4B constraint estimates in provable-consensus.md are this
module at scale (same SpMV CCS, larger n, more iterations, GPU prover).

## API

```rust
use zheng::{prove_spmv, verify_spmv, SparseGraph};
use zheng::{prove_phi_star, verify_phi_star, TriKernelParams};

let proof = prove_spmv(&graph, &x, &y)?;
assert!(verify_spmv(&graph, &x, &y, &proof));

let phi = prove_phi_star(&t, &sym, &deg, &tel, &phi0, k, &params)?;
assert!(verify_phi_star(&t, &sym, &deg, &tel, &phi0, &phi, &params));
```

## next

- prove S and H SpMVs per iteration (not only D)
- algebraic PCS opens of edges from BBG (section 1 of circuit)
- bind φ* into foculus `FinalityEvidence::issue_from_domain`
- GPU prover path for large n

---

discover all [[concepts]]
