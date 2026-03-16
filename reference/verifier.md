---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: zheng verifier, stark verifier
---
# verifier

the standalone verifier algorithm for [[zheng]]. accepts a proof and a public statement, returns accept or reject. the verifier is a [[nox]] program — it runs inside the same VM that produced the original trace, enabling recursive proof composition.

## algorithm

```
VERIFY(commitment C, statement S, proof π) → accept/reject:

  1. INIT TRANSCRIPT
     T = transcript_init(DOMAIN_SEP)
     T.absorb(S)
     T.absorb(C)

  2. SUMCHECK VERIFICATION (k rounds, k = n + 4)
     claim₀ = 0  (constraints must sum to zero)
     for i in 1..k:
       gᵢ = π.sumcheck_polynomials[i]
       assert gᵢ(0) + gᵢ(1) = claim_{i-1}
       T.absorb(gᵢ)
       rᵢ = T.squeeze()
       claimᵢ = gᵢ(rᵢ)

  3. EVALUATION CHECK
     r = (r₁, ..., r_k)
     v = π.evaluation_value
     assert claimₖ = constraint_eval(v, r, S)

  4. WHIR VERIFICATION
     assert WHIR_verify(C, r, v, π.whir_opening)

  return accept
```

step 2 is pure field arithmetic. step 4 is hash operations (Merkle path verification). the split determines the cost structure.

## cost breakdown

| component | without jets | with jets | reduction |
|---|---|---|---|
| parse proof | ~1,000 | ~1,000 | 1× |
| Fiat-Shamir challenges | ~30,000 | ~5,000 | 6× |
| Merkle verification | ~500,000 | ~50,000 | 10× |
| constraint evaluation | ~10,000 | ~3,000 | 3× |
| WHIR verification | ~50,000 | ~10,000 | 5× |
| total | ~600,000 | ~70,000 | 8.5× |

Merkle verification dominates without jets (83%). the merkle_verify jet reduces it 10×. this single jet makes recursion practical.

## nox pattern decomposition

every verifier operation maps to native [[nox]] patterns:

| verifier operation | nox patterns | why native |
|---|---|---|
| field arithmetic | 5 (add), 6 (sub), 7 (mul), 8 (inv) | [[Goldilocks field]] is the native field |
| hash computation | 15 (hash) / hash jet | [[hemera]] is the nox hash |
| [[sumcheck]] verification | 5, 7, 9 | pure field arithmetic |
| [[WHIR]] opening verification | 15, 4, poly_eval/merkle_verify/fri_fold jets | Merkle paths + polynomial eval |

no external primitive enters the verification loop. the verifier is closed under the nox instruction set. consequence: verify(proof) can itself be proven, and verify(verify(proof)) too, to arbitrary depth.

## input/output format

```
INPUTS (public):
  commitment:  [u8; 64]              // hemera digest
  statement:   Statement {
    program_hash: [u8; 64],           // hash of the nox program
    input_hash:   [u8; 64],           // hash of public inputs
    output_hash:  [u8; 64],           // hash of public outputs
    focus_bound:  u64,                // maximum focus consumed
  }

PROOF:
  sumcheck_polynomials: Vec<Vec<GoldilocksElement>>,
  evaluation_value:     GoldilocksElement,
  whir_opening:         WHIRProof,

OUTPUT:
  accept / reject
```

## verification time

| security level | verification time | operations |
|---|---|---|
| 100-bit | ~290 μs | ~1,800 hemera hashes + field ops |
| 128-bit | ~1.0 ms | ~2,700 hemera hashes + field ops |

verification time is independent of the original computation size. a proof of a 300-constraint identity check and a proof of a million-constraint neural network inference verify in the same time.

## recursive verification

when the verifier runs as a nox program, its execution trace can be proven by zheng. the recursive proof attests that a previous proof was valid.

```
proof_A = zheng.prove(computation)         // ~|C| constraints
proof_B = zheng.prove(zheng.verify(proof_A))  // ~70K constraints (with jets)
proof_C = zheng.prove(zheng.verify(proof_B))  // ~70K constraints (with jets)
```

each recursion level costs exactly ~70,000 constraints with jets, regardless of the original computation size. proof size remains constant: ~60-157 KiB.

see [[transcript]] for Fiat-Shamir construction, [[sumcheck]] for the core protocol, [[WHIR]] for the opening verification, [[constraints]] for the AIR format, [[nox]] for the VM
