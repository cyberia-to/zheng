---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: Weights Help Improving Rate
---
# WHIR

WHIR (Weights Help Improving Rate) is the polynomial commitment of zheng's succinct profile (envelope profile 1): the winner of the phase-2 bake-off of the [[soft3/proposals/proof-system-repair|proof-system repair]] for both size classes, shipped at rate 1/64 (parameters below). it is also the decider of the machine profile and, run field-natively, the opening inside the recursion circuit (profiles 4–6). it was zheng's first lens; the expander-code commitment that briefly replaced it is retired as unsound ([[zheng/docs/explanation/recursive-brakedown|recursive-brakedown]]). the implementation lives in [[lens]] (`Whir`, PCS id 1; contract `lens/specs/whir.md`).

Weights Help Improving Rate. an interactive oracle proof of proximity for constrained Reed-Solomon codes that simultaneously serves as a multilinear polynomial commitment scheme. Arnon, Chiesa, Fenzi, Yogev (EUROCRYPT 2025). ePrint 2024/1586.

## protocol

WHIR provides three operations:

```
WHIR_commit(f) → C
  input:  multilinear polynomial f(x₁, ..., x_k) over Goldilocks
  output: commitment C (hemera Merkle root over evaluation table)
  cost:   O(2^k log 2^k) hemera hashes

WHIR_open(f, r) → (v, π)
  input:  polynomial f, evaluation point r ∈ Fp3^k (zheng draws evaluation points in the cubic extension)
  output: value v = f(r), proximity proof π
  cost:   O(2^k) field ops + O(log² 2^k) hemera hashes

WHIR_verify(C, r, v, π) → accept/reject
  input:  commitment C, point r, claimed value v, proof π
  output: accept if f(r) = v and f is close to a degree-bounded polynomial
  cost:   O(log² 2^k) hemera hashes + field ops
```

## verification algorithm

```
WHIR_verify(C, r, v, proof):
  1. init transcript T from C
  2. for each folding round i = 1..log(N):
     a. absorb prover's round message into T
     b. squeeze challenge αᵢ from T
     c. verify Merkle paths for queried positions against round commitment
     d. fold polynomial: combine evaluations using αᵢ as weight
     e. check consistency: folded values match next round's commitment
  3. verify final polynomial is constant (degree 0)
  4. check that the accumulated evaluation equals v at point r
```

the folding formula per round: given evaluations f(x) on the current domain and challenge α, split into even and odd parts:

```
f_folded(x) = (f(x) + f(-x)) / 2 + α × (f(x) - f(-x)) / (2x)
```

this halves the number of evaluation points each round. the even part `(f(x) + f(-x))/2` extracts the symmetric component; the odd part `(f(x) - f(-x))/(2x)` extracts the antisymmetric component. the challenge α linearly combines them into a single folded polynomial of half the degree.

for multilinear polynomials: folding over variable x_j with challenge r_j gives:

```
f'(x_1, ..., x_{j-1}, x_{j+1}, ..., x_k) = f(..., x_j=0) × (1 - r_j) + f(..., x_j=1) × r_j
```

each round eliminates one variable, reducing a k-variate multilinear polynomial to a (k-1)-variate one.

## Reed-Solomon domain

the evaluation domain is a multiplicative coset of a 2-adic subgroup of the [[Goldilocks field]] (p = 2^64 - 2^32 + 1).

rate ρ is the inverse of the blowup factor. ρ = 1/2 means the evaluation domain is 2× the polynomial degree; ρ = 1/4 means 4×. lower rate increases proof size but improves soundness per query.

in zheng the committed polynomial is the witness `w̃` of the compiled relation, with 2^ℓ evaluations; the Reed–Solomon evaluation domain has size 2^ℓ / ρ. at the shipped ρ = 1/64 that is 2^{ℓ+6}.

domain generator: a primitive 2^k-th root of unity ω in Goldilocks. the Goldilocks field has multiplicative order p - 1 = 2^32 × (2^32 - 1), so primitive 2^k-th roots of unity exist for k up to 32. the subgroup ⟨ω⟩ = {ω^0, ω^1, ..., ω^{2^k - 1}} forms the base domain.

coset shift: multiply the entire subgroup by a fixed non-unity element g ∈ F* to obtain the coset g⟨ω⟩ = {g, gω, gω², ...}. this avoids evaluating at zero and ensures the evaluation domain is disjoint from the polynomial's natural domain.

## proof structure

a WHIRProof contains:

```
WHIRProof {
  rounds: [RoundData; log₂(N) / k]           // k variables folded per round
  final_value: F                          // constant polynomial value after all folds
}

RoundData {
  commitment: hemera Merkle root           // commitment to folded evaluations
  auth_paths: [MerklePath; num_queries]   // authentication paths for queried positions
  leaf_values: [F; num_queries]           // evaluation values at queried positions
}
```

query positions are derived deterministically from the Fiat-Shamir transcript: after absorbing each round commitment, the verifier squeezes query indices from the transcript. this makes the proof non-interactive.

number of queries per round: security_bits / log₂(1/ρ). at 100-bit security with ρ = 1/2: 100 / log₂(2) = 100 queries per round. at ρ = 1/4: 100 / log₂(4) = 50 queries per round. lower rate reduces queries but increases evaluation domain size.

## parameters

the succinct profile's default prover (`succinct::device_params`, lens `WhirConfig`, Johnson-bound decoding); the bake-off set `succinct::params_for` is the same with folding 4 and 24 grinding bits at every size:

| parameter | value |
|---|---|
| rate ρ | 1/64 |
| folding factor k | 4 up to `2^16` committed variables, 5 above |
| grinding | 16 bits up to `2^17`, 22 at `2^18`, 24 beyond — the least that keeps the proof ≤ 64 KB |
| challenge and evaluation field | Fp3 over [[Goldilocks field|Goldilocks]] (p³ ≈ 2^192) |
| hash | [[hemera]] (Poseidon2 over Goldilocks), Merkle trees and Fiat–Shamir |
| proven soundness | ≥ 128 bits, round-by-round, grinding included (the policy rejects any set below 128) |

measured inside the succinct profile (Apple M4 Max, shared machine): with the device parameters, one hemera hash (`hash.tri`, 2^10 committed slots) — 16,756 B, verify under 10 ms; Merkle membership at depth 32 (2^18) — 64,071 B, 310 ms (soft3 `audit/proof-latency-2026-10.md`). with the bake-off parameters, `hash.tri` — 15,921 B, 7.96 ms; a synthetic 2^20-row relation — 71,081 B, 270 ms (`audit/succinct-profile-2026-10.md`). the goal of the repair is ≤ 64 KB and verify ≤ 1 ms; one relation misses 64 KB above 2^18 and every size misses 1 ms. bit-flip scans: 0 accepted.

## performance comparison

published figures from the WHIR paper, eprint 2024/1586 (its own hash and field, not hemera; not zheng measurements). at d = 2²⁴, 128-bit security:

| scheme | argument size | verifier hashes | verification time |
|---|---|---|---|
| FRI | 306 KiB | 5,600 | 3.9 ms |
| STIR | 160 KiB | 2,600 | 3.8 ms |
| WHIR | 157 KiB | 2,700 | 1.0 ms |

## properties

| property | value |
|---|---|
| trusted setup | none (transparent) |
| post-quantum | yes (hash-only security) |
| dual nature | IOPP (proximity test) + multilinear lens |
| field | any with large multiplicative subgroup |
| soundness | mutual correlated agreement |

## WHIR inside a proof

WHIR's verifier is proved today, not planned: the recursion circuit runs a field-native WHIR (`rs/src/recursion/whir/`: a duplex transcript over hemera's permutation, 4-ary field-native Merkle trees, batched openings) as rows of each IVC step and of each wrap level, and the final wrap level's proof is checked natively ([[zheng/specs/recursion|recursion]], `audit/recursion-2026-10.md`). its soundness rows are in [[zheng/specs/soundness|the soundness ledger]] § field-native WHIR.

## design notes (ideas, not built)

### WHIR-compressed Merkle proofs

a binary [[hemera]] Merkle path of depth 20 carries 20 sibling digests, 640 bytes. WHIR alternative: commit each tree level as a multilinear polynomial, open at queried positions.

```
encoding: f_ℓ(b₁, ..., b_ℓ) = hash of node reached by path bits b₁...b_ℓ
crossover: k > ~80 leaves for depth 20 (below this, standard proofs are smaller)
hybrid:    prover selects mode; verifier accepts both via mode flag
```

open questions: evaluation table layout, root finalization domain separation, hybrid mode protocol.

### incremental commitment updates

EdgeSet polynomial commitments face re-commitment cost when edges are added. with a fixed evaluation domain:

```
insert edge k+1:
  1. evaluate P at new point
  2. update one Merkle leaf
  3. rehash path: log₂(D) × 2 permutations

for D = 2^16: 32 permutations per insertion
vs full re-commit: O(N log N) hashes
```

domain sizing strategy: start at 2^10, double when 75% full. amortized O(1) per insertion.

see [[polynomial-commitments]] for the commitment abstraction, [[sumcheck]] for the weight polynomial mechanism, [[verifier]] for the full zheng verification algorithm, [[whirlaway]] for the architecture