---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: Fiat-Shamir transcript, proof transcript
diffusion: 0.00010722364868599256
springs: 0.00041965751464741007
heat: 0.0003266304655997323
focus: 0.0002448351718571626
gravity: 0
density: 0.46
---
# transcript

the Fiat-Shamir transcript converts [[zheng]]'s interactive proof into a non-interactive one. the prover maintains a running [[hemera]] hash of every message exchanged. each verifier challenge is derived by hashing the transcript so far. the verifier recomputes the same transcript and checks consistency.

~3 hemera calls total per proof: (1) domain separation initialization, (2) Fiat-Shamir seed from commitment, (3) Brakedown binding hash. remaining challenges use the algebraic Fiat-Shamir path — field arithmetic derived from the sponge state without additional hash invocations.

## construction

```
transcript state: H = hemera_init(DOMAIN_SEP)

DOMAIN_SEP = hemera(0x01 | "zheng-transcript-v1")

absorb(message):
  H = hemera_absorb(H, message)

squeeze(n_challenges):
  challenges = hemera_squeeze(H, n_challenges)
  H = hemera_absorb(H, challenges)
  return challenges
```

the transcript is a sponge: absorb prover messages, squeeze verifier challenges. [[hemera]]'s sponge construction (Poseidon2 with 512-bit state, 256-bit capacity) provides 128-bit security against transcript manipulation.

## domain separation

each proof phase uses a distinct domain separator to prevent cross-phase attacks:

| phase | separator | purpose |
|---|---|---|
| commitment | `0x02 \| "commit"` | binds Brakedown commitment to transcript |
| sumcheck round i | `0x03 \| i` | each round gets a unique challenge domain |
| evaluation | `0x04 \| "eval"` | separates evaluation point from constraint checks |
| PCS opening | `0x05 \| "pcs-open"` | prevents reuse of sumcheck challenges in PCS |
| recursive | `0x06 \| "recurse"` | inner proof transcripts isolated from outer |

domain separators are absorbed before the corresponding message. this ensures that identical messages in different phases produce different challenges.

## transcript format

a serialized proof contains the full sequence of prover messages. the verifier reconstructs the transcript by absorbing each message in order and checking that derived challenges match.

```
proof = [
  commitment: [u8; 64],           // Brakedown commitment (hemera digest)
  sumcheck_polynomials: [         // one per round
    [GoldilocksElement; deg+1],   // coefficients of univariate g_i
  ],
  evaluation_value: GoldilocksElement,  // f(r) at sumcheck output point
  pcs_opening: BrakedownProof,    // recursive Brakedown opening proof
]
```

the verifier processes this sequentially: absorb commitment -> squeeze sumcheck challenges -> absorb each sumcheck polynomial -> squeeze next challenge -> ... -> absorb evaluation -> verify Brakedown opening.

## binary encoding

all multi-byte integers are little-endian. all field elements are in canonical form (value < p where p = 2^64 - 2^32 + 1).

### GoldilocksElement

8 bytes. the canonical u64 representation in little-endian byte order. the value must satisfy 0 <= v < p. any encoding with v >= p is rejected by the verifier.

```
GoldilocksElement := u64_le(v)    // 8 bytes, v < 2^64 - 2^32 + 1
```

### commitment

64 bytes. a [[hemera]] digest consists of 8 GoldilocksElements concatenated in order, each encoded as 8 bytes LE.

```
Commitment := GoldilocksElement[0] || GoldilocksElement[1] || ... || GoldilocksElement[7]
           // 8 * 8 = 64 bytes
```

### sumcheck polynomial (per round)

each round emits one univariate polynomial g_i of degree d. the encoding is:

```
SumcheckPoly :=
  degree: u8                          // 1 byte, value d
  coefficients: GoldilocksElement[d+1] // (d+1) * 8 bytes
```

coefficients are in ascending order: [c_0, c_1, ..., c_d] where g_i(X) = c_0 + c_1*X + c_2*X^2 + ... + c_d*X^d. each coefficient is an 8-byte LE u64 in canonical form.

total per round: 1 + 8*(d+1) bytes.

### evaluation value

8 bytes. a single GoldilocksElement encoding f(r) at the sumcheck output point.

```
EvaluationValue := GoldilocksElement    // 8 bytes LE
```

### BrakedownProof

the Brakedown opening proof encodes recursive tensor reductions:

```
BrakedownProof :=
  num_levels: u8                        // log log N recursion levels
  for each level:
    commitment: Commitment              // 64 bytes (Brakedown commitment of opening vector)
    tensor_response: [GoldilocksElement] // tensor reduction at this level
  final_elements: [GoldilocksElement; lambda]  // <= lambda direct field elements
```

the number of recursion levels and tensor dimensions are determined by the Brakedown parameters. the verifier knows these from the public configuration.

### full proof wire format

```
Proof :=
  commitment: Commitment               // 64 bytes
  num_rounds: u16_le                   // 2 bytes
  sumcheck_polys: SumcheckPoly[num_rounds]
  evaluation: EvaluationValue          // 8 bytes
  pcs_proof: BrakedownProof
```

the prover writes fields in this exact order. the verifier reads them sequentially, absorbing each into the Fiat-Shamir transcript as it goes.

### proof size

for N = 2^20 (typical nox trace), 128-bit security:
- commitment: 64 bytes
- num_rounds: 2 bytes
- sumcheck_polys: ~660 bytes (20 rounds * ~33 bytes each)
- evaluation: 8 bytes
- pcs_proof: ~1,300 bytes (log log N levels of recursive tensor openings + lambda final elements)
- **total: ~2 KiB**

proof size is constant regardless of original computation size.

## properties

| property | value |
|---|---|
| hash function | [[hemera]] (Poseidon2 over [[Goldilocks field]]) |
| hemera calls | ~3 per proof |
| state size | 512 bits (8 field elements) |
| capacity | 256 bits (4 field elements) |
| security | 128-bit classical, 85+ bit post-quantum |
| challenge type | native [[Goldilocks field]] elements (no truncation) |
| domain separation | per-phase prefix absorb |

## soundness

if hemera behaves as a random oracle, the Fiat-Shamir transcript is as sound as the interactive protocol. the soundness error per [[sumcheck]] round is at most d/p, where d is the polynomial degree and p = 2^64 - 2^32 + 1. across k rounds, total soundness error <= kd/p — negligible for any practical parameters.

the critical property: challenges are native [[Goldilocks field]] elements. no reduction, no truncation, no modular bias. hemera outputs field elements directly.

see [[sumcheck]] for the protocol that generates transcript messages, [[Brakedown]] for the PCS opening proof format, [[hemera]] for the hash construction
