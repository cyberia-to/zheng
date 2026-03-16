---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: Fiat-Shamir transcript, proof transcript
---
# transcript

the Fiat-Shamir transcript converts [[zheng]]'s interactive proof into a non-interactive one. the prover maintains a running [[hemera]] hash of every message exchanged. each verifier challenge is derived by hashing the transcript so far. the verifier recomputes the same transcript and checks consistency.

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
| commitment | `0x02 \| "commit"` | binds WHIR commitment to transcript |
| sumcheck round i | `0x03 \| i` | each round gets a unique challenge domain |
| evaluation | `0x04 \| "eval"` | separates evaluation point from constraint checks |
| WHIR opening | `0x05 \| "whir-open"` | prevents reuse of sumcheck challenges in PCS |
| recursive | `0x06 \| "recurse"` | inner proof transcripts isolated from outer |

domain separators are absorbed before the corresponding message. this ensures that identical messages in different phases produce different challenges.

## transcript format

a serialized proof contains the full sequence of prover messages. the verifier reconstructs the transcript by absorbing each message in order and checking that derived challenges match.

```
proof = [
  commitment: [u8; 64],           // WHIR commitment (hemera digest)
  sumcheck_polynomials: [         // one per round
    [GoldilocksElement; deg+1],   // coefficients of univariate gᵢ
  ],
  evaluation_value: GoldilocksElement,  // f(r) at sumcheck output point
  whir_opening: WHIRProof,        // WHIR evaluation proof
]
```

the verifier processes this sequentially: absorb commitment → squeeze sumcheck challenges → absorb each sumcheck polynomial → squeeze next challenge → ... → absorb evaluation → verify WHIR opening.

## properties

| property | value |
|---|---|
| hash function | [[hemera]] (Poseidon2 over [[Goldilocks field]]) |
| state size | 512 bits (8 field elements) |
| capacity | 256 bits (4 field elements) |
| security | 128-bit classical, 85+ bit post-quantum |
| challenge type | native [[Goldilocks field]] elements (no truncation) |
| domain separation | per-phase prefix absorb |

## soundness

if hemera behaves as a random oracle, the Fiat-Shamir transcript is as sound as the interactive protocol. the soundness error per [[sumcheck]] round is at most d/p, where d is the polynomial degree and p = 2^64 - 2^32 + 1. across k rounds, total soundness error ≤ kd/p — negligible for any practical parameters.

the critical property: challenges are native [[Goldilocks field]] elements. no reduction, no truncation, no modular bias. hemera outputs field elements directly.

see [[sumcheck]] for the protocol that generates transcript messages, [[WHIR]] for the opening proof format, [[hemera]] for the hash construction
