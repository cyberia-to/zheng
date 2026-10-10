---
tags: computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: Fiat-Shamir transcript, proof transcript
---
# transcript

the Fiat–Shamir transcript converts [[zheng]]'s interactive protocols into non-interactive ones. the prover absorbs every message into a running [[hemera]] sponge; each verifier challenge is squeezed from the transcript so far; the verifier replays the same absorbs and squeezes. hemera is modelled as a random oracle — that assumption, and the hash's own bits, are rows of the [[soundness]] ledger.

hemera is called throughout: once per absorb/squeeze and once per Merkle node the PCS opening authenticates. there is no "algebraic" shortcut that derives challenges without hashing; every challenge comes out of the sponge.

## construction

```
transcript state: H = hemera_init(); absorb("\x01zheng-transcript-v1")

absorb(message):
  H = hemera_absorb(H, message)

squeeze (wide rule, Transcript::new):
  absorb("\x09squeeze-wide" ‖ n_limbs)
  xof = hemera_finalize_xof(H)
  chain = xof[0..32];  H = hemera_init(); absorb(chain)       // re-seed, chain forward
  limb_j = (24 XOF bytes as a 192-bit integer) mod p           // one per output limb
```

`squeeze_challenge` returns one Goldilocks limb; `squeeze_fp3` returns three limbs as an element of Fp3 = F_p[t]/(t³ − t − 1). each limb is within `p / 2^192 < 2^-128` of uniform (exactly uniform for hemera's canonical-limb output). every production profile — succinct, zk (veil) — draws its challenges with `squeeze_fp3`: the challenge set has `p³ ≈ 2^192` elements.

`Transcript::new_v1` reproduces the 0.4.0 rule (the first 8 bytes of one 32-byte squeeze, Goldilocks challenges) only to read retired artifacts (public v2, state v1) and the legacy path for one release. Goldilocks challenges give `≈ 2^-56` sumcheck soundness at 2^20 — too small for any 128-bit claim, which is why the production profiles use Fp3.

## domain separation

| phase | separator | purpose |
|---|---|---|
| init | `0x01 \| "zheng-transcript-v1"` | transcript identity |
| commitment | `0x02 \| "commit"` | binds the PCS root (a hemera Merkle root) |
| sumcheck round i | `0x03 \| i` | each round gets a unique challenge domain |
| evaluation | `0x04 \| "eval"` | separates evaluation claims from round messages |
| PCS opening | `0x05 \| "pcs-open"` | prevents reuse of sumcheck challenges in the PCS |
| wide squeeze | `0x09 \| "squeeze-wide"` | the wide challenge rule |
| legacy only | `0x06` recurse, `0x07` statement, `0x08` linkage | the legacy folded trace API (feature `legacy`) |

each protocol also absorbs its own label first (`"zheng-succinct-v1"`, `"zheng-veil-v1"`), then `"zheng-vk" ‖ digest` of the verifying key and the statement bytes, so a proof is bound to its relation and statement ([[execution]]). the PCS opening runs on a separate lens transcript seeded by one 32-byte squeeze of the zheng transcript.

## encoding of absorbed values

all integers little-endian; all field elements canonical (`v < p`, `p = 2^64 − 2^32 + 1`), rejected otherwise.

```
Goldilocks := u64_le(v)                       // 8 bytes
Fp3        := Goldilocks[3]                   // 24 bytes, c0 ‖ c1 ‖ c2
Commitment := Goldilocks[4]                   // 32-byte hemera digest
SumcheckPoly (absorbed) := 0x03 ‖ round u64 ‖ degree u8 ‖ coefficients (8 or 24 bytes each)
```

round polynomials travel without their linear coefficient; the verifier restores `c_1 = claim − 2c_0 − Σ_{i≥2} c_i` before absorbing, so prover and verifier absorb the same polynomial. the wire bodies of each profile (succinct, veil, the certificates) are specified in [[execution]] and travel in the `ZHENGPF1` envelope.

## properties

| property | value |
|---|---|
| hash function | [[hemera]] (Poseidon2 over [[Goldilocks field]]), random-oracle model |
| challenge field | Fp3 (production profiles); Goldilocks for retired artifacts only |
| challenge bias | `< 2^-128` per limb (wide rule) |
| digest | 32 bytes (4 limbs): 2^128 classical collision (birthday on p²), ~2^85 quantum (BHT) |
| domain separation | per-phase prefix absorb |

the digest row is why hemera profile v2 (hemera#15) proposes longer identity digests; in-proof Merkle nodes stay 32 bytes.

## soundness

in the random-oracle model, a protocol that is round-by-round sound with per-round error `ε_r` stays sound after Fiat–Shamir: a prover making `Q` hemera queries succeeds with probability at most `Q · ε_r` plus hemera collisions (Canetti et al. 2019). for a sumcheck round of degree `d` over Fp3, `ε_r = d / p³`; the succinct and zk profiles keep every round, PCS grinding included, at or below `2^-128`. the composed bounds — 128.0 bits for succinct (set by the WHIR opening), 128.2 for veil — are derived in the [[soundness]] ledger, not here.

see [[sumcheck]] for the protocol that generates transcript messages, [[execution]] for each profile's transcript order, [[hemera]] for the hash construction.
