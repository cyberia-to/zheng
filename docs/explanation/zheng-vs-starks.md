---
alias: zheng vs starks
title: "zheng proofs and STARKs"
tags: computer science, cryptography
crystal-type: article
crystal-domain: computer science
authors: [cyber]
date: 2026-03-23
status: draft
---

# zheng proofs and STARKs

this page compares [[zheng]] proofs with [[STARKs]] as they stand after the [[soft3/proposals/proof-system-repair|proof-system repair]] (2026-10). an earlier version of this page described a design — expander-code commitments without Merkle trees, homomorphic folding over a hash, a tiny constant checkpoint — that was unsound and never shipped; its retirement is recorded in [[zheng/docs/explanation/recursive-brakedown|recursive-brakedown]] and in the proposal's §2.

zheng is not a STARK. it shares the STARK family's trust model — transparent, hash-only, post-quantum — and differs in arithmetization, IOP and commitment.

## 1. what the two have in common

- one cryptographic assumption: a hash function behaving as a random oracle. no trusted setup, no pairings, no discrete logarithm, so nothing a quantum computer breaks beyond the generic Grover/BHT speed-ups.
- Reed–Solomon codes over a 64-bit-friendly prime field, committed with Merkle trees of the hash, opened by proximity tests whose soundness is proven up to the Johnson bound.
- Fiat–Shamir with the same hash as the transcript.
- proofs grow with the number of queries times the depth of the Merkle paths: a hash-only proof cannot be smaller than the authentication of its own queries. both families live in the tens of kilobytes and up.

in zheng every one of these parts is single: one field (Goldilocks, [[nebu]], with its cubic extension Fp3 for every challenge and evaluation point), one hash ([[hemera]], Poseidon2 over Goldilocks, for Merkle trees and Fiat–Shamir), one code (Reed–Solomon over Goldilocks).

## 2. where they differ

| | typical STARK (Stwo, Plonky3, RISC Zero, Triton) | zheng proofs |
|---|---|---|
| arithmetization | AIR: transition constraints over a trace, univariate polynomials over a multiplicative subgroup | [[CCS]] of any degree, compiled by the verifier from the nox program; multilinear polynomials over the Boolean hypercube |
| IOP | quotient polynomial + DEEP-ALI | Spartan (SuperSpartan): an outer sumcheck of the CCS degree and an inner sumcheck batching the matrix evaluations |
| commitment / proximity | FRI (some systems: STIR, WHIR) | one multilinear opening by WHIR (rate 1/64, folding factor 4, 24 grinding bits) — the winner of the phase-2 bake-off; a Reed–Solomon tensor code with Ligero geometry (TensorRs) was the loser |
| what is committed | the whole trace and the quotient | the witness `w` only; the verifier derives the relation and the public prefix `(1 ‖ io ‖ cycles)` itself |
| challenges | extension field of the base field | Fp3 (`p³ ≈ 2^192`) |
| zero knowledge | trace randomisation | profile "veil": Libra-masked sumchecks + one hiding Ligero-style RS tensor commitment |

the multilinear/sumcheck route lets the prover work without FFTs over the trace in the IOP, and lets one IOP serve constraints of any degree. it does not by itself make proofs smaller: the commitment dominates the size in both families.

## 3. the profiles

zheng carries every proof in one envelope, `ZHENGPF1` (magic · version · profile byte · canonical body):

- public (profile 0) and state-public (profile 3): the witness is disclosed and the verifier checks every CCS row exactly. soundness error 0 for the compiled relation, linear size, not succinct. a STARK has no counterpart; it is the fallback that is sound without any proximity argument.
- succinct (profile 1): the witness is committed; Spartan over Fp3 plus one WHIR opening. this is the profile comparable to a STARK.
- zk (profile 2, "veil"): succinct with masking; honest-verifier statistical zero knowledge, zero knowledge in the random-oracle model after Fiat–Shamir.

soundness of every component is in [[zheng/specs/soundness|the soundness ledger]].

## 4. measured figures

Apple M4 Max, shared machine, `zheng/audit/succinct-profile-2026-10.md` and `zheng/audit/zk-profile-2026-10.md`:

| statement | profile | proof | verify | proven bits |
|---|---|---|---|---|
| `add.tri` | public v3 | 185 B envelope | — | error 0 |
| `hash.tri` (one hemera hash) | public v3 | 6,463 B envelope | — | error 0 |
| `hash.tri` | succinct, WHIR | 15,921 B proof / 16,148 B envelope | 7.96 ms | 128 |
| synthetic relation, 2^20 rows | succinct, WHIR | 71,081 B | 270 ms | 128 |
| hash of a secret preimage | zk (veil) | 63.9 KB | 10.0 ms (4.1 ms with a cached verifying key) | 128.2 |

for scale, production STARK chains publish proofs of roughly 150 KB to 1 MB (proposal §1). the hash-only WHIR literature reports 56–87 KiB at `2^20` at rate 1/16.

the goal of the repair: any nox computation → a proof ≤ 64 KB, post-quantum, verify ≤ 1 ms, constant in the number of steps; small statements ≤ 16–20 KB. today the 2^20 relation misses the size goal by 11 %, and verification misses the 1 ms goal at every size — the causes are hemera's speed inside the opening, an unstructured Spartan verifier, and recompiling the relation (a cached verifying key removes the last).

## 5. long computations

a STARK proves a long computation as one long trace, or recursively by verifying proofs inside proofs. zheng's plan (phase 3, in progress, no numbers yet) is hash-based accumulation of Reed–Solomon evaluation claims, ARC/WARP-style: the nox machine becomes one uniform step relation; each step batches its claims with a sumcheck, commits one combined word, samples out-of-domain points and opens a few positions; the accumulator is one root plus a fixed number of claims, independent of the number of steps; the decider is one WHIR opening of the final accumulator. decider proof: ≤ 64 KB goal, decider 44–93 KB measured (one WHIR opening of an Fp3 word, ℓ = 14…21; `audit/accumulation-2026-10.md`); measured: the decider is 44–93 KB, but without recursion the whole proof grows with the steps — 83 KB (33 cycles), 146 KB (merkle-32), 384 KB (16,383 cycles, 3 segments), ~96 KB per 2^14-row segment (`audit/accumulation-2026-10.md`).

this replaces the folding of the 0.3/0.4 design, which needs a homomorphic commitment; hemera is a hash, so the stack never had it soundly. recursion proper — a zheng verifier written as a nox program — is kept for composition (across domains, across versions), never for size: in a hash-only world the outer proof carries its own Merkle paths again.

a light-client checkpoint is a state root plus the decider proof of the accumulator: ≤ 64 KB goal; decider 44–93 KB measured (one WHIR opening of an Fp3 word, ℓ = 14…21; `audit/accumulation-2026-10.md`).

## 6. honest assessment

- zheng's succinct and zk profiles are new code with weeks of review, not years of production; STARK provers have years.
- the relation compiler (program → CCS) is tested against native nox but not proven; it is a conjectured row of the soundness ledger.
- hemera's 32-byte digest gives 128-bit classical and about 85-bit quantum collision resistance; longer identity digests are proposed as hemera profile v2. Merkle nodes inside proofs stay 32 bytes.
- the 1 ms verification goal is not met yet.

## references

[1] S. Setty, "SuperSpartan: Doubly-efficient SNARKs without preprocessing," Crypto 2023.
[2] G. Arnon, A. Chiesa, G. Fenzi, E. Yogev, "WHIR: Reed–Solomon Proximity Testing with Super-Fast Verification," eprint 2024/1586.
[3] ARC, accumulation for Reed–Solomon codes, eprint 2024/1731.
[4] WARP, eprint 2025/753.
[5] E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev, "Scalable, transparent, and post-quantum secure computational integrity," eprint 2018/046.
[6] S. Ames, C. Hazay, Y. Ishai, M. Venkitasubramaniam, "Ligero," CCS 2017.
[7] T. Xie et al., "Libra," CRYPTO 2019, eprint 2019/317.
[8] L. Grassi et al., "Poseidon2: A Faster Version of the Poseidon Hash Function," 2023.
