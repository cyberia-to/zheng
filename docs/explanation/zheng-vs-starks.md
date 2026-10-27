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
| arithmetization | AIR: transition constraints over a trace, univariate polynomials over a multiplicative subgroup | one statement: [[CCS]] of any degree, compiled by the verifier from the nox program; a run of any length: one uniform AIR for the nox machine; multilinear polynomials over the Boolean hypercube in both |
| IOP | quotient polynomial + DEEP-ALI | sumcheck, no quotient: Spartan (SuperSpartan) for a CCS, a zerocheck for the machine AIR |
| commitment / proximity | FRI (some systems: STIR, WHIR) | one multilinear opening by WHIR (rate 1/64) — the winner of the phase-2 bake-off; a Reed–Solomon tensor code with Ligero geometry (TensorRs) was the loser |
| what is committed | the whole trace and the quotient | the witness `w` only; the verifier derives the relation and the public prefix `(1 ‖ io ‖ cycles)` itself |
| challenges | extension field of the base field | Fp3 (`p³ ≈ 2^192`) |
| zero knowledge | trace randomisation | profile "veil": Libra-masked sumchecks + one hiding Ligero-style RS tensor commitment |

the multilinear/sumcheck route lets the prover work without FFTs over the trace in the IOP, and lets one IOP serve constraints of any degree. it does not by itself make proofs smaller: the commitment dominates the size in both families.

## 3. the profiles

zheng carries every proof in one envelope, `ZHENGPF1` (magic · version · profile byte · canonical body):

- public (profile 0) and state-public (profile 3): the witness is disclosed and the verifier checks every CCS row exactly. soundness error 0 for the compiled relation, linear size, not succinct. a STARK has no counterpart; it is the fallback that is sound without any proximity argument.
- succinct (profile 1): the witness is committed; Spartan over Fp3 plus one WHIR opening. this is the profile comparable to a STARK.
- zk (profile 2, "veil"): succinct with masking; honest-verifier statistical zero knowledge, zero knowledge in the random-oracle model after Fiat–Shamir. scheme 1 of the same profile is an MPC-in-the-head fallback with linear size.
- machine (profile 4), recursive (profile 5) and wrapped (profile 6): a nox run of any length, accumulated, then IVC, then wrapped to constant size (§5).

soundness of every component is in [[zheng/specs/soundness|the soundness ledger]].

## 4. measured figures

Apple M4 Max, shared machine; every figure names its audit (zheng `audit/`, unless marked soft3):

| statement | profile | proof | verify | source |
|---|---|---|---|---|
| `hash.tri` (one hemera hash) | public v3 | 6,463 B envelope | linear | `audit/succinct-profile-2026-10.md` |
| `hash.tri` | succinct, shipped device parameters | 16,756 B | < 10 ms | soft3 `audit/proof-latency-2026-10.md` |
| Merkle membership, depth 32 | succinct, device parameters | 64,071 B | 310 ms | same |
| synthetic relation, 2^20 rows | succinct, bake-off parameters (24 grinding bits) | 71,081 B | 270 ms | `audit/succinct-profile-2026-10.md` |
| hash of a secret preimage | zk (veil) | 63.9 KB | 10.0 ms (4.1 ms with a cached verifying key) | `audit/zk-profile-2026-10.md` |
| `add.tri`, a run of any length | wrapped (profile 6) | 63,029 B, at most 64,213 B over every transcript | 1.9–2.2 ms | `audit/ivc-speed-2026-10.md` |

every succinct, zk and wrapped proof carries ≥ 128 proven bits. for scale, production STARK chains publish proofs of roughly 150 KB to 1 MB (soft3 `proposals/proof-system-repair.md` §1); the hash-only WHIR literature reports 56–87 KiB at `2^20` at rate 1/16.

the goal of the repair: any nox computation → a proof ≤ 64 KB, post-quantum, verify ≤ 1 ms, constant in the number of steps; small statements ≤ 16–20 KB. profile 6 meets the size for a run of any length; one-relation proofs meet it up to `2^18` committed variables. verification misses 1 ms in every profile — the causes are hemera inside the opening, an unstructured Spartan verifier, and recompiling the relation (a cached verifying key removes the last).

## 5. long computations

a STARK proves a long computation as one long trace, or recursively by verifying proofs inside proofs. zheng does the second, hash-only ([[zheng/docs/explanation/recursion|recursion]]):

- the nox machine is one uniform step relation for every program, an AIR proved by a sumcheck zerocheck (profile 4); its segments' Reed–Solomon evaluation claims are accumulated hash-based (WARP-structured, ARC-style out-of-domain samples) and decided by one WHIR opening. accumulation alone leaves every step's openings in the proof: about 96 KB per `2^14`-row segment (`audit/accumulation-2026-10.md`).
- IVC (profile 5): each step's relation runs the previous step's verifier, so the proof stays at about 285 KB from 33 to 1.57M cycles (`audit/recursion-2026-10.md`).
- wrap (profile 6): three wrap levels prove the IVC proof's final verifier, down to at most 64,213 B, proved in about 19 s on Metal (`audit/ivc-speed-2-2026-10.md`) — an aggregator's job, not a user device's.

this replaces the folding of the retired 0.3 design, which needed a homomorphic commitment; hemera is a hash, so the stack never had it soundly. the composition of IVC and wrap is a conjectured row of the soundness ledger, the heuristic every deployed recursive system shares.

## 6. honest assessment

- zheng's succinct and zk profiles are new code with weeks of review, not years of production; STARK provers have years.
- the relation compiler (program → CCS) is tested against native nox but not proven; it is a conjectured row of the soundness ledger.
- hemera's 32-byte digest gives 128-bit classical and about 85-bit quantum collision resistance. zheng's code and every figure above run hemera 0.3.1; the frozen material is hemera 0.4 (2026-10-16, same 32-byte digest), which zheng adopts in PR #69/#73. Merkle nodes inside proofs stay 32 bytes.
- the composition of IVC and wrap rests on the recursive Fiat–Shamir heuristic (a conjectured ledger row).
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
