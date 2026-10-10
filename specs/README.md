---
tags: computer science, cryptography
---
# zheng: polynomial proof system

one field: Goldilocks ([[nebu]]) for everything committed, its cubic extension Fp3 for every challenge and evaluation point.
one hash: [[hemera]] (Poseidon2 over Goldilocks) — Merkle trees and Fiat–Shamir, used as a random oracle.
one code: Reed–Solomon over Goldilocks, behind the [[lens]] PCS trait (WHIR shipped; TensorRs the bake-off loser).
one IOP: [[SuperSpartan]] + [[sumcheck]] over CCS, challenges in Fp3.
one wire format: the `ZHENGPF1` envelope (magic · version · profile · canonical body).

zheng proofs are not STARKs: no AIR, no FRI. soundness of every production component is recorded, with its assumption and bits, in the [[soundness]] ledger.

## profiles

| envelope profile | name | what the verifier checks | size / verify (measured) |
|---|---|---|---|
| 0 | public certificate v3 | recompiles the CCS from the program, pins `z[0] = 1`, io and cycles, checks every row of the disclosed witness exactly; error 0 for the compiled relation | hash.tri 6,463 B envelope; linear, not succinct |
| 3 | state-public v3 | as profile 0, plus every read authenticated against the statement's own state root (`StateEvidence`) | linear |
| 1 | succinct | Spartan over Fp3, then one WHIR opening of the committed witness (rate 1/64, folding 4, 24 grinding bits); 128 proven bits | hash.tri 16,148 B envelope, verify 7.96 ms; 2^20 relation 71,081 B, 270 ms |
| 2 | zk (veil; MPC-in-the-head fallback) | Libra-masked Spartan over Fp3 + one hiding RS tensor commitment opened by one zero-knowledge linear test; 128.2 proven bits | secret-preimage hash 63.9 KB, verify 10.0 ms (4.1 ms with a cached verifying key) |
| 4 | machine proof (accumulation) | lands with phase 3: the nox machine as one step relation, accumulated per step, decided by one WHIR opening | goal ≤ 64 KB, constant in steps; measured: the decider is 44–93 KB, but without recursion the whole proof grows with the steps — 83 KB (33 cycles), 146 KB (merkle-32), 384 KB (16,383 cycles, 3 segments), ~96 KB per 2^14-row segment (`audit/accumulation-2026-10.md`) |
| 5 | recursive proof (IVC) | the last 2^15-row step natively (its circuit verified the step before), the final state against the run, three deferred claims, one WHIR decider; admitted parameter sets only | hash.tri 284,950 B envelope, decode + verify 26.5 ms; merkle-32 285,303 B, 32.1 ms; constant in steps (`audit/recursive-envelope-2026-10.md`) |
| 6 | wrapped proof | the profile-5 proof's final verifier proved by three wrap levels: the deferred nox-public claim against the statement, the public digest, one final-mode wrap proof natively; the admitted chain only (the final key bound to the IVC parameters) | hash.tri 62,962 B envelope (final proof 62,685 B), decode + verify 21–24 ms with keys, 4.2–4.6 s in a fresh process (keys derived); prove 21 min alone (#56), ~30 GB resident (`audit/wrapped-envelope-2026-10.md`) |

measurements: [succinct bake-off](../audit/succinct-profile-2026-10.md), [zk profile](../audit/zk-profile-2026-10.md) (Apple M4 Max, shared machine). the goal (owner, 2026-10-09): any nox computation → proof ≤ 64 KB, post-quantum (hash-only), verify ≤ 1 ms, constant in the number of steps. the succinct profile misses the size goal at 2^20 by 11 % and the verify goal everywhere today.

## spec pages

Implementation reviews and validation evidence are indexed in
[audit](../audit/README.md).

- [[soundness]] — the soundness ledger: one row per production component
- [[execution]] — profiles 0–3, verifying keys, the `ZHENGPF1` envelope
- [[lens]] — polynomial commitment (separate repo; `specs/whir.md`, `specs/tensor-rs.md`)
- [[sumcheck]] — the engine: O(N) prover reduces an exponential sum to one evaluation
- [[superspartan]] — CCS IOP via sumcheck: any-degree constraints, one PCS opening
- accumulation and machine (`accumulation.md`, `machine.md`) — phase 3, landing in this release: hash-based accumulation of RS evaluation claims (ARC/WARP-style) and the nox step relation
- [[recursion]] — IVC over the nox machine: each step's relation verifies the previous step in-circuit; constant-size proofs (`rs/src/recursion/`, `audit/recursion-2026-10.md`)
- [[accumulator]] — superseded: the legacy universal accumulator
- [[decider]] — superseded: the legacy decider, kept for its soundness residuals
- [[tensor]] — tensor compression for O(√N) prover memory
- [[verifier]] — what each profile's verifier does
- [[constraints]] — CCS format, pattern table, state operations
- [[transcript]] — Fiat–Shamir via hemera, Fp3 challenges
- [[api]] — the public API: certify / prove / verify / envelope / verifying keys
- [[phi-spmv]] — φ* SpMV circuit (legacy feature)

## architecture

```
zheng
├── execution (Rust: execution::*)
│   ├── relation compiler      nox program + subject shape → CCS
│   ├── certificate (v3)       profile 0 — exact row check
│   ├── state (v3)             profile 3 — reads authenticated under the state root
│   ├── succinct               profile 1 — Spartan/Fp3 + one lens opening
│   ├── veil                   profile 2 — masked Spartan + hiding RS tensor opening
│   ├── zk (MITH)              profile 2 scheme 1 — fallback, linear size
│   └── vk                     verifying keys, digest = hemera tree root of the relation
│
├── IOP layer
│   ├── SuperSpartan           CCS constraint system
│   └── sumcheck               generic over the challenge field (Goldilocks | Fp3)
│
├── lens layer (external repo)
│   ├── WHIR                   shipped (id 1)
│   └── TensorRs               bake-off loser (id 2), decodable until phase 5
│
├── hash layer
│   └── hemera                 Merkle trees + Fiat–Shamir (random oracle)
│
├── accumulation (phase 3, landing in this release)
│   └── ARC/WARP-style         per step: batch claims by sumcheck, commit one word,
│                              out-of-domain samples, a few queries; decider = one WHIR opening
│
└── legacy (feature `legacy`, off by default, unsound, removed in phase 5)
    └── folded trace API       commit/open/verify/fold/decide, universal CCS, phi
```

## the legacy fold

the 0.3/0.4 folded trace API (`commit`, `open`, `verify_eval`, `verify`, `fold`, `decide`, the universal CCS, phi) compiles only with the cargo feature `legacy`. it is unsound — the fold is never checked, the statement is unbound, the constant wire is free, and the Brakedown code distance is unproven ([[decider]] §soundness). it folded with a homomorphic-commitment protocol that hemera, a hash, cannot support; accumulation replaces it. recursion proper (a verifier as a nox program) is for composition only, never for size.

for intuition, motivation, and learning paths see [docs/explanation](../docs/explanation/). canonical design record: [[soft3/proposals/proof-system-repair|proof-system repair]].
