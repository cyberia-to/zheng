---
tags: cyber, computer science, cryptography
crystal-type: entity
crystal-domain: computer science
alias: universal accumulator, universal proof accumulator
---
# accumulator

> superseded: this page described a universal accumulator built on the legacy fold (feature `legacy`, unsound, removed in phase 5); the accumulator of the shipped design is specified in `accumulation.md` (phase 3), and its sizes are not measured yet.

the idea survives: every proof obligation of the chain — signal validity, state integrity, cross-index consistency, content availability, physical time — is absorbed into one running object, so a node that was offline downloads that object and one decider proof instead of replaying history. what changed is the mechanism and the honesty of the numbers.

## the accumulator of the shipped design

phase 3 (`accumulation.md`, `machine.md`, landing in this release) accumulates Reed–Solomon evaluation claims hash-based, ARC/WARP-style (ARC eprint 2024/1731, WARP 2025/753). each step batches the incoming claims with a sumcheck, commits one combined word (a hemera Merkle root), samples out-of-domain points and opens a few query positions. the accumulator is one root plus a fixed number of claims — independent of the number of steps. the decider is ONE WHIR opening of the final accumulator.

| quantity | status |
|---|---|
| accumulator size | constant in steps: one root and 1 + s + t claims (38 at rate 1/64, 55 at 1/16); ≈ 1.6–2.1 KB compressed, 19–29 KB as encoded today |
| decider proof | goal ≤ 64 KB; decider 44–93 KB measured (one WHIR opening of an Fp3 word, ℓ = 14…21; `audit/accumulation-2026-10.md`) |
| decider verify | goal ≤ 1 ms; decider verify 3.1–4.6 ms measured (hash.tri, merkle-32; whole machine proof 5–40 ms, linear in segments) |
| light-client checkpoint | state root + the decider proof; goal ≤ 64 KB; decider 44–93 KB measured (one WHIR opening of an Fp3 word, ℓ = 14…21; `audit/accumulation-2026-10.md`) |

## proof obligations

each block produces multiple independent obligations:

```
per signal:    zheng proof (cyberlink validity + impulse)
per block:     LogUp proof (cross-index consistency across the NMTs)
per index:     NMT completeness proofs (state integrity)
per sync:      DAS proofs (content availability)
per signal:    VDF proof (physical time)
```

for these to share one accumulator, each must be stated as claims about RS-encoded witnesses over Goldilocks; the nox machine relation (`machine.md`) is the first such relation. which of the other obligations are expressed as nox programs, and which stay separate proofs composed at the edge, is open.

## light client

```
light client joins:
  1. download checkpoint (state root + decider proof of the accumulator)
  2. verify ONE WHIR opening (the decider)
  3. request specific namespaces, verify against the committed state root
```

## the legacy universal accumulator (historical)

the earlier design folded every obligation as a CCS instance into one accumulator with the legacy fold with a selector "universal CCS" for F_p and F₂ rows, and quoted a fixed small checkpoint size and microsecond verification. that fold was never checked by the verifier — hemera is a hash, not a homomorphic commitment — so those figures described no sound object and are withdrawn ([[decider]] §soundness).

## open questions

1. heterogeneous obligations: signal, LogUp, DAS and VDF relations differ by orders of magnitude in size; one step relation, several, or composition at the edge.
2. availability freshness: DAS is probabilistic (O(√n) samples). accumulating it proves "sampling was performed correctly", not "data is available forever".
3. VDF chains are sequential; accumulating them proves the chain was verified, it does not remove the sequentiality.
4. cross-algebra: F₂ obligations either get an RS-over-Goldilocks encoding or are proven separately.

see `accumulation.md` for the scheme, [[recursion]] for composition, [[lens]] for the PCS.
