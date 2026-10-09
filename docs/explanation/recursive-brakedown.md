---
alias: recursive brakedown
title: "recursive Brakedown: a retired design, and why it was unsound"
tags: cyber, soft3, zheng, article
crystal-type: article
crystal-domain: cyber
date: 2026-03-24
---

> superseded: unsound — retired by the [[soft3/proposals/proof-system-repair|proof-system repair]] (2026-10-09); the shipped commitment is Reed–Solomon + hemera Merkle trees (WHIR for the succinct profile), see [[zheng/specs/soundness|soundness ledger]] and [[zheng/docs/explanation/whir|whir]].

this page used to present "recursive Brakedown" as the polynomial commitment of [[zheng]]. it is kept as a research note so the links to it still resolve and so the reasoning error is recorded once. none of its size, time or soundness figures was ever true; they are not repeated here.

## 1. what the design was

[[Brakedown]] arranges the `N` evaluations of a multilinear polynomial as a `√N × √N` matrix, encodes each row with a linear-time expander code and opens an evaluation `f(r)` by sending one combined row `q = M · t₁` (`√N` field elements) and spot-checking columns of the encoding.

the recursive variant replaced "send `q`" by "commit to `q` and open `q` at a fresh point", level after level, until the remaining vector was about λ elements long. the commitment at every level was meant to be a single hemera hash of the whole encoded word ("one hash, 32 bytes"), without a Merkle tree. the page derived from this a proof of `O(log N + λ)` field elements, a verifier of `O(λ log log N)` field operations, a constant that did not grow with `N`, and per-level soundness error `2^-λ`.

## 2. why it is unsound

- a flat hash cannot be opened at one position. the verifier's spot-checks need the queried symbols of the encoded word to be bound to the commitment; a single hash of the whole word binds them only if the whole word is sent. any local opening of a hash commitment costs Θ(log n) digests per query in a hash-only world, by lower bound — the Merkle path is not overhead, it is the opening. Brakedown without a Merkle tree therefore has no opening at all, and the implementation that followed it compared a prover-supplied value with itself (lens dbf472b, zheng#14; 2,080 dead proof bytes found by bit-flip scan).
- the code distance was never proven. the expander code's minimum distance is proven only to be at least 1 (lens#6, `lens/specs/scalar-field.md`), so a fixed number of spot-checks bounds nothing; to be safe the implementation ended up opening every column.
- λ was counted in elements, not bits. the soundness section treated "λ = 128 spot-checks" as "error `2^-128`" without a per-query rejection probability, which requires a proven relative distance (the item above) and authenticated queries (the first item).
- the recursion composed claims whose own openings had the same two holes at every level, so the composed protocol inherited them; its knowledge soundness was listed as "open question 1" on this page and never closed.
- its numbers fed the old 0.3.x claim of a small constant proof for any computation. a hash-only proof cannot be smaller than the authentication of its own queries; the measured figures of the design that replaced it are in [[zheng/specs/soundness|specs/soundness.md]] and `audit/succinct-profile-2026-10.md`.

## 3. what replaced it

one code — Reed–Solomon over [[Goldilocks field|Goldilocks]] — committed with [[hemera]] Merkle trees and opened with proofs whose soundness is proven up to the Johnson bound. in the bake-off of phase 2 of the repair, WHIR (rate 1/64, folding factor 4, 24 grinding bits) won both size classes and ships as the succinct profile's opening; the RS tensor code (TensorRs, Ligero geometry) lost. constant size in the number of steps comes from hash-based accumulation of Reed–Solomon evaluation claims (ARC/WARP-style, phase 3), not from a smaller opening. the goal of the repair is a proof of any nox computation ≤ 64 KB, post-quantum, verify ≤ 1 ms, constant in the number of steps — a goal, not yet met.

the legacy Brakedown code path in lens and zheng stays behind cargo feature `legacy` (off by default, unsound) until it is deleted in phase 5.

see [[soft3/proposals/proof-system-repair|proof-system repair]] §2 for the full list of holes, [[zheng/docs/explanation/polynomial-commitments|polynomial-commitments]] for the commitment the profiles use, [[Brakedown]] for the base scheme as published.
