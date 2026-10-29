# why zheng

the entire cyber stack exists for one purpose: turning computation into
proofs. every layer beneath zheng was engineered with this moment in
mind. [[nebu]] defines the field. [[hemera]] defines the hash. [[nox]]
defines the virtual machine. zheng is the keystone that locks them
together — the component that takes a nox program, its inputs and its result and
produces a cryptographic proof that the program computes that result.

so why build a custom proof system from scratch? why not reach for
Groth16, Plonk, or one of the existing [[STARK]] implementations?

## the translation tax

every proof system speaks a particular algebraic dialect. Groth16 speaks
BN254 pairings. Plonk speaks a custom gate language over elliptic curves.
existing STARK toolchains speak their own constraint formats, their own
field choices, their own hash functions.

nox speaks [[Goldilocks]]. its registers are Goldilocks field elements.
its opcodes perform Goldilocks arithmetic. its memory is indexed over
Goldilocks. if zheng used a foreign proof system, every nox operation
would need to be translated into that system's constraint language — a
layer of indirection that inflates circuit size, slows the prover, and
introduces a surface area for bugs that have nothing to do with the
computation being proved.

zheng eliminates the translation entirely. the relation is compiled
directly from the nox program. the constraint system operates over the same field the VM uses.
the hash function inside the proof protocol is the same [[hemera]] hash
that nox calls as a native opcode. there is no impedance mismatch, no
encoding overhead, no second field to reason about.

## the zheng architecture

zheng is a polynomial proof system built from four parts, each single:

- one field: [[Goldilocks]] ([[nebu]]) for everything committed, its cubic
  extension Fp3 for every challenge and evaluation point.
- one hash: [[hemera]] (Poseidon2 over Goldilocks), for Merkle trees and
  Fiat–Shamir.
- one code: Reed–Solomon over Goldilocks.
- one IOP: [[SuperSpartan|Spartan]] [[sumcheck]] over [[CCS]] of any
  degree. the verifier compiles the CCS from the program itself and
  places the constant, the inputs, the outputs and the cost; only the
  witness is committed. a nox run of any length uses the nox machine
  instead — one uniform AIR for every program, proved by a sumcheck
  zerocheck.

the commitment of the succinct profile is [[WHIR]] — a hash-based
multilinear commitment over Reed–Solomon codes, opened with Merkle paths.
no elliptic curve pairings, no trusted setup ceremony, no structured
reference string. the security rests on [[hemera]] behaving as a random
oracle, so the same hash that secures nox's memory also secures the
proofs. the zk profile "veil" masks the sumchecks and uses a hiding
Reed–Solomon tensor commitment. every proof travels in one envelope,
`ZHENGPF1`, with a profile byte.

this combination yields:

- transparent setup (no ceremony, no toxic waste)
- post-quantum security (hash-only, no pairings to break)
- 128 proven bits per succinct proof ([[zheng/specs/soundness|soundness ledger]])
- a prover whose IOP streams through the relation with no FFT

measured on an Apple M4 Max: one hemera hash proves in 0.07 s on Metal
into a 16,756 B proof verified in under 10 ms (soft3
`audit/proof-latency-2026-10.md`); a run of any length wraps into at
most 64,213 B, verified in 2–6 ms (`audit/ivc-speed-2026-10.md`, `audit/consistency-2026-10-27.md`).
the goal is any nox computation in ≤ 64 KB, verified in ≤ 1 ms,
constant in the number of steps: the size is met, the verify time is
not.

## why nativity matters

the verifier performs [[Goldilocks]] arithmetic (native to nox), calls
[[hemera]] (a nox opcode), and evaluates multilinear polynomials over
the same field the VM already uses. so a verifier proved inside a zheng
relation needs no emulated foreign field. if zheng used a curve-based
system, a verifier inside nox would emulate a 256-bit field in a 64-bit
VM at hundreds of constraints per multiplication.

this is how zheng gets constant size today: each IVC step runs the
previous step's verifier as rows of its own relation, over hash-based
accumulation of Reed–Solomon evaluation claims, and three wrap levels
compress the result to at most 64,213 B
([[zheng/docs/explanation/recursion|recursion]]). a verifier written as a
nox program — the second verifier, in Trident, for composition across
domains and versions — is roadmap, not built.

## one field, one hash, one proof

step back and look at the full cryptographic stack:

- one prime: p = 2^64 - 2^32 + 1 ([[Goldilocks]]), with its cubic extension
- one hash: [[hemera]] (Poseidon2 over Goldilocks)
- one proof system: zheng (Spartan over CCS + Reed–Solomon commitments under hemera)

this is the entire cryptographic surface. when you audit zheng, you audit
the whole stack. when you analyze the security of [[hemera]], that
analysis covers both the VM's memory integrity and the proof system's
soundness. there are no seams between components where assumptions might
silently diverge.

## the keystone

[[nebu]] gives cyber its arithmetic. [[hemera]] gives cyber its memory
integrity. [[nox]] gives cyber its programmability. zheng gives cyber
something none of the others can provide alone: the ability to turn a
computation into a proof that anyone can verify without trusting the
prover, without trusting a ceremony, trusting only mathematics and one
hash.

zheng is where computation becomes evidence. it is the reason the stack
exists. every design choice in [[nebu]], every opcode in [[nox]], every
algebraic property of [[hemera]] was made so that this moment — the moment
a computation becomes a proof — would be sound first, and then as small
and as fast as a hash-only proof can be.

the proof is the product. zheng produces it.
