# why zheng

the entire cyber stack exists for one purpose: turning computation into
[[proofs]]. every layer beneath zheng was engineered with this moment in
mind. [[nebu]] defines the field. [[hemera]] defines the hash. [[nox]]
defines the virtual machine. zheng is the keystone that locks them
together — the component that takes a nox execution trace and produces
a cryptographic proof that the trace is correct.

so why build a custom proof system from scratch? why not reach for
[[Groth16]], [[Plonk]], or one of the existing [[STARK]] implementations?

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

zheng eliminates the translation entirely. the prover reads nox traces
directly. the constraint system operates over the same field the VM uses.
the hash function inside the proof protocol is the same [[hemera]] hash
that nox calls as a native opcode. there is no impedance mismatch, no
encoding overhead, no second field to reason about.

## the zheng architecture

zheng is a polynomial proof system combining three components that
reinforce each other:

[[SuperSpartan]] is the interactive oracle proof. it encodes the entire
execution trace as a single [[multilinear polynomial]] — one polynomial,
regardless of trace length. the prover runs in linear time over the trace
because [[sumcheck]] requires no NTT, no FFT, no expensive polynomial
multiplication. just field additions and multiplications, streaming
through the trace.

recursive Brakedown is the polynomial commitment scheme. it replaces [[KZG]]
and [[FRI]] with a hash-based construction that achieves sub-millisecond
verification. no elliptic curve pairings, no trusted setup ceremony, no
structured reference string that could be compromised. the security
rests entirely on the collision resistance of [[hemera]], which means
the same hash function that secures nox's memory also secures the proofs.

the [[sumcheck protocol]] is the connective tissue. it reduces claims
about multilinear polynomials to single-point evaluations, which Brakedown
then commits to. the reduction is tight — no blowup factors, no
auxiliary polynomials, no overhead beyond what information theory demands.

this combination yields four properties simultaneously:

- transparent setup (no ceremony, no toxic waste)
- post-quantum security (hash-based, no pairings to break)
- sub-millisecond verification (Brakedown beats KZG on speed)
- linear-time proving (sumcheck streams through the trace)

## recursion demands nativity

the deepest reason for building zheng in-house is [[recursive composition]].
a proof system is recursive when its verifier can run inside its own prover.
this means the verifier must be expressible as a program in [[nox]], which
means every operation the verifier performs — hashing, field arithmetic,
polynomial evaluation — must be native to nox.

if zheng used a foreign proof system, recursion would require emulating
foreign field arithmetic inside nox. emulating a 256-bit elliptic curve
field inside a 64-bit Goldilocks VM costs hundreds of constraints per
multiplication. the overhead compounds exponentially with recursion depth.
at two or three levels of nesting, the circuits become impractically large.

zheng avoids this entirely. the verifier performs [[Goldilocks]] arithmetic
(native to nox), calls [[hemera]] (a nox opcode), and evaluates
[[multilinear polynomials]] over the same field the VM already uses.
the verifier is a small nox program. recursion is cheap. composition
scales to arbitrary depth.

## one field, one hash, one proof

step back and look at the full cryptographic stack:

- one prime: p = 2^64 - 2^32 + 1 ([[Goldilocks]])
- one hash: [[hemera]] (Poseidon2 over Goldilocks)
- one proof system: zheng (SuperSpartan + recursive Brakedown over hemera over Goldilocks)

this is the entire cryptographic surface. one security parameter governs
the field. one algebraic structure governs the hash. one protocol governs
the proofs. when you audit zheng, you audit the whole stack. when you
analyze the security of [[hemera]], that analysis covers both the VM's
memory integrity and the proof system's soundness. there are no seams
between components where assumptions might silently diverge.

## the keystone

[[nebu]] gives cyber its arithmetic. [[hemera]] gives cyber its memory
integrity. [[nox]] gives cyber its programmability. zheng gives cyber
something none of the others can provide alone: the ability to compress
an entire computation into a short proof that anyone can verify in under
a millisecond, without trusting the prover, without trusting a ceremony,
without trusting anything except mathematics.

zheng is where computation becomes evidence. it is the reason the stack
exists. every design choice in [[nebu]], every opcode in [[nox]], every
algebraic property of [[hemera]] was made so that this moment — the moment
a trace becomes a proof — would be as fast, as small, and as secure as
the laws of information theory allow.

the proof is the product. zheng produces it.
