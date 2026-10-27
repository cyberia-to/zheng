# the proof system landscape

every proof system makes a bet. it trades something — trust, proof size,
verification speed, quantum resistance — for something else. understanding
where [[zheng]] sits requires mapping the landscape of these tradeoffs.

## SNARKs with trusted setup

Groth16 is the oldest production proof system still in wide use. it
produces the smallest proofs in existence: 128 bytes, three elliptic curve
points. verification takes about 1.5 ms. [[Zcash]] and Tornado Cash
built on Groth16 because on-chain storage is expensive and small proofs
save gas.

the cost is a trusted setup ceremony. a group of participants generates a
structured reference string, and if even one participant is honest, the
system is secure. but "trusted" is the operative word. the ceremony
produces toxic waste — secret randomness that, if reconstructed, allows
forging arbitrary proofs. and the elliptic curves that make Groth16
possible are vulnerable to quantum computers. Shor's algorithm breaks
the discrete log assumption that underpins every pairing-based scheme.

## universal SNARKs

PLONK and its descendants (Halo2, HyperPlonk) replaced the
per-circuit trusted setup with a universal one. generate the structured
reference string once, use it for any circuit up to a fixed size. custom
gates allow efficient encoding of specific operations. many Layer 2
rollups adopted PLONKish systems because universality simplifies
deployment.

the curves remain. the quantum vulnerability remains. proof sizes grow
to roughly 400 bytes. verification slows to around 5 ms. the universal
setup is better than Groth16's per-circuit ceremony, but it is still a
ceremony.

## Bulletproofs

Bulletproofs eliminated the trusted setup entirely for range proofs
and general arithmetic circuits. [[Monero]] uses Bulletproofs because
the system requires zero trust in any external party. the tradeoff:
verification is logarithmic in the circuit size rather than constant,
making it slow for large circuits. and the underlying discrete log
assumption is still quantum-vulnerable.

## univariate STARKs

[[STARKs]] broke free from elliptic curves entirely. the security rests
on collision-resistant hash functions — transparent setup, post-quantum
security, no ceremonies, no toxic waste. [[StarkWare]] built [[CAIRO]]
on this foundation. Plonky2 and Stwo pushed STARK performance
further using small fields and FRI as the polynomial commitment
scheme.

the cost is proof size. production STARK chains publish proofs of
roughly 150 KB to 1 MB (soft3 `proposals/proof-system-repair.md` §1),
a thousand times or more larger than Groth16, and verification takes
milliseconds to tens of milliseconds.
for on-chain verification where every byte costs gas, this matters.

## multilinear, hash-based proofs

zheng uses the multilinear route: the interactive oracle proof is
[[SuperSpartan|Spartan]], which checks constraints with the [[sumcheck protocol]]
 rather than univariate polynomial division, and the
commitment is [[WHIR]] — Reed–Solomon codes over Goldilocks committed
with [[hemera]] Merkle trees and opened at one point of the cubic
extension Fp3. WHIR won the phase-2 bake-off of the
[[soft3/proposals/proof-system-repair|proof-system repair]]; the
expander-code ("recursive Brakedown") commitment it replaces had no real
opening and is retired. a nox run of any length is one uniform AIR,
proved by a sumcheck zerocheck rather than a quotient, then accumulated
and recursively composed to a constant size.

the shift from univariate to multilinear changes the prover: sumcheck
needs no FFT over the trace in the IOP. it does not change the size
floor: a hash-only proof still carries a Merkle path for every query, so
zheng's proofs sit in the same tens-of-kilobytes range as other hash-only
systems. the proofs are transparent and post-quantum, like FRI-based
STARKs.

## the tradeoff map

| system | setup | post-quantum | proof size | verify time |
|---|---|---|---|---|
| Groth16 | trusted (per-circuit) | no | 128 bytes | ~1.5 ms |
| PLONK | universal ceremony | no | ~400 bytes | ~5 ms |
| univariate [[STARK]] (FRI), production chains | transparent | yes | 150 KB – 1 MB | milliseconds to tens of ms |
| zheng succinct (Spartan + WHIR), one hemera hash | transparent | yes | 16,756 B | < 10 ms |
| zheng wrapped (profile 6), a nox run of any length | transparent | yes | ≤ 64,213 B | 1.9–2.2 ms |

zheng's figures are measured on an Apple M4 Max, shared machine (soft3
`audit/proof-latency-2026-10.md`; zheng `audit/ivc-speed-2026-10.md`);
the others are published figures.

## where the tradeoffs converge

trusted setups buy small proofs. the 128 bytes of Groth16 remain
unbeatable for raw size. but that compactness costs trust (ceremonies
that produce toxic waste) and quantum resistance (pairings that Shor's
algorithm will eventually break). universal setups like PLONK soften
the trust requirement without eliminating it.

hash-based systems — STARKs and zheng alike — trade larger proofs for
transparency and post-quantum security. zheng's goal inside that corner
is a proof of any nox computation ≤ 64 KB, verified in ≤ 1 ms, constant
in the number of steps. the size is met — by one relation up to
`2^18` committed variables, and by the wrapped profile for a run of any
length; the verification time is not met yet.

## why this corner suits cyber

[[cyber]] needs transparency (no ceremonies to coordinate across a
decentralized network) and post-quantum security (the foundation must
survive quantum computing). it does not need the smallest possible
proof per statement: long computations are combined by hash-based
accumulation of Reed–Solomon evaluation claims, IVC and wrapping into one
proof of at most 64,213 B ([[zheng/docs/explanation/recursion|recursion]]),
proved on aggregators rather than on the user's device.

the landscape has many valid positions. zheng chose the one that is
transparent, post-quantum and rests on one hash.
