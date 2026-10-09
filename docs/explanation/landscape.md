# the proof system landscape

every proof system makes a bet. it trades something — trust, proof size,
verification speed, quantum resistance — for something else. understanding
where [[zheng]] sits requires mapping the landscape of these tradeoffs.

## SNARKs with trusted setup

[[Groth16]] is the oldest production proof system still in wide use. it
produces the smallest proofs in existence: 128 bytes, three elliptic curve
points. verification takes about 1.5 ms. [[Zcash]] and [[Tornado Cash]]
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

[[PLONK]] and its descendants ([[Halo2]], [[HyperPlonk]]) replaced the
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

[[Bulletproofs]] eliminated the trusted setup entirely for range proofs
and general arithmetic circuits. [[Monero]] uses Bulletproofs because
the system requires zero trust in any external party. the tradeoff:
verification is logarithmic in the circuit size rather than constant,
making it slow for large circuits. and the underlying discrete log
assumption is still quantum-vulnerable.

## univariate STARKs

[[STARKs]] broke free from elliptic curves entirely. the security rests
on collision-resistant hash functions — transparent setup, post-quantum
security, no ceremonies, no toxic waste. [[StarkWare]] built [[CAIRO]]
on this foundation. [[Plonky2]] and [[Stwo]] pushed STARK performance
further using small fields and [[FRI]] as the polynomial commitment
scheme.

the cost is proof size. FRI-based STARKs produce proofs in the range of
50-200 KiB, roughly a thousand times larger than Groth16. verification
takes 10-50 ms, an order of magnitude slower than pairing-based schemes.
for on-chain verification where every byte costs gas, this matters.

## multilinear, hash-based proofs

zheng uses the multilinear route: the interactive oracle proof is
[[SuperSpartan|Spartan]], which checks constraints with the [[sumcheck
protocol]] rather than univariate polynomial division, and the
commitment is [[WHIR]] — Reed–Solomon codes over Goldilocks committed
with [[hemera]] Merkle trees and opened at one point of the cubic
extension Fp3. WHIR won the phase-2 bake-off of the
[[soft3/proposals/proof-system-repair|proof-system repair]]; the
expander-code ("recursive Brakedown") commitment it replaces had no real
opening and is retired.

the shift from univariate to multilinear changes the prover: sumcheck
needs no FFT over the trace in the IOP. it does not change the size
floor: a hash-only proof still carries a Merkle path for every query, so
zheng's proofs sit in the same tens-of-kilobytes range as other hash-only
systems. the proofs are transparent and post-quantum, like FRI-based
STARKs.

## the tradeoff map

| system | setup | post-quantum | proof size | verify time |
|---|---|---|---|---|
| [[Groth16]] | trusted (per-circuit) | no | 128 bytes | ~1.5 ms |
| [[PLONK]] | universal ceremony | no | ~400 bytes | ~5 ms |
| univariate [[STARK]] (FRI), production chains | transparent | yes | 150 KB – 1 MB | 10-50 ms |
| zheng succinct (Spartan + WHIR), one hemera hash | transparent | yes | 15,921 B | 7.96 ms |
| zheng succinct, 2^20-row relation | transparent | yes | 71,081 B | 270 ms |

zheng's figures are measured (Apple M4 Max, shared machine,
`audit/succinct-profile-2026-10.md`); the others are published figures.

## where the tradeoffs converge

trusted setups buy small proofs. the 128 bytes of Groth16 remain
unbeatable for raw size. but that compactness costs trust (ceremonies
that produce toxic waste) and quantum resistance (pairings that Shor's
algorithm will eventually break). universal setups like PLONK soften
the trust requirement without eliminating it.

hash-based systems — STARKs and zheng alike — trade larger proofs for
transparency and post-quantum security. zheng's goal inside that corner
is a proof of any nox computation ≤ 64 KB, verified in ≤ 1 ms, constant
in the number of steps. the size is met for small statements and missed
by 11 % at 2^20 rows; the verification time is not met yet.

## why this corner suits cyber

[[cyber]] needs transparency (no ceremonies to coordinate across a
decentralized network) and post-quantum security (the foundation must
survive quantum computing). it does not need the smallest possible
proof per statement: long computations and many statements are combined
by hash-based accumulation of Reed–Solomon evaluation claims (phase 3,
ARC/WARP-style, in progress), decided by one WHIR opening — decider
proof ≤ 64 KB goal, measured size TODO(F-numbers). recursion proper — a
verifier written as a nox program — is kept for composition, not for
size: in a hash-only world a proof of a proof carries its own Merkle
paths again.

the landscape has many valid positions. zheng chose the one that is
transparent, post-quantum and rests on one hash.
