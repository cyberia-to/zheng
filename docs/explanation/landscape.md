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

## multilinear STARKs

[[Whirlaway]] represents the current frontier. it replaces FRI with
[[WHIR]], a hash-based polynomial commitment scheme for [[multilinear
polynomials]]. the interactive oracle proof is [[SuperSpartan]], which
encodes constraints using the [[sumcheck protocol]] rather than
univariate polynomial division. this is where zheng lives.

the shift from univariate to multilinear changes the economics. sumcheck
requires no NTT and no FFT — the prover runs in linear time over the
trace. WHIR achieves sub-millisecond verification while remaining
purely hash-based. the proofs are transparent and post-quantum, like
FRI-based STARKs, but verification speed competes with pairing-based
schemes.

## the tradeoff map

| system | setup | post-quantum | proof size | verify time | prover cost |
|---|---|---|---|---|---|
| [[Groth16]] | trusted (per-circuit) | no | 128 bytes | ~1.5 ms | O(N log N) |
| [[PLONK]] | universal ceremony | no | ~400 bytes | ~5 ms | O(N log N) |
| univariate [[STARK]] (FRI) | transparent | yes | ~200 KiB | 10-50 ms | O(N log N) |
| [[Whirlaway]] (zheng) | transparent | yes | ~157 KiB | ~1.0 ms | O(N log N) |

## where the tradeoffs converge

trusted setups buy small proofs. the 128 bytes of Groth16 remain
unbeatable for raw size. but that compactness costs trust (ceremonies
that produce toxic waste) and quantum resistance (pairings that Shor's
algorithm will eventually break). universal setups like PLONK soften
the trust requirement without eliminating it.

hash-based systems — all flavors of STARKs — trade larger proofs for
transparency and post-quantum security. FRI-based STARKs proved this
tradeoff viable. WHIR sharpens it: the same hash-based security model,
but verification drops from tens of milliseconds to under one
millisecond.

zheng occupies the corner of the landscape labeled "transparent setup,
post-quantum, fastest verification among hash-based systems." the cost
is proof size: ~157 KiB at 128-bit security versus 128 bytes for
Groth16. that is a real tradeoff, and for systems where each proof is
stored individually on-chain, it matters.

## why this corner suits cyber

[[cyber]] does not store individual proofs on-chain. proofs are verified
[[recursively]] — aggregated into tree structures, folded into epoch
proofs, compressed until a single proof covers an entire block or an
entire epoch. the intermediate proof sizes vanish into the recursion.
what remains is verification speed, because the verifier runs inside
[[nox]] at every recursion level.

sub-millisecond verification means cheap recursion. transparent setup
means no ceremonies to coordinate across a decentralized network.
post-quantum security means the cryptographic foundation survives the
transition to quantum computing. zheng pays the proof-size cost that
[[cyber]] can absorb and collects every property that cyber requires.

the landscape has many valid positions. zheng chose the one that makes
recursive composition fast, trustless, and future-proof.
