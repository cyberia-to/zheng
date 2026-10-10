---
tags: zheng, audit, succinct, pcs, whir, bake-off
crystal-type: audit
crystal-domain: crypto
---
# succinct profile and PCS bake-off — 2026-10-09

Work package E of the proof-system repair (soft3
`proposals/proof-system-repair.md`, §3 design, §5 phase 2). The succinct
profile (`zheng::execution::succinct`, envelope profile 1) proves the public
v3 / state v3 statements with the witness committed: the verifier derives the
relation and the pinned half `p` of `z' = (w ‖ p)` itself, checks Spartan over
Fp3 (outer sumcheck of the CCS degree, inner sumcheck batching the matrix
evaluations) and one PCS opening of `w̃` at an Fp3 point. Protocol:
`specs/execution.md` § succinct; bound: `specs/soundness.md`.

Stand: zheng `feat/succinct-profile` (on `feat/soundness-floor`), lens
`feat/rs-whir-pcs` 8f188a9 (unchanged — no lens API addition was needed),
joy `feat/succinct-profile`. Machine: Apple M4 Max, 16 cores, macOS 26.4,
rustc 1.95.0, `--release`, no LTO. **The machine was shared with other agents
during every run (load average 12–56, recorded per table); times are medians
of the stated repetitions under that load and are upper bounds of a quiet
machine. Sizes are deterministic.**

## columns

`n` = `2^ℓ` committed witness slots (free columns of the relation, rounded
up); `rows` = CCS rows; `proof B` = PCS id + params + root + Spartan + opening
(no statement); `envelope B` = the whole `ZHENGPF1` envelope (program
fixtures; synthetic relations have no statement type); `spartan B` = matrix
evaluations + compressed rounds + `w̃(r')` (Fp3 values only, length varints
excluded); `opening B` = the lens proof after its parameter header;
`prove ms` = relation + witness + commit + IOP + opening; `verify ms` =
statement → relation compile → IOP → opening (the public API);
`vfy-rel ms` = the same with the relation already compiled; `pcs vfy ms` =
the lens opening alone at the same size and parameters; `pcs bits` = lens's
proven round-by-round bound, grinding included; `total bits` =
`−log2(ε_spartan + ε_pcs)`.

Fixtures: joy `add.tri` (7, 5) and `hash.tri` (7) as compiled; `chain-11` =
eleven chained hemera noun-hashes `d_{i+1} = H(d_i, 0⁴)` built for the relation
compiler and checked against native nox (output and reductions,
`tests/succinct_profile.rs::hash_chain_agrees_with_native_nox`); synthetic
relations at `2^10 … 2^20` rows in the compiler's matrix shape (`a·b = c` and
`x^7 = w` rows, five matrices, degree 7). There is no Merkle-path program in
joy or trident fixtures, and a 32-hash chain does not compile: each hash of a
digest costs ~2,670 wires and the relation compiler caps a public statement at
32,768 ops/rows, so 11 hashes (27,520 free wires, `2^15`) is the longest chain
it admits. A 32-hash path needs the uniform step relation of phase 3.

## 1. bake-off — TensorRs vs WHIR, same fixtures, same transcript

Command: `cargo run --release -p zheng --example succinct_bakeoff -- bakeoff 3`
on zheng 80e373e. Grinding 16 bits, Johnson decoding, final polynomial
≤ 2^8 (lens defaults) unless stated. Load: 13.5 at the start, 11.3 at the end.

| fixture | pcs | n (committed) | rows | proof B | envelope B | spartan B | opening B | prove ms | verify ms | vfy-rel ms | pcs vfy ms | pcs bits | total bits | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| add.tri | TensorRs 1/4 | 2^4 | 2^4 | 1251 | 1425 | 624 | 584 | 0.7 | 0.634 | 0.619 | 0.116 | 186.09 | 185.54 |  |
| add.tri | TensorRs 1/16 | 2^4 | 2^4 | 2787 | 2961 | 624 | 2120 | 1.2 | 0.926 | 0.901 | 0.400 | 184.09 | 183.93 |  |
| add.tri | WHIR 1/4 k=2 | 2^4 | 2^4 | 1433 | 1607 | 624 | 764 | 0.9 | 0.837 | 0.816 | 0.311 | 142.96 | 142.96 |  |
| add.tri | WHIR 1/4 k=3 | 2^4 | 2^4 | 1433 | 1607 | 624 | 764 | 0.8 | 0.750 | 0.730 | 0.228 | 142.96 | 142.96 |  |
| add.tri | WHIR 1/4 k=4 | 2^4 | 2^4 | 1457 | 1631 | 624 | 788 | 0.8 | 0.697 | 0.676 | 0.175 | 142.96 | 142.96 |  |
| add.tri | WHIR 1/4 k=5 | 2^4 | 2^4 | 1457 | 1631 | 624 | 788 | 0.8 | 0.697 | 0.674 | 0.175 | 142.96 | 142.96 |  |
| add.tri | WHIR 1/4 k=6 | 2^4 | 2^4 | 1457 | 1631 | 624 | 788 | 0.8 | 0.699 | 0.674 | 0.174 | 142.96 | 142.96 |  |
| add.tri | WHIR 1/16 k=2 | 2^4 | 2^4 | 2785 | 2959 | 624 | 2116 | 28.5 | 1.365 | 1.288 | 0.763 | 128.07 | 128.07 |  |
| add.tri | WHIR 1/16 k=3 | 2^4 | 2^4 | 2969 | 3143 | 624 | 2300 | 1.2 | 1.172 | 1.152 | 0.675 | 142.60 | 142.60 |  |
| add.tri | WHIR 1/16 k=4 | 2^4 | 2^4 | 2993 | 3167 | 624 | 2324 | 1.0 | 0.948 | 0.926 | 0.454 | 142.60 | 142.60 |  |
| add.tri | WHIR 1/16 k=5 | 2^4 | 2^4 | 2993 | 3167 | 624 | 2324 | 1.0 | 0.958 | 0.927 | 0.438 | 142.60 | 142.60 |  |
| add.tri | WHIR 1/16 k=6 | 2^4 | 2^4 | 2993 | 3167 | 624 | 2324 | 1.0 | 0.950 | 0.926 | 0.449 | 142.60 | 142.60 |  |
| hash.tri | TensorRs 1/4 | 2^10 | 2^10 | 24747 | 24974 | 2592 | 22112 | 72.8 | 10.509 | 6.355 | 4.741 | 128.56 | 128.56 |  |
| hash.tri | TensorRs 1/16 | 2^10 | 2^10 | 29483 | 29710 | 2592 | 26848 | 74.6 | 10.827 | 6.680 | 5.256 | 128.24 | 128.24 |  |
| hash.tri | WHIR 1/4 k=2 | 2^10 | 2^10 | 20913 | 21140 | 2592 | 18276 | 42.9 | 9.544 | 5.361 | 4.176 | 128.01 | 128.01 |  |
| hash.tri | WHIR 1/4 k=3 | 2^10 | 2^10 | 18369 | 18596 | 2592 | 15732 | 44.7 | 9.117 | 5.023 | 3.431 | 128.01 | 128.01 |  |
| hash.tri | WHIR 1/4 k=4 | 2^10 | 2^10 | 19345 | 19572 | 2592 | 16708 | 71.0 | 8.316 | 4.395 | 3.194 | 128.01 | 128.01 |  |
| hash.tri | WHIR 1/4 k=5 | 2^10 | 2^10 | 24193 | 24420 | 2592 | 21556 | 43.0 | 7.395 | 4.564 | 3.434 | 128.01 | 128.01 |  |
| hash.tri | WHIR 1/4 k=6 | 2^10 | 2^10 | 36137 | 36364 | 2592 | 33500 | 17.7 | 8.795 | 5.209 | 3.939 | 130.96 | 130.96 |  |
| hash.tri | WHIR 1/16 k=2 | 2^10 | 2^10 | 20689 | 20916 | 2592 | 18052 | 47.9 | 8.758 | 4.549 | 3.162 | 128.07 | 128.07 |  |
| hash.tri | WHIR 1/16 k=3 | 2^10 | 2^10 | 16897 | 17124 | 2592 | 14260 | 72.8 | 8.286 | 4.128 | 2.859 | 128.07 | 128.07 |  |
| hash.tri | WHIR 1/16 k=4 | 2^10 | 2^10 | 17937 | 18164 | 2592 | 15300 | 42.4 | 8.172 | 4.081 | 2.702 | 128.07 | 128.07 |  |
| hash.tri | WHIR 1/16 k=5 | 2^10 | 2^10 | 22593 | 22820 | 2592 | 19956 | 58.6 | 8.431 | 4.291 | 2.841 | 128.07 | 128.07 |  |
| hash.tri | WHIR 1/16 k=6 | 2^10 | 2^10 | 33329 | 33556 | 2592 | 30692 | 50.2 | 9.322 | 5.162 | 3.486 | 128.07 | 128.07 |  |
| chain-11 (hemera) | TensorRs 1/4 | 2^15 | 2^15 | 114459 | 115371 | 3792 | 110624 | 461.4 | 161.764 | 25.326 | 17.355 | 128.56 | 128.56 |  |
| chain-11 (hemera) | TensorRs 1/16 | 2^15 | 2^15 | 108923 | 109835 | 3792 | 105088 | 487.2 | 156.337 | 23.664 | 13.650 | 128.24 | 128.24 |  |
| chain-11 (hemera) | WHIR 1/4 k=2 | 2^15 | 2^15 | 92501 | 93413 | 3792 | 88664 | 716.8 | 160.157 | 24.781 | 16.142 | 128.01 | 128.01 |  |
| chain-11 (hemera) | WHIR 1/4 k=3 | 2^15 | 2^15 | 72857 | 73769 | 3792 | 69020 | 706.0 | 155.940 | 20.820 | 12.282 | 128.01 | 128.01 |  |
| chain-11 (hemera) | WHIR 1/4 k=4 | 2^15 | 2^15 | 67453 | 68365 | 3792 | 63616 | 517.9 | 153.766 | 18.436 | 9.837 | 128.01 | 128.01 |  |
| chain-11 (hemera) | WHIR 1/4 k=5 | 2^15 | 2^15 | 85421 | 86333 | 3792 | 81584 | 515.7 | 152.924 | 18.981 | 10.957 | 128.01 | 128.01 |  |
| chain-11 (hemera) | WHIR 1/4 k=6 | 2^15 | 2^15 | 129933 | 130845 | 3792 | 126096 | 654.3 | 158.577 | 22.357 | 13.991 | 128.01 | 128.01 |  |
| chain-11 (hemera) | WHIR 1/16 k=2 | 2^15 | 2^15 | 73253 | 74165 | 3792 | 69416 | 969.5 | 154.695 | 20.529 | 10.960 | 128.05 | 128.05 |  |
| chain-11 (hemera) | WHIR 1/16 k=3 | 2^15 | 2^15 | 57945 | 58857 | 3792 | 54108 | 880.4 | 150.874 | 17.430 | 9.136 | 128.01 | 128.01 |  |
| chain-11 (hemera) | WHIR 1/16 k=4 | 2^15 | 2^15 | 51741 | 52653 | 3792 | 47904 | 622.5 | 143.863 | 15.534 | 6.996 | 128.07 | 128.07 |  |
| chain-11 (hemera) | WHIR 1/16 k=5 | 2^15 | 2^15 | 61733 | 62645 | 3792 | 57896 | 617.0 | 149.111 | 15.853 | 7.523 | 128.01 | 128.01 |  |
| chain-11 (hemera) | WHIR 1/16 k=6 | 2^15 | 2^15 | 89453 | 90365 | 3792 | 85616 | 689.0 | 151.074 | 17.898 | 9.892 | 128.07 | 128.07 |  |
| synthetic 2^10 | TensorRs 1/4 | 2^10 | 2^10 | 24299 | — | 2592 | 21664 | 70.8 | 5.922 | 5.922 | 4.647 | 128.56 | 128.56 |  |
| synthetic 2^10 | TensorRs 1/16 | 2^10 | 2^10 | 29483 | — | 2592 | 26848 | 45.2 | 6.400 | 6.400 | 5.124 | 128.24 | 128.24 |  |
| synthetic 2^10 | WHIR 1/4 k=2 | 2^10 | 2^10 | 21073 | — | 2592 | 18436 | 42.5 | 5.189 | 5.189 | 4.069 | 128.01 | 128.01 |  |
| synthetic 2^10 | WHIR 1/4 k=3 | 2^10 | 2^10 | 18561 | — | 2592 | 15924 | 46.2 | 4.831 | 4.831 | 3.580 | 128.01 | 128.01 |  |
| synthetic 2^10 | WHIR 1/4 k=4 | 2^10 | 2^10 | 19761 | — | 2592 | 17124 | 63.9 | 4.459 | 4.459 | 2.918 | 128.01 | 128.01 |  |
| synthetic 2^10 | WHIR 1/4 k=5 | 2^10 | 2^10 | 23521 | — | 2592 | 20884 | 40.4 | 4.227 | 4.227 | 3.070 | 128.01 | 128.01 |  |
| synthetic 2^10 | WHIR 1/4 k=6 | 2^10 | 2^10 | 36137 | — | 2592 | 33500 | 11.9 | 5.079 | 5.079 | 3.888 | 130.96 | 130.96 |  |
| synthetic 2^10 | WHIR 1/16 k=2 | 2^10 | 2^10 | 19857 | — | 2592 | 17220 | 98.4 | 4.239 | 4.239 | 3.096 | 128.07 | 128.07 |  |
| synthetic 2^10 | WHIR 1/16 k=3 | 2^10 | 2^10 | 17761 | — | 2592 | 15124 | 87.3 | 4.044 | 4.044 | 2.803 | 128.07 | 128.07 |  |
| synthetic 2^10 | WHIR 1/16 k=4 | 2^10 | 2^10 | 17489 | — | 2592 | 14852 | 42.2 | 3.766 | 3.766 | 2.660 | 128.07 | 128.07 |  |
| synthetic 2^10 | WHIR 1/16 k=5 | 2^10 | 2^10 | 22369 | — | 2592 | 19732 | 50.7 | 4.027 | 4.027 | 2.764 | 128.07 | 128.07 |  |
| synthetic 2^10 | WHIR 1/16 k=6 | 2^10 | 2^10 | 34513 | — | 2592 | 31876 | 77.5 | 5.071 | 5.071 | 3.421 | 128.07 | 128.07 |  |
| synthetic 2^14 | TensorRs 1/4 | 2^14 | 2^14 | 84811 | — | 3552 | 81216 | 188.1 | 15.179 | 15.179 | 11.748 | 128.56 | 128.56 |  |
| synthetic 2^14 | TensorRs 1/16 | 2^14 | 2^14 | 78475 | — | 3552 | 74880 | 181.4 | 13.842 | 13.842 | 10.817 | 128.24 | 128.24 |  |
| synthetic 2^14 | WHIR 1/4 k=2 | 2^14 | 2^14 | 73193 | — | 3552 | 69596 | 360.6 | 16.209 | 16.209 | 13.078 | 128.01 | 128.01 |  |
| synthetic 2^14 | WHIR 1/4 k=3 | 2^14 | 2^14 | 57029 | — | 3552 | 53432 | 252.0 | 12.916 | 12.916 | 9.629 | 128.01 | 128.01 |  |
| synthetic 2^14 | WHIR 1/4 k=4 | 2^14 | 2^14 | 60397 | — | 3552 | 56800 | 268.6 | 12.070 | 12.070 | 8.737 | 128.01 | 128.01 |  |
| synthetic 2^14 | WHIR 1/4 k=5 | 2^14 | 2^14 | 78165 | — | 3552 | 74568 | 269.4 | 11.921 | 11.921 | 8.582 | 128.01 | 128.01 |  |
| synthetic 2^14 | WHIR 1/4 k=6 | 2^14 | 2^14 | 74721 | — | 3552 | 71124 | 165.8 | 11.373 | 11.373 | 7.461 | 128.01 | 128.01 |  |
| synthetic 2^14 | WHIR 1/16 k=2 | 2^14 | 2^14 | 59177 | — | 3552 | 55580 | 662.7 | 13.269 | 13.269 | 9.499 | 128.05 | 128.05 |  |
| synthetic 2^14 | WHIR 1/16 k=3 | 2^14 | 2^14 | 45501 | — | 3552 | 41904 | 344.4 | 10.388 | 10.388 | 7.035 | 128.07 | 128.07 |  |
| synthetic 2^14 | WHIR 1/16 k=4 | 2^14 | 2^14 | 46925 | — | 3552 | 43328 | 262.2 | 9.193 | 9.193 | 5.647 | 128.07 | 128.07 |  |
| synthetic 2^14 | WHIR 1/16 k=5 | 2^14 | 2^14 | 59221 | — | 3552 | 55624 | 306.5 | 9.049 | 9.049 | 7.034 | 128.01 | 128.01 |  |
| synthetic 2^14 | WHIR 1/16 k=6 | 2^14 | 2^14 | 48609 | — | 3552 | 45012 | 193.5 | 8.970 | 8.970 | 5.779 | 128.07 | 128.07 |  |
| synthetic 2^16 | TensorRs 1/4 | 2^16 | 2^16 | 155307 | — | 4032 | 151232 | 568.7 | 30.519 | 30.519 | 20.712 | 128.56 | 128.56 |  |
| synthetic 2^16 | TensorRs 1/16 | 2^16 | 2^16 | 141579 | — | 4032 | 137504 | 598.5 | 28.594 | 28.594 | 17.799 | 128.24 | 128.24 |  |
| synthetic 2^16 | WHIR 1/4 k=2 | 2^16 | 2^16 | 104021 | — | 4032 | 99944 | 955.4 | 28.124 | 28.124 | 17.938 | 128.01 | 128.01 |  |
| synthetic 2^16 | WHIR 1/4 k=3 | 2^16 | 2^16 | 81825 | — | 4032 | 77748 | 869.4 | 23.189 | 23.189 | 13.142 | 128.01 | 128.01 |  |
| synthetic 2^16 | WHIR 1/4 k=4 | 2^16 | 2^16 | 75725 | — | 4032 | 71648 | 719.0 | 20.881 | 20.881 | 11.004 | 128.01 | 128.01 |  |
| synthetic 2^16 | WHIR 1/4 k=5 | 2^16 | 2^16 | 89981 | — | 4032 | 85904 | 737.2 | 20.576 | 20.576 | 11.517 | 128.01 | 128.01 |  |
| synthetic 2^16 | WHIR 1/4 k=6 | 2^16 | 2^16 | 135101 | — | 4032 | 131024 | 717.0 | 25.076 | 25.076 | 14.819 | 128.01 | 128.01 |  |
| synthetic 2^16 | WHIR 1/16 k=2 | 2^16 | 2^16 | 81589 | — | 4032 | 77512 | 1361.5 | 23.162 | 23.162 | 13.113 | 128.05 | 128.05 |  |
| synthetic 2^16 | WHIR 1/16 k=3 | 2^16 | 2^16 | 64041 | — | 4032 | 59964 | 1153.1 | 20.010 | 20.010 | 9.686 | 128.01 | 128.01 |  |
| synthetic 2^16 | WHIR 1/16 k=4 | 2^16 | 2^16 | 57261 | — | 4032 | 53184 | 862.9 | 18.136 | 18.136 | 7.786 | 128.07 | 128.07 |  |
| synthetic 2^16 | WHIR 1/16 k=5 | 2^16 | 2^16 | 65429 | — | 4032 | 61352 | 832.0 | 17.890 | 17.890 | 8.040 | 128.01 | 128.01 |  |
| synthetic 2^16 | WHIR 1/16 k=6 | 2^16 | 2^16 | 93213 | — | 4032 | 89136 | 878.6 | 20.402 | 20.402 | 10.326 | 128.07 | 128.07 |  |
| synthetic 2^18 | TensorRs 1/4 | 2^18 | 2^18 | 295115 | — | 4512 | 290560 | 2181.2 | 92.596 | 92.596 | 37.408 | 128.56 | 128.56 |  |
| synthetic 2^18 | TensorRs 1/16 | 2^18 | 2^18 | 257291 | — | 4512 | 252736 | 2364.2 | 86.652 | 86.652 | 31.706 | 128.24 | 128.24 |  |
| synthetic 2^18 | WHIR 1/4 k=2 | 2^18 | 2^18 | 136801 | — | 4512 | 132244 | 3416.5 | 80.295 | 80.295 | 23.330 | 128.01 | 128.01 |  |
| synthetic 2^18 | WHIR 1/4 k=3 | 2^18 | 2^18 | 107149 | — | 4512 | 102592 | 2962.9 | 72.750 | 72.750 | 17.172 | 128.01 | 128.01 |  |
| synthetic 2^18 | WHIR 1/4 k=4 | 2^18 | 2^18 | 100713 | — | 4512 | 96156 | 2781.4 | 70.073 | 70.073 | 14.644 | 128.01 | 128.01 |  |
| synthetic 2^18 | WHIR 1/4 k=5 | 2^18 | 2^18 | 105629 | — | 4512 | 101072 | 2499.7 | 67.271 | 67.271 | 13.796 | 128.01 | 128.01 |  |
| synthetic 2^18 | WHIR 1/4 k=6 | 2^18 | 2^18 | 146573 | — | 4512 | 142016 | 2532.0 | 71.892 | 71.892 | 13.756 | 128.01 | 128.01 |  |
| synthetic 2^18 | WHIR 1/16 k=2 | 2^18 | 2^18 | 106337 | — | 4512 | 101780 | 4869.0 | 69.487 | 69.487 | 16.366 | 128.01 | 128.01 |  |
| synthetic 2^18 | WHIR 1/16 k=3 | 2^18 | 2^18 | 82885 | — | 4512 | 78328 | 4266.6 | 65.835 | 65.835 | 12.160 | 128.01 | 128.01 |  |
| synthetic 2^18 | WHIR 1/16 k=4 | 2^18 | 2^18 | 76361 | — | 4512 | 71804 | 3412.3 | 62.516 | 62.516 | 10.042 | 128.07 | 128.07 |  |
| synthetic 2^18 | WHIR 1/16 k=5 | 2^18 | 2^18 | 76093 | — | 4512 | 71536 | 2914.3 | 61.866 | 61.866 | 9.231 | 128.01 | 128.01 |  |
| synthetic 2^18 | WHIR 1/16 k=6 | 2^18 | 2^18 | 100941 | — | 4512 | 96384 | 2835.8 | 66.946 | 66.946 | 11.012 | 128.07 | 128.07 |  |
| synthetic 2^20 | TensorRs 1/4 | 2^20 | 2^20 | 570155 | — | 4992 | 565120 | 8221.8 | 300.909 | 300.909 | 67.624 | 128.56 | 128.56 |  |
| synthetic 2^20 | TensorRs 1/16 | 2^20 | 2^20 | 485547 | — | 4992 | 480512 | 8835.4 | 293.969 | 293.969 | 55.132 | 128.24 | 128.24 |  |
| synthetic 2^20 | WHIR 1/4 k=2 | 2^20 | 2^20 | 172173 | — | 4992 | 167136 | 11844.5 | 269.352 | 269.352 | 28.933 | 128.05 | 128.05 |  |
| synthetic 2^20 | WHIR 1/4 k=3 | 2^20 | 2^20 | 128077 | — | 4992 | 123040 | 10874.2 | 261.689 | 261.689 | 20.506 | 128.01 | 128.01 |  |
| synthetic 2^20 | WHIR 1/4 k=4 | 2^20 | 2^20 | 117897 | — | 4992 | 112860 | 10098.0 | 259.265 | 259.265 | 17.090 | 128.01 | 128.01 |  |
| synthetic 2^20 | WHIR 1/4 k=5 | 2^20 | 2^20 | 136241 | — | 4992 | 131204 | 9788.9 | 258.519 | 258.519 | 17.623 | 128.06 | 128.06 |  |
| synthetic 2^20 | WHIR 1/4 k=6 | 2^20 | 2^20 | 161453 | — | 4992 | 156416 | 9401.4 | 260.308 | 260.308 | 18.726 | 128.06 | 128.06 |  |
| synthetic 2^20 | WHIR 1/16 k=2 | 2^20 | 2^20 | 132749 | — | 4992 | 127712 | 20462.0 | 246.833 | 246.833 | 17.950 | 128.01 | 128.01 |  |
| synthetic 2^20 | WHIR 1/16 k=3 | 2^20 | 2^20 | 97733 | — | 4992 | 92696 | 15356.5 | 248.146 | 248.146 | 14.360 | 128.01 | 128.01 |  |
| synthetic 2^20 | WHIR 1/16 k=4 | 2^20 | 2^20 | 88777 | — | 4992 | 83740 | 12745.1 | 250.689 | 250.689 | 11.929 | 128.22 | 128.22 |  |
| synthetic 2^20 | WHIR 1/16 k=5 | 2^20 | 2^20 | 100049 | — | 4992 | 95012 | 12289.4 | 253.717 | 253.717 | 12.380 | 128.01 | 128.01 |  |
| synthetic 2^20 | WHIR 1/16 k=6 | 2^20 | 2^20 | 112237 | — | 4992 | 107200 | 11115.4 | 255.250 | 255.250 | 11.783 | 128.28 | 128.28 |  |

Every row is ≥ 128 proven bits (lens's bound; the Spartan term is 2^-184 or
smaller everywhere and never the minimum).

Reading (best TensorRs proof ÷ best WHIR proof per fixture): add.tri 0.87
(TensorRs wins at `2^4`, 1,251 B against 1,433 B, opening every column),
hash.tri 1.46, synthetic `2^10` 1.39, `2^14` 1.72, chain-11 2.11, `2^16` 2.47,
`2^18` 3.38, `2^20` 5.47. WHIR's best rate is 1/16 at every size above `2^4`;
its best folding factor is 3 or 4.

## 2. levers, one at a time (proposal §A)

Command: `… succinct_bakeoff -- levers 3`. Fixtures hash.tri and synthetic
`2^20`; base WHIR 1/16, k = 4, grinding 16. Sizes deterministic; times from
an intermediate verifier build (the map-based matrix weight before the
closed-form `eq(τ, ρ)`), ~100 ms slower at `2^20` than the final verifier.

| fixture | pcs | n (committed) | rows | proof B | envelope B | spartan B | opening B | prove ms | verify ms | vfy-rel ms | pcs vfy ms | pcs bits | total bits | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| hash.tri | WHIR 1/16 k=4 pow=16 | 2^10 | 2^10 | 17937 | 18164 | 2592 | 15300 | 43.0 | 8.172 | 4.093 | 2.651 | 128.07 | 128.07 | t=[57] siblings 206 (full paths 540, dedup saves 10688 B); u32 prefixes 9 (36 B); 2235 limbs: fixed 17880 B vs varint 21064 B |
| hash.tri | WHIR 1/16 k=4 pow=20 | 2^10 | 2^10 | 16913 | 17140 | 2592 | 14276 | 313.3 | 8.045 | 3.932 | 2.578 | 128.04 | 128.04 | t=[55] siblings 182 (full paths 520, dedup saves 10816 B); u32 prefixes 9 (36 B); 2107 limbs: fixed 16856 B vs varint 19865 B |
| hash.tri | WHIR 1/16 k=4 pow=24 | 2^10 | 2^10 | 17457 | 17684 | 2592 | 14820 | 9223.3 | 8.111 | 4.008 | 2.289 | 128.01 | 128.01 | t=[53] siblings 195 (full paths 530, dedup saves 10720 B); u32 prefixes 9 (36 B); 2175 limbs: fixed 17400 B vs varint 20544 B |
| hash.tri | WHIR 1/16 k=2 pow=16 | 2^10 | 2^10 | 20689 | 20916 | 2592 | 18052 | 51.2 | 8.727 | 4.601 | 2.814 | 128.07 | 128.07 | t=[57] siblings 310 (full paths 684, dedup saves 11968 B); u32 prefixes 9 (36 B); 2579 limbs: fixed 20632 B vs varint 24242 B |
| hash.tri | WHIR 1/16 k=3 pow=16 | 2^10 | 2^10 | 16897 | 17124 | 2592 | 14260 | 75.9 | 7.656 | 3.779 | 2.584 | 128.07 | 128.07 | t=[57] siblings 233 (full paths 605, dedup saves 11904 B); u32 prefixes 9 (36 B); 2105 limbs: fixed 16840 B vs varint 19823 B |
| hash.tri | WHIR 1/16 k=4 pow=16 | 2^10 | 2^10 | 17937 | 18164 | 2592 | 15300 | 46.7 | 8.007 | 4.076 | 2.650 | 128.07 | 128.07 | t=[57] siblings 206 (full paths 540, dedup saves 10688 B); u32 prefixes 9 (36 B); 2235 limbs: fixed 17880 B vs varint 21064 B |
| hash.tri | WHIR 1/16 k=5 pow=16 | 2^10 | 2^10 | 22593 | 22820 | 2592 | 19956 | 57.7 | 8.396 | 4.315 | 2.764 | 128.07 | 128.07 | t=[57] siblings 150 (full paths 495, dedup saves 11040 B); u32 prefixes 9 (36 B); 2817 limbs: fixed 22536 B vs varint 26475 B |
| hash.tri | WHIR 1/16 k=6 pow=16 | 2^10 | 2^10 | 33329 | 33556 | 2592 | 30692 | 51.0 | 9.243 | 5.184 | 3.401 | 128.07 | 128.07 | t=[57] siblings 88 (full paths 424, dedup saves 10752 B); u32 prefixes 9 (36 B); 4159 limbs: fixed 33272 B vs varint 38985 B |
| hash.tri | WHIR 1/2 k=4 pow=16 | 2^10 | 2^10 | 20809 | 21036 | 2592 | 18172 | 16.8 | 9.015 | 4.999 | 3.504 | 131.34 | 131.34 | t=[128] siblings 0 (full paths 896, dedup saves 28672 B); u32 prefixes 9 (36 B); 2595 limbs: fixed 20760 B vs varint 23495 B |
| hash.tri | WHIR 1/4 k=4 pow=16 | 2^10 | 2^10 | 19345 | 19572 | 2592 | 16708 | 68.1 | 8.691 | 4.636 | 3.281 | 128.01 | 128.01 | t=[114] siblings 102 (full paths 728, dedup saves 20032 B); u32 prefixes 9 (36 B); 2411 limbs: fixed 19288 B vs varint 22320 B |
| hash.tri | WHIR 1/8 k=4 pow=16 | 2^10 | 2^10 | 18961 | 19188 | 2592 | 16324 | 49.0 | 8.476 | 4.391 | 2.835 | 128.06 | 128.06 | t=[76] siblings 162 (full paths 657, dedup saves 15840 B); u32 prefixes 9 (36 B); 2363 limbs: fixed 18904 B vs varint 22133 B |
| hash.tri | WHIR 1/16 k=4 pow=16 | 2^10 | 2^10 | 17937 | 18164 | 2592 | 15300 | 45.8 | 8.136 | 4.099 | 2.650 | 128.07 | 128.07 | t=[57] siblings 206 (full paths 540, dedup saves 10688 B); u32 prefixes 9 (36 B); 2235 limbs: fixed 17880 B vs varint 21064 B |
| hash.tri | WHIR 1/32 k=4 pow=16 | 2^10 | 2^10 | 16625 | 16852 | 2592 | 13988 | 50.3 | 7.874 | 3.818 | 2.452 | 128.05 | 128.05 | t=[46] siblings 209 (full paths 473, dedup saves 8448 B); u32 prefixes 9 (36 B); 2071 limbs: fixed 16568 B vs varint 19520 B |
| synthetic 2^20 | WHIR 1/16 k=4 pow=16 | 2^20 | 2^20 | 88777 | — | 4992 | 83740 | 13073.8 | 343.965 | 343.965 | 11.449 | 128.22 | 128.22 | t=[58 33 23] siblings 1492 (full paths 2201, dedup saves 22688 B); u32 prefixes 23 (92 B); 11069 limbs: fixed 88552 B vs varint 105063 B |
| synthetic 2^20 | WHIR 1/16 k=4 pow=20 | 2^20 | 2^20 | 85929 | — | 4992 | 80892 | 13282.4 | 332.094 | 332.094 | 10.651 | 128.04 | 128.04 | t=[55 32 22] siblings 1439 (full paths 2104, dedup saves 21280 B); u32 prefixes 23 (92 B); 10713 limbs: fixed 85704 B vs varint 101728 B |
| synthetic 2^20 | WHIR 1/16 k=4 pow=24 | 2^20 | 2^20 | 81673 | — | 4992 | 76636 | 27546.2 | 359.430 | 359.430 | 8.944 | 128.01 | 128.01 | t=[53 30 21] siblings 1350 (full paths 2008, dedup saves 21056 B); u32 prefixes 23 (92 B); 10181 limbs: fixed 81448 B vs varint 96594 B |
| synthetic 2^20 | WHIR 1/16 k=2 pow=16 | 2^20 | 2^20 | 132749 | — | 4992 | 127712 | 18668.1 | 367.138 | 367.138 | 21.247 | 128.01 | 128.01 | t=[58 46 38 33 29 26] siblings 3188 (full paths 4593, dedup saves 44960 B); u32 prefixes 44 (176 B); 16554 limbs: fixed 132432 B vs varint 157143 B |
| synthetic 2^20 | WHIR 1/16 k=3 pow=16 | 2^20 | 2^20 | 97733 | — | 4992 | 92696 | 15504.9 | 335.539 | 335.539 | 15.041 | 128.01 | 128.01 | t=[58 38 29 23] siblings 2017 (full paths 2943, dedup saves 29632 B); u32 prefixes 30 (120 B); 12184 limbs: fixed 97472 B vs varint 115681 B |
| synthetic 2^20 | WHIR 1/16 k=4 pow=16 | 2^20 | 2^20 | 88777 | — | 4992 | 83740 | 13138.2 | 363.121 | 363.121 | 12.445 | 128.22 | 128.22 | t=[58 33 23] siblings 1492 (full paths 2201, dedup saves 22688 B); u32 prefixes 23 (92 B); 11069 limbs: fixed 88552 B vs varint 105063 B |
| synthetic 2^20 | WHIR 1/16 k=5 pow=16 | 2^20 | 2^20 | 100049 | — | 4992 | 95012 | 12206.7 | 360.191 | 360.191 | 12.594 | 128.01 | 128.01 | t=[58 29 19] siblings 1295 (full paths 1947, dedup saves 20864 B); u32 prefixes 23 (92 B); 12475 limbs: fixed 99800 B vs varint 118378 B |
| synthetic 2^20 | WHIR 1/16 k=6 pow=16 | 2^20 | 2^20 | 112237 | — | 4992 | 107200 | 11180.8 | 361.367 | 361.367 | 12.935 | 128.28 | 128.28 | t=[58 26] siblings 956 (full paths 1486, dedup saves 16960 B); u32 prefixes 16 (64 B); 14006 limbs: fixed 112048 B vs varint 132911 B |
| synthetic 2^20 | WHIR 1/2 k=4 pow=16 | 2^20 | 2^20 | 162921 | — | 4992 | 157884 | 9858.8 | 368.268 | 368.268 | 25.130 | 128.05 | 128.05 | t=[231 57 33] siblings 2709 (full paths 5334, dedup saves 84000 B); u32 prefixes 23 (92 B); 20337 limbs: fixed 162696 B vs varint 192999 B |
| synthetic 2^20 | WHIR 1/4 k=4 pow=16 | 2^20 | 2^20 | 117897 | — | 4992 | 112860 | 9984.2 | 369.412 | 369.412 | 17.226 | 128.01 | 128.01 | t=[115 46 29] siblings 1946 (full paths 3316, dedup saves 43840 B); u32 prefixes 23 (92 B); 14709 limbs: fixed 117672 B vs varint 139776 B |
| synthetic 2^20 | WHIR 1/8 k=4 pow=16 | 2^20 | 2^20 | 99721 | — | 4992 | 94684 | 11087.7 | 354.789 | 354.789 | 13.669 | 128.08 | 128.08 | t=[77 38 26] siblings 1662 (full paths 2589, dedup saves 29664 B); u32 prefixes 23 (92 B); 12437 limbs: fixed 99496 B vs varint 118115 B |
| synthetic 2^20 | WHIR 1/16 k=4 pow=16 | 2^20 | 2^20 | 88777 | — | 4992 | 83740 | 12588.1 | 359.980 | 359.980 | 12.398 | 128.22 | 128.22 | t=[58 33 23] siblings 1492 (full paths 2201, dedup saves 22688 B); u32 prefixes 23 (92 B); 11069 limbs: fixed 88552 B vs varint 105063 B |
| synthetic 2^20 | WHIR 1/32 k=4 pow=16 | 2^20 | 2^20 | 80969 | — | 4992 | 75932 | 17295.5 | 358.142 | 358.142 | 11.157 | 128.01 | 128.01 | t=[46 29 21] siblings 1368 (full paths 1945, dedup saves 18464 B); u32 prefixes 23 (92 B); 10093 limbs: fixed 80744 B vs varint 95886 B |

| lever | measured effect | status |
|---|---|---|
| Merkle path deduplication across queries | lens already sends only the siblings the verifier cannot recompute (`rspcs/src/merkle.rs`); against full per-query paths it saves 10.7 KB of 28.6 KB at hash.tri and 22.7 KB at `2^20` (column `dedup saves`) | already in lens; nothing to add |
| grinding 16 → 20 → 24 | `2^10`: 17,937 → 16,913 → 17,457 B (one round; query count 57 → 55 → 53, the leaf mix moves the bytes); `2^20`: 88,777 → 85,929 → 81,673 B (−8 %); prover time grows with `2^pow` | taken: 24 |
| folding factor 2 … 6 | `2^10`: 20,689 / 16,897 / 17,937 / 22,593 / 33,329 B; `2^20`: 132,749 / 97,733 / 88,777 / 100,049 / 112,237 B | 3 at `2^10`, 4 above; with rate 1/64 + grinding 4 wins everywhere (§3) |
| rate 1/2 … 1/32 | `2^10`: 20,809 / 19,345 / 18,961 / 17,937 / 16,625 B; `2^20`: 162,921 / 117,897 / 99,721 / 88,777 / 80,969 B | taken: 1/64 after §3 |
| fixed 8-byte limbs vs LEB128 varints | every field element and digest limb as a varint is **larger**: 21,064 vs 17,880 B at hash.tri, 105,063 vs 88,552 B at `2^20` (+18 %) — challenge-field and hash outputs are uniform below `p ≈ 2^64`, so most need 9–10 varint bytes | rejected: fixed limbs stay |
| lens u32 length prefixes | every one is implied by the parameters and the size; 9 prefixes (36 B) at `2^10`, 23 (92 B) at `2^20` | not taken: < 0.2 %, needs a lens wire change |
| Spartan round compression (drop `c_1`) | in from the start: saves `(log m + ℓ + 1)` × 24 B = 504 B at hash.tri, 984 B at `2^20` | taken |
| zip (eprint 2025/1446) | — | **not done**: not implemented in this package; no number is claimed |

## 3. levers combined

Command: `… succinct_bakeoff -- combos 1` (rates 1/16, 1/32, 1/64 × k 3, 4, 5
× grinding 16, 20 × final variables 8, 6, 4), then `grind-small 1` and
`grind 1` (rates 1/32, 1/64 × grinding 20, 24, k = 4). The five smallest per
fixture; sizes deterministic, times single runs under load.

| fixture | pcs | n (committed) | rows | proof B | envelope B | spartan B | opening B | prove ms | verify ms | vfy-rel ms | pcs vfy ms | pcs bits | total bits | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| hash.tri | WHIR 1/64 k=4 pow=20 fin=6 | 2^10 | 2^10 | 16113 | 16340 | 2592 | 13476 | 685.0 | 6.420 | 2.974 | 2.236 | 128.11 | 128.11 |  |
| hash.tri | WHIR 1/64 k=4 pow=20 fin=8 | 2^10 | 2^10 | 16145 | 16372 | 2592 | 13508 | 51.3 | 7.711 | 3.601 | 2.210 | 128.11 | 128.11 |  |
| hash.tri | WHIR 1/32 k=4 pow=20 fin=8 | 2^10 | 2^10 | 16177 | 16404 | 2592 | 13540 | 760.0 | 7.137 | 3.297 | 2.165 | 128.05 | 128.05 |  |
| hash.tri | WHIR 1/64 k=4 pow=16 fin=8 | 2^10 | 2^10 | 16337 | 16564 | 2592 | 13700 | 80.2 | 7.208 | 3.618 | 2.365 | 128.08 | 128.08 |  |
| hash.tri | WHIR 1/64 k=4 pow=16 fin=6 | 2^10 | 2^10 | 16529 | 16756 | 2592 | 13892 | 56.6 | 7.802 | 3.643 | 2.329 | 128.08 | 128.08 |  |
| chain-11 (hemera) | WHIR 1/64 k=4 pow=20 fin=8 | 2^15 | 2^15 | 43293 | 44205 | 3792 | 39456 | 2007.8 | 142.608 | 14.372 | 5.951 | 128.11 | 128.11 |  |
| chain-11 (hemera) | WHIR 1/64 k=4 pow=16 fin=8 | 2^15 | 2^15 | 44189 | 45101 | 3792 | 40352 | 982.9 | 149.198 | 14.410 | 6.045 | 128.08 | 128.08 |  |
| chain-11 (hemera) | WHIR 1/32 k=4 pow=20 fin=8 | 2^15 | 2^15 | 45373 | 46285 | 3792 | 41536 | 2182.4 | 139.504 | 14.076 | 6.325 | 128.05 | 128.05 |  |
| chain-11 (hemera) | WHIR 1/32 k=4 pow=16 fin=8 | 2^15 | 2^15 | 47101 | 48013 | 3792 | 43264 | 665.2 | 139.564 | 13.496 | 5.790 | 128.01 | 128.01 |  |
| chain-11 (hemera) | WHIR 1/16 k=4 pow=20 fin=8 | 2^15 | 2^15 | 49373 | 50285 | 3792 | 45536 | 2809.7 | 133.313 | 15.137 | 6.090 | 128.01 | 128.01 |  |
| synthetic 2^16 | WHIR 1/64 k=4 pow=20 fin=8 | 2^16 | 2^16 | 48173 | — | 4032 | 44096 | 2028.9 | 15.190 | 15.190 | 6.395 | 128.11 | 128.11 |  |
| synthetic 2^16 | WHIR 1/64 k=4 pow=16 fin=8 | 2^16 | 2^16 | 49805 | — | 4032 | 45728 | 1582.2 | 17.375 | 17.375 | 6.261 | 128.08 | 128.08 |  |
| synthetic 2^16 | WHIR 1/32 k=4 pow=20 fin=8 | 2^16 | 2^16 | 51565 | — | 4032 | 47488 | 1089.1 | 17.897 | 17.897 | 7.035 | 128.05 | 128.05 |  |
| synthetic 2^16 | WHIR 1/64 k=5 pow=20 fin=8 | 2^16 | 2^16 | 52829 | — | 4032 | 48752 | 1452.8 | 17.087 | 17.087 | 6.470 | 128.08 | 128.08 |  |
| synthetic 2^16 | WHIR 1/64 k=5 pow=20 fin=6 | 2^16 | 2^16 | 52925 | — | 4032 | 48848 | 2161.9 | 16.564 | 16.564 | 6.459 | 128.08 | 128.08 |  |
| synthetic 2^20 | WHIR 1/64 k=4 pow=20 fin=8 | 2^20 | 2^20 | 74153 | — | 4992 | 69116 | 28444.2 | 244.778 | 244.778 | 9.705 | 128.11 | 128.11 |  |
| synthetic 2^20 | WHIR 1/64 k=4 pow=16 fin=8 | 2^20 | 2^20 | 77097 | — | 4992 | 72060 | 26043.9 | 245.811 | 245.811 | 9.992 | 128.50 | 128.50 |  |
| synthetic 2^20 | WHIR 1/32 k=4 pow=20 fin=8 | 2^20 | 2^20 | 78249 | — | 4992 | 73212 | 19630.4 | 268.880 | 268.880 | 10.837 | 128.01 | 128.01 |  |
| synthetic 2^20 | WHIR 1/32 k=4 pow=16 fin=8 | 2^20 | 2^20 | 80969 | — | 4992 | 75932 | 17412.1 | 245.429 | 245.429 | 11.168 | 128.01 | 128.01 |  |
| synthetic 2^20 | WHIR 1/64 k=5 pow=20 fin=6 | 2^20 | 2^20 | 81041 | — | 4992 | 76004 | 37082.3 | 261.189 | 261.189 | 8.306 | 128.08 | 128.08 |  |

Grinding 24 at the two best rates:

| fixture | pcs | n (committed) | rows | proof B | envelope B | spartan B | opening B | prove ms | verify ms | vfy-rel ms | pcs vfy ms | pcs bits | total bits | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| hash.tri | WHIR 1/32 k=4 pow=20 fin=8 | 2^10 | 2^10 | 16177 | 16404 | 2592 | 13540 | 754.5 | 8.091 | 3.719 | 2.309 | 128.05 | 128.05 | t=[44] siblings 195 (full paths 473, dedup saves 8896 B); u32 prefixes 9 (36 B); 2015 limbs: fixed 16120 B vs varint 18985 B |
| hash.tri | WHIR 1/32 k=4 pow=24 fin=8 | 2^10 | 2^10 | 16369 | 16596 | 2592 | 13732 | 9815.4 | 8.230 | 3.765 | 2.309 | 128.03 | 128.03 | t=[42] siblings 204 (full paths 462, dedup saves 8256 B); u32 prefixes 9 (36 B); 2035 limbs: fixed 16280 B vs varint 19154 B |
| hash.tri | WHIR 1/64 k=4 pow=20 fin=8 | 2^10 | 2^10 | 16145 | 16372 | 2592 | 13508 | 54.8 | 7.963 | 3.644 | 2.291 | 128.11 | 128.11 | t=[37] siblings 218 (full paths 444, dedup saves 7232 B); u32 prefixes 9 (36 B); 2011 limbs: fixed 16088 B vs varint 18948 B |
| hash.tri | WHIR 1/64 k=4 pow=24 fin=8 | 2^10 | 2^10 | 15921 | 16148 | 2592 | 13284 | 1623.3 | 6.721 | 2.935 | 2.020 | 128.00 | 128.00 | t=[35] siblings 218 (full paths 420, dedup saves 6464 B); u32 prefixes 9 (36 B); 1979 limbs: fixed 15832 B vs varint 18643 B |
| chain-11 (hemera) | WHIR 1/32 k=4 pow=20 fin=8 | 2^15 | 2^15 | 45373 | 46285 | 3792 | 41536 | 2053.1 | 140.405 | 13.635 | 5.803 | 128.05 | 128.05 | t=[44 28] siblings 672 (full paths 1124, dedup saves 14464 B); u32 prefixes 16 (64 B); 5656 limbs: fixed 45248 B vs varint 53126 B |
| chain-11 (hemera) | WHIR 1/32 k=4 pow=24 fin=8 | 2^15 | 2^15 | 44285 | 45197 | 3792 | 40448 | 35305.2 | 144.238 | 13.511 | 6.043 | 128.03 | 128.03 | t=[42 27] siblings 658 (full paths 1077, dedup saves 13408 B); u32 prefixes 16 (64 B); 5520 limbs: fixed 44160 B vs varint 51802 B |
| chain-11 (hemera) | WHIR 1/64 k=4 pow=20 fin=8 | 2^15 | 2^15 | 43293 | 44205 | 3792 | 39456 | 1985.2 | 151.503 | 13.217 | 5.976 | 128.11 | 128.11 | t=[37 25] siblings 670 (full paths 1029, dedup saves 11488 B); u32 prefixes 16 (64 B); 5392 limbs: fixed 43136 B vs varint 50652 B |
| chain-11 (hemera) | WHIR 1/64 k=4 pow=24 fin=8 | 2^15 | 2^15 | 41405 | 42317 | 3792 | 37568 | 36434.8 | 149.072 | 14.155 | 5.644 | 128.00 | 128.00 | t=[35 24] siblings 631 (full paths 979, dedup saves 11136 B); u32 prefixes 16 (64 B); 5156 limbs: fixed 41248 B vs varint 48368 B |
| synthetic 2^16 | WHIR 1/32 k=4 pow=20 fin=8 | 2^16 | 2^16 | 51565 | — | 4032 | 47488 | 1127.7 | 18.520 | 18.520 | 7.058 | 128.05 | 128.05 | t=[44 28] siblings 761 (full paths 1196, dedup saves 13920 B); u32 prefixes 16 (64 B); 6426 limbs: fixed 51408 B vs varint 60963 B |
| synthetic 2^16 | WHIR 1/32 k=4 pow=24 fin=8 | 2^16 | 2^16 | 50029 | — | 4032 | 45952 | 8644.3 | 17.809 | 17.809 | 6.757 | 128.03 | 128.03 | t=[42 27] siblings 733 (full paths 1146, dedup saves 13216 B); u32 prefixes 16 (64 B); 6234 limbs: fixed 49872 B vs varint 59086 B |
| synthetic 2^16 | WHIR 1/64 k=4 pow=20 fin=8 | 2^16 | 2^16 | 48173 | — | 4032 | 44096 | 2120.1 | 18.838 | 18.838 | 6.589 | 128.11 | 128.11 | t=[37 25] siblings 719 (full paths 1091, dedup saves 11904 B); u32 prefixes 16 (64 B); 6002 limbs: fixed 48016 B vs varint 56963 B |
| synthetic 2^16 | WHIR 1/64 k=4 pow=24 fin=8 | 2^16 | 2^16 | 47245 | — | 4032 | 43168 | 39846.0 | 21.339 | 21.339 | 6.339 | 128.00 | 128.00 | t=[35 24] siblings 710 (full paths 1038, dedup saves 10496 B); u32 prefixes 16 (64 B); 5886 limbs: fixed 47088 B vs varint 55881 B |
| synthetic 2^20 | WHIR 1/32 k=4 pow=20 fin=8 | 2^20 | 2^20 | 78249 | — | 4992 | 73212 | 19702.5 | 231.956 | 231.956 | 9.061 | 128.01 | 128.01 | t=[44 28 20] siblings 1315 (full paths 1864, dedup saves 17568 B); u32 prefixes 23 (92 B); 9753 limbs: fixed 78024 B vs varint 92614 B |
| synthetic 2^20 | WHIR 1/32 k=4 pow=24 fin=8 | 2^20 | 2^20 | 76521 | — | 4992 | 71484 | 61135.6 | 226.861 | 226.861 | 8.672 | 128.15 | 128.15 | t=[43 27 20] siblings 1277 (full paths 1823, dedup saves 17472 B); u32 prefixes 23 (92 B); 9537 limbs: fixed 76296 B vs varint 90446 B |
| synthetic 2^20 | WHIR 1/64 k=4 pow=20 fin=8 | 2^20 | 2^20 | 74153 | — | 4992 | 69116 | 43245.4 | 230.922 | 230.922 | 9.496 | 128.11 | 128.11 | t=[37 25 19] siblings 1263 (full paths 1719, dedup saves 14592 B); u32 prefixes 23 (92 B); 9241 limbs: fixed 73928 B vs varint 87632 B |
| synthetic 2^20 | WHIR 1/64 k=4 pow=24 fin=8 | 2^20 | 2^20 | 71081 | — | 4992 | 66044 | 78916.4 | 232.178 | 232.178 | 8.018 | 128.24 | 128.24 | t=[36 24 18] siblings 1195 (full paths 1656, dedup saves 14752 B); u32 prefixes 23 (92 B); 8857 limbs: fixed 70856 B vs varint 84137 B |

(The `2^20` grinding rows were measured while the zheng test suite ran concurrently; their times are noisier than the rest, their sizes are exact.)

## 4. decision

Rule (work package): per class, the smallest proof with ≥ 128 proven bits.

| class | winner | hash.tri | chain-11 (`2^15`) | synthetic `2^16` | synthetic `2^20` |
|---|---|---|---|---|---|
| small (`ℓ ≤ 16`) | **WHIR, rate 1/64, k = 4, grinding 24, final ≤ 2^8** | 15,921 B proof · 16,148 B envelope | 41,405 B proof · 42,317 B envelope | 47,245 B | — |
| large (`ℓ > 16`) | **the same** | — | — | — | 71,081 B |

Within the small class TensorRs still wins at `2^4` (add.tri: 1,425 B against
5,607 B for the shipped WHIR parameters); the class winner is the scheme that is
smallest on the class's statements that matter (hash.tri, the hash chain, the
`2^14`/`2^16` relations) and in total. Both classes chose the same
configuration; it is shipped as
`succinct::params_for` / `prove_default` and used by `joy prove --succinct`.
TensorRs loses every size above `2^4` and is the bake-off loser (proposal §7:
deleted in phase 5; it stays decodable under id 2 until then). Grinding 24
costs prover time: a proof takes seconds at `2^10` and 40–90 s at `2^15`–`2^20`
(§3 and the table below). Grinding 20 gives +224 B at hash.tri, +3.1 KB at
`2^20` for a fraction of that time; the rule as stated picks 24.

Shipped choice on every fixture (command `… -- chosen 3`, load 11.3 at the start, 19.0 at the end):

| fixture | pcs | n (committed) | rows | proof B | envelope B | spartan B | opening B | prove ms | verify ms | vfy-rel ms | pcs vfy ms | pcs bits | total bits | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| add.tri | WHIR 1/64 k=4 pow=24 fin=8 (small) | 2^4 | 2^4 | 5433 | 5607 | 624 | 4764 | 265.0 | 1.235 | 1.208 | 0.772 | 128.00 | 128.00 | t=[35] siblings 24 (full paths 174, dedup saves 4800 B); u32 prefixes 9 (36 B); 672 limbs: fixed 5376 B vs varint 6336 B |
| hash.tri | WHIR 1/64 k=4 pow=24 fin=8 (small) | 2^10 | 2^10 | 15921 | 16148 | 2592 | 13284 | 1727.8 | 7.955 | 3.647 | 2.134 | 128.00 | 128.00 | t=[35] siblings 218 (full paths 420, dedup saves 6464 B); u32 prefixes 9 (36 B); 1979 limbs: fixed 15832 B vs varint 18643 B |
| chain-11 (hemera) | WHIR 1/64 k=4 pow=24 fin=8 (small) | 2^15 | 2^15 | 41405 | 42317 | 3792 | 37568 | 36313.4 | 142.290 | 13.300 | 5.343 | 128.00 | 128.00 | t=[35 24] siblings 631 (full paths 979, dedup saves 11136 B); u32 prefixes 16 (64 B); 5156 limbs: fixed 41248 B vs varint 48368 B |
| synthetic 2^10 | WHIR 1/64 k=4 pow=24 fin=8 (small) | 2^10 | 2^10 | 15441 | — | 2592 | 12804 | 1353.0 | 2.796 | 2.796 | 2.123 | 128.00 | 128.00 | t=[35] siblings 203 (full paths 420, dedup saves 6944 B); u32 prefixes 9 (36 B); 1919 limbs: fixed 15352 B vs varint 18177 B |
| synthetic 2^14 | WHIR 1/64 k=4 pow=24 fin=8 (small) | 2^14 | 2^14 | 38189 | — | 3552 | 34592 | 6134.6 | 7.370 | 7.370 | 5.183 | 128.00 | 128.00 | t=[35 24] siblings 586 (full paths 920, dedup saves 10688 B); u32 prefixes 16 (64 B); 4754 limbs: fixed 38032 B vs varint 45135 B |
| synthetic 2^16 | WHIR 1/64 k=4 pow=24 fin=8 (small) | 2^16 | 2^16 | 47245 | — | 4032 | 43168 | 37906.1 | 17.814 | 17.814 | 5.330 | 128.00 | 128.00 | t=[35 24] siblings 710 (full paths 1038, dedup saves 10496 B); u32 prefixes 16 (64 B); 5886 limbs: fixed 47088 B vs varint 55881 B |
| synthetic 2^18 | WHIR 1/64 k=4 pow=24 fin=8 (large) | 2^18 | 2^18 | 61545 | — | 4512 | 56988 | 34219.9 | 65.954 | 65.954 | 8.396 | 128.00 | 128.00 | t=[35 24 18] siblings 1060 (full paths 1480, dedup saves 13440 B); u32 prefixes 23 (92 B); 7665 limbs: fixed 61320 B vs varint 72711 B |
| synthetic 2^20 | WHIR 1/64 k=4 pow=24 fin=8 (large) | 2^20 | 2^20 | 71081 | — | 4992 | 66044 | 60263.8 | 270.499 | 270.499 | 9.842 | 128.24 | 128.24 | t=[36 24 18] siblings 1195 (full paths 1656, dedup saves 14752 B); u32 prefixes 23 (92 B); 8857 limbs: fixed 70856 B vs varint 84137 B |

## 5. against the goals

| goal (proposal §0) | measured | verdict |
|---|---|---|
| small ≤ 16 KB stretch / ≤ 20 KB | hash.tri: **15,921 B proof, 16,148 B envelope** (15.77 KiB); the envelope is under 16 KiB (16,384 B) and over 16.0 kB (16,000 B) | ≤ 20 KB met; 16 KB met in KiB, missed by 148 B in kB |
| large `n = 2^20` ≤ 64 KB | **71,081 B** (69.4 KiB) | missed by 7.1 KB (11 %) |
| verify ≤ 1 ms | shipped choice (§4 table): hash.tri 7.96 ms = relation compile 4.3 + Spartan 1.5 + opening 2.1; `2^20` 270 ms = Spartan ~260 + opening 9.8 | **missed** at every size above add.tri (1.2 ms) |
| ≥ 128 bits proven | 128.00 (hash.tri) … 128.24 (`2^20`), PCS-limited; Spartan ≤ 2^-184 | met |

The verify-time miss has three separate causes, measured separately above:
(1) the opening — Merkle paths and WHIR's checks in hemera, 2.1 ms at hash.tri
and 9.8 ms at `2^20` (≈ 480 and 2,200 permutations at lens's measured
4.43 µs each); the 1 ms goal needs hemera ~2–10× faster (being optimised
separately); (2) the
Spartan verifier evaluates `Σ γ^i M̃_i(ρ_x, r)` over every nonzero of an
unstructured relation — `O(nnz + n)` Fp3 work, ~1.5 ms at `2^10` and ~260 ms
at `2^20` — which only a structured (uniform-step) relation or a sparse-matrix
commitment removes (phase 3); (3) recompiling the relation from the program
(4.3 ms for hash.tri, 129 ms for chain-11), which a cached `vk` digest would
skip. None of the three is hidden in the numbers above.

For scale: the public v3 certificate of the same hash.tri statement is
6,463 B (joy CLI test), because the 810 free witness values travel as varints
and are checked directly. At `2^10` a committed witness is larger than a
disclosed one; the succinct profile pays off from ~`2^12` on and is the only
option when the witness must not travel (and, with VEIL in phase 4, when it
must stay hidden).

## 6. soundness tests

- completeness on add.tri (two inputs), hash.tri (two inputs), chain-11 and
  synthetic `2^10` under both schemes; state statements under WHIR;
- forged input, output, extra output, cycles (±1), budget and program are
  rejected; a valid proof of each of five statements verifies only for its
  own statement (25 pairs); tampered `w̃(r')`, every matrix evaluation, an
  outer and an inner round, the root and the parameters are rejected; a
  zeroed constant pin and a moved output pin are rejected;
- parameters below policy are refused by prover and verifier (a target of 96
  or 100, and any set with < 128 proven bits at the proof's `ℓ`);
- state: a wrong read value, a missing read, a forged statement with a
  matching forged certificate, each of four root limbs, and the context;
- determinism: identical envelopes from repeated proving under both schemes;
- **bit-flip scan** over the full serialized envelope of hash.tri (input 7),
  every bit of every byte flipped and decoded + verified:
  WHIR (lens defaults, 18,164 B): **145,312 flips, 0 accepted**; TensorRs
  (lens defaults, 24,974 B): **199,792 flips, 0 accepted** (328.6 s for both
  on 16 cores; `tests/succinct_bitflip.rs`, the TensorRs scan is `--ignored`
  by default).

Test commands: `cargo test --release -p zheng` and `--features serde` (all
green, 189 / 193 library tests plus integration suites), joy `cargo test
--workspace --release --locked` (green).

## 7. not done

- zip (eprint 2025/1446): not implemented; no gain is claimed.
- Spartan outer-round trick that sends the round polynomial without its
  `eq(τ, ·)` factor (one Fp3 coefficient per outer round, ~240 B at `2^10`):
  not done — it changes the IOP transcript shared with the retired v2 reader.
- lens wire: the implied u32 length prefixes stay (≤ 92 B).
- the 64 KB large-class goal and the 1 ms verify goal (§5).
- a Merkle-32 path fixture: none exists; a 32-hash chain exceeds the relation
  compiler's 32,768-row cap (chain-11 measured instead).
- state statements in `joy prove --succinct`: the CLI refuses `--state`;
  zheng proves and verifies succinct state statements (`succinct::prove_state`
  / `verify_state`, envelope profile 1 kind 1) but joy's `JOYST002` wraps only
  the profile-3 envelope.
