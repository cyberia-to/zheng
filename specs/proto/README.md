# proto — zheng's IOP as zippel protocols

Executable specs of the IOP in `rs/src/spartan` and `rs/src/sumcheck`, written for
[eniac/zippel](https://github.com/eniac/zippel) so that the transcript is derived
from the choreography and the completeness and special-soundness analyses can run
on it. Background and the verdict: [docs/explanation/zippel.md](../../docs/explanation/zippel.md);
results: [audit/zippel-2026-10-24.md](../../audit/zippel-2026-10-24.md).

| protocol | what | sizes |
|---|---|---|
| `zheng_spartan` | the whole IOP, CCS matrices as instance inputs (dense, row-major), the lens as an oracle | `LM` = log rows, `NV` = log columns |
| `zheng_spartan_fixed` | the same with the CCS fixed as constants of the pattern (as in the legacy universal CCS, which is fixed) — the analysable form | `LM = NV = 2` |
| `zheng_outer` | the outer sumcheck alone: eq(τ,·)·(a·b − c), degree 3, four points, the matrix_evals check | `LM` |
| `zheng_inner` | the inner sumcheck alone: ⟨w, z⟩ as a product of two multilinears, degree 2, three points, the closing check and the oracle opening | `NV` |
| `zheng_bug` | `zheng_spartan_fixed` with the outer round polynomial sent as three points instead of four — a deliberate bug the analysis must catch | `LM = NV = 2` |

Oracle model: the lens is replaced by the verifier evaluating ẑ itself, so `z` is
`instance`. The analyses cover the IOP; the commitment's binding stays with the lens.

Scope: these protocols were written on 2026-10-24 against master's 0.3 IOP — an
R1CS-shaped outer sumcheck (`a·b − c`, degree 3) with the legacy Brakedown opening
behind the oracle. The shipped IOP (`spartan::iop`, envelope profiles 1 and 2) runs
the same outer/inner structure over CCS rows up to degree 7, with Fp3 challenges and
a WHIR opening. The oracle model makes the PCS irrelevant to the analyses; the degree
and the challenge field are not re-cut here yet, and zippel has no Goldilocks backend
(audit/zippel-2026-10-24.md).

## run

zippel is not a dependency of zheng. It is checked out once, built on its own pinned
nightly, and these directories are copied into its `examples/`:

```sh
git clone https://github.com/eniac/zippel ~/.cache/cyber/zippel
cd ~/.cache/cyber/zippel
for p in zheng_spartan zheng_spartan_fixed zheng_outer zheng_inner zheng_bug; do cp -r ~/cyber/zheng/specs/proto/$p examples/; done
# register each in examples/registry.rs (a `#[path]` module line and an entry in `with_examples!`)
PATH="$HOME/.cargo/bin:$PATH" cargo build --release -p zippel --example zippel   # rustup's cargo honours rust-toolchain.toml
Z=target/release/examples/zippel
$Z run zheng_spartan_fixed --size LM=2 --size NV=2
$Z analyze zheng_spartan_fixed completeness --size LM=2 --size NV=2
$Z analyze zheng_inner soundness --size NV=2
```

`cargo build -p check` gives `zippel-check` for a type check without a harness:
`target/release/zippel-check --size LM=2 --size NV=2 specs/proto/zheng_spartan/zheng_spartan.zippel`.
The Singular backend (`brew install singular`, `--backend singular`) lifts ark-gb's
1,023-variable limit.

## what maps to what

| zheng | zippel |
|---|---|
| `transcript.absorb_commitment` | nothing: `z` is instance, bound into the domain separator |
| `squeeze_challenges(log_m)` → τ | `draw_taus` (one `challenge<F>` per coordinate) |
| `OuterSumcheckProver::round_poly` (degree + 2 points), `absorb_sumcheck_poly`, `squeeze_challenge` | `evs <- [round_poly(t) for t in pts3]`, `r <- challenge<F>` |
| `matrix_evals`, `absorb_eval` ×3 | `v_a <- …`, `v_b <- …`, `v_c <- …` |
| `eq_val · constraint_val == outer_final_claim` | `verify(e_x == (v_a·v_b − v_c)·eq_tau_at_rx)` |
| γ, `batched_claim = Σ γ^i v_i` | `gamma <- challenge<F>`, `t2` |
| `w_combined`, `SumcheckProver` rounds | `w_comb`, `inner_round` |
| `final_claim == w_at_point · eval_value`, `absorb_eval(eval_value)` | `eval_value <- dot(ly, z)`, `verify(e_y == w_at_point · eval_value)` |
| the PCS opening (`Brakedown::verify` on 0.3; WHIR in the shipped IOP) | `verify(eval_value == dot(ly, z))` — the oracle |
