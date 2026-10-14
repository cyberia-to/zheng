#!/bin/bash
# joy_table.sh <fixture…> — `joy prove` in fresh processes per backend
# (median of RUNS, default 3), then `joy verify` once; one row per
# fixture × backend: prove ms as joy reports it, wall s, peak RSS MB, then
# artifact bytes, verify wall s and the artifact's SHA-1 prefix (equal
# across backends: proof bytes do not depend on the backend).
#
#   JOY       the joy binary (default: joy on PATH)
#   FIXTURES  directory of <name>.nox + <name>.inputs (profile 1) or
#             <name>.nox + <name>.secret (veil, profile 2); write them with
#             `FAST_DUMP=$FIXTURES fast_path <name>…` (rs/examples/fast_path)
#   OUT       scratch directory for artifacts (default: $FIXTURES)
#   BACKENDS  default "metal cpu webgpu"; BUDGET default 2^40
J=${JOY:-joy}
D=${FIXTURES:?FIXTURES: directory of .nox fixtures}
O=${OUT:-$D}
RUNS=${RUNS:-3}
BUDGET=${BUDGET:-1099511627776}
for f in "$@"; do
  if [ -f "$D/$f.secret" ]; then
    args=(--secret "$(cat "$D/$f.secret")")
  else
    args=(--succinct --input-values "$(cat "$D/$f.inputs")")
  fi
  for b in ${BACKENDS:-metal cpu webgpu}; do
    line="$f $b"
    for i in $(seq "$RUNS"); do
      out=$( { /usr/bin/time -l "$J" prove "$D/$f.nox" "${args[@]}" --budget "$BUDGET" --backend "$b" --output "$O/jt-$f-$b.zheng" --force; } 2>&1 )
      ms=$(echo "$out" | sed -nE 's/.*in ([0-9]+) ms on.*/\1/p')
      real=$(echo "$out" | awk '/ real /{print $1}')
      rss=$(echo "$out" | awk '/maximum resident/{printf "%.0f", $1/1048576}')
      bytes=$(echo "$out" | sed -nE 's/.*reductions, ([0-9]+) bytes.*/\1/p')
      line="$line | ${ms}ms ${real}s ${rss}MB"
    done
    v=$( { /usr/bin/time -p "$J" verify "$O/jt-$f-$b.zheng"; } 2>&1 | awk '/^real/{print $2}')
    echo "$line | ${bytes}B | verify ${v}s | sha $(shasum "$O/jt-$f-$b.zheng" | cut -c1-8)"
  done
done
