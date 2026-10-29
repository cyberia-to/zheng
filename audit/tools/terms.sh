#!/bin/sh
# terms.sh — grep sweep of a zheng checkout for banned and stale terms. Prints counts and hits.
# usage: terms.sh <zheng-dir>
d="$1"
cd "$d" || exit 2
inc="--include=*.md --include=*.rs --include=*.toml --include=*.yml"
ex="--exclude-dir=target --exclude-dir=.git"
for pat in 'STARK' 'Brakedown' '2 KB' '2 KiB' '100 ns' 'sub-millisecond' '0\.3\.3' 'CLAUDE\.md' '\[\[tape\]\]' 'package = "tape"|tape::' 'release/0\.4' 'HyperNova' 'Merkle-free' 'no AIR'; do
  n=$(grep -rnE $inc $ex -e "$pat" . | wc -l | tr -d ' ')
  echo "== $pat: $n"
done
