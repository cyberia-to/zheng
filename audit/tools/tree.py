#!/usr/bin/env python3
# tree.py <sample.txt> <min count> <max depth> — the main thread's call
# tree from macOS `sample <pid>` output, short names, nodes with at least
# <min count> samples down to <max depth> levels.
import sys, re
f = sys.argv[1]; minc = int(sys.argv[2]); maxd = int(sys.argv[3])
inmain = False
for l in open(f).read().split('\n'):
    if 'Thread_' in l:
        inmain = 'main-thread' in l
        continue
    if not inmain:
        continue
    m = re.match(r'^(\s*[+!:| ]*)(\d+) (.*)$', l)
    if not m:
        continue
    d = len(m.group(1)); c = int(m.group(2)); name = m.group(3)
    name = re.sub(r'\s+\(in .*', '', name); name = re.sub(r'::h[0-9a-f]{16}', '', name)
    name = re.sub(r'_\$LT\$', '<', name).replace('$GT$', '>').replace('$u20$', ' ').replace('..', '::')
    lvl = (d - 5) // 2
    if c >= minc and lvl <= maxd:
        print('  ' * lvl + f'{c} {name[:150]}')
