# Independent recomputation of the rebalanced field-native WHIR ledgers
# (WHIR eprint 2024/1586 Thm 5.2/7.5, Lemma 4.25; BCGM 2025/2051 Lemma 9.3),
# from the round specs alone; compare with zheng's printed rows.
import math
P = 2**64 - 2**32 + 1
K = 3 * math.log2(P)
def lg_add(a, b):
    if a == -math.inf: return b
    if b == -math.inf: return a
    hi, lo = max(a, b), min(a, b)
    return hi + math.log2(1 + 2 ** (lo - hi))
def prox(m, r):  # Johnson(m)
    return (-r / 2 + math.log2(1 + 1 / (2 * m)), math.log2(m) + r)
def mca(m, r, logn):
    return 7 * math.log2(m + .5) - math.log2(3) + 1.5 * r + 2 * logn - K
def fold_err(m, r, logn, k):
    lst = math.log2(3) + prox(m, r)[1] - K
    return max(lg_add(lst, mca(m, r, logn - s)) for s in range(1, k + 1))
def ood_err(lst, mv, s):
    return 2 * lst - 1 + s * (mv - K)
# rounds: (num_vars, fold, r, log_domain, m, ood, queries, qpow, fpow)
def terms(rounds, inputs, claims, comb_pow):
    out = {}
    r0 = rounds[0]
    l0 = prox(r0[4], r0[2])[1]
    if claims > 1: out['batch γ'] = K - l0 - math.log2(claims - 1)
    if inputs > 1:
        out['batch sumcheck'] = K - l0 - 1
        d = math.log2(inputs - 1)
        ce = lg_add(mca(r0[4], r0[2], r0[3]) + d, l0 + d - K)
        out['batch combine'] = -ce + comb_pow
    for i, (mv, k, r, logn, m, ood, t, qp, fp) in enumerate(rounds):
        lom, lst = prox(m, r)
        out[f'ood_{i}'] = -ood_err(lst, mv, ood)
        if i == 0 and ood > 0: out['comb_0'] = K - lst - math.log2(ood)
        if i > 0:
            pv = rounds[i - 1]
            plom = prox(pv[4], pv[2])[0]
            e = lg_add(pv[6] * plom, lst + math.log2(pv[6] + ood) - K)
            out[f'shift_{i}'] = -e + pv[7]
        out[f'fold_{i}'] = -fold_err(m, r, logn, k) + fp
    last = rounds[-1]
    out['fin'] = -(last[6] * prox(last[4], last[2])[0]) + last[7]
    return out
levels = {
 # name: (rounds, inputs, claims, comb_pow) — specs as printed by the review test
 'final 1/512': ([(20,4,9,29,5,1,24,24,22),(16,4,12,28,4,1,18,24,22),(12,4,15,27,3,1,14,27,22)], 1, None, 0),
 'level 1 1/128': ([(21,4,7,28,5,1,31,24,17),(17,4,10,27,4,1,22,22,17),(13,4,13,26,3,1,17,22,17),(9,4,16,25,3,1,14,20,20)], 5, None, 21),
 'level 0 1/16': ([(22,4,4,26,7,1,58,18,11),(18,4,7,25,7,1,33,16,14),(14,4,10,24,4,1,23,17,11),(10,4,13,23,3,1,18,16,11)], 5, None, 15),
 'IVC decider 1/8': ([(21,4,3,24,13,1,77,17,12),(17,4,6,23,9,1,38,17,11),(13,4,9,22,7,1,26,14,11),(9,4,12,21,7,1,19,16,13)], 3, 88+2, 15),
}
for name, (rounds, inputs, claims, comb) in levels.items():
    t = terms(rounds, inputs, claims or 2, comb)
    w = min(t, key=t.get)
    print(f'{name}: weakest {w} {t[w]:.2f}; ' + ' '.join(f'{k} {v:.2f}' for k, v in t.items() if v < 140))
