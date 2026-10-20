"""E8: cumulative share disclosure on the KeyLease schedule.

Theorem 2 assumes that fewer than t custodians ever deviate. This experiment
estimates how likely it is that an adversary who breaches custodian storage
episodically, and keeps what it reads, nevertheless accumulates t shares of
one epoch. It evaluates the generating-function bound of Theorem 3 on the
actual KeyLease schedule (daily epochs held by all n custodians, a commit
notice at the next hourly renewal, and a terminal epoch that stays readable
at breached custodians until revocation or the erasure horizon) and on the
measured placements of E5, and checks the bound in two independent ways:
exhaustive enumeration of the latent node/domain outcomes, and a
shared-history Monte Carlo simulation of the whole schedule.

Rates are declared sensitivity inputs, not measurements.
"""
import itertools
import json
import math

import numpy as np

from common import OUT, HOUR, DAY

YEAR = 365 * DAY
rng = np.random.default_rng(20261020)

PROVIDER = {"AWS Frankfurt": "AWS", "AWS Stockholm": "AWS", "AWS UAE": "AWS",
            "AWS Mumbai": "AWS", "AWS Virginia": "AWS", "AWS Tokyo": "AWS",
            "Hetzner Falkenstein": "Hetzner", "Hetzner Helsinki": "Hetzner",
            "Yandex Moscow": "Yandex"}
placements = {r["placement"]: (r["t"], r["endpoints"]) for r in
              json.load(open(OUT + "/e6_models.json"))["placements"]}
placements["B4 single custodian"] = (1, ["Hetzner Helsinki"])

# declared base rates (per year) and schedule
LAM_NODE = 0.2      # storage breach of one custodian
LAM_DOM = 0.05      # compelled or breached provider (reads all its custodians)
EPOCH = 1 * DAY     # rotation period
OVER = 1 * HOUR + 2 + 1   # commit notice at next renewal + 2 clock skews + prep
LEASE, HORIZON_H = 72 * HOUR, 30 * DAY


def pgf(nodes, doms, ell):
    """Coefficients of G(z) = prod_d [(1-q_d) prod_i (1-p_i+p_i z) + q_d z^h]
    for one epoch window of length ell (seconds)."""
    p = 1 - math.exp(-LAM_NODE * ell / YEAR)
    q = 1 - math.exp(-LAM_DOM * ell / YEAR)
    total = np.array([1.0])
    for d in sorted(set(doms)):
        h = sum(1 for x in doms if x == d)
        node = np.array([1.0])
        for _ in range(h):
            node = np.convolve(node, [1 - p, p])
        dom = (1 - q) * node
        dom[h] += q
        total = np.convolve(total, dom)
    return total


def tail(coef, k):
    return float(coef[max(k, 0):].sum()) if k > 0 else 1.0


def enumerate_exact(doms, ell, k):
    """P[X >= k] by enumeration of all node and domain outcomes."""
    p = 1 - math.exp(-LAM_NODE * ell / YEAR)
    q = 1 - math.exp(-LAM_DOM * ell / YEAR)
    ds = sorted(set(doms))
    n = len(doms)
    tot = 0.0
    for dv in itertools.product([0, 1], repeat=len(ds)):
        pd = math.prod(q if x else 1 - q for x in dv)
        hit = {d for d, x in zip(ds, dv) if x}
        for nv in itertools.product([0, 1], repeat=n):
            pn = math.prod(p if x else 1 - p for x in nv)
            read = sum(1 for i in range(n) if nv[i] or doms[i] in hit)
            if read >= k:
                tot += pd * pn
    return tot


def certificate(t, doms, f, final_window):
    """Union bound over one year of daily epochs plus the terminal epoch."""
    k = t - f
    r_epoch = tail(pgf(None, doms, EPOCH + OVER), k)
    r_final = tail(pgf(None, doms, final_window), k)
    return min(1.0, 365 * r_epoch + r_final), r_epoch, r_final


def simulate(t, doms, f, final_window, trials):
    """Shared-history Monte Carlo: Poisson reads over the whole horizon; an
    epoch is exposed if at least t-f distinct custodians are read inside its
    acquisition window. Adjacent windows overlap by OVER."""
    n = len(doms)
    ds = sorted(set(doms))
    T = 365 * EPOCH + final_window
    starts = np.arange(365) * EPOCH
    windows = [(s, s + EPOCH + OVER) for s in starts]
    windows.append((365 * EPOCH, 365 * EPOCH + final_window))
    k = t - f
    hits = 0
    for _ in range(trials):
        times = []                     # (time, set of custodians read)
        for i in range(n):
            m = rng.poisson(LAM_NODE * T / YEAR)
            times += [(x, {i}) for x in rng.uniform(0, T, m)]
        for d in ds:
            m = rng.poisson(LAM_DOM * T / YEAR)
            members = {i for i in range(n) if doms[i] == d}
            times += [(x, members) for x in rng.uniform(0, T, m)]
        exposed = False
        for a, b in windows:
            got = set()
            for x, s in times:
                if a <= x < b:
                    got |= s
            if len(got) >= k:
                exposed = True
                break
        hits += exposed
    pe = hits / trials
    z = 1.96
    den = 1 + z * z / trials
    c = (pe + z * z / (2 * trials)) / den
    h = z * math.sqrt(pe * (1 - pe) / trials + z * z / (4 * trials ** 2)) / den
    return pe, (max(0.0, c - h), c + h)


res = {"assumptions": {
    "node_breach_rate_per_year": LAM_NODE,
    "provider_shock_rate_per_year": LAM_DOM,
    "epoch_s": EPOCH, "overhead_s": OVER,
    "terminal_window_no_revocation_s": LEASE + HORIZON_H,
    "terminal_window_revoked_6h_s": 6 * HOUR,
    "domain": "provider (equal to home jurisdiction for the three providers)"},
    "rows": [], "validation": [], "sensitivity": []}

# --- exhaustive check of the generating function
for name in ("P1 (2,3) three providers", "P3 (3,5) balanced",
             "P2 (3,5) one provider"):
    t, eps = placements[name]
    doms = [PROVIDER[e] for e in eps]
    for ell in (EPOCH + OVER, LEASE + HORIZON_H):
        for k in range(1, len(doms) + 1):
            a = tail(pgf(None, doms, ell), k)
            b = enumerate_exact(doms, ell, k)
            res["validation"].append({"placement": name, "ell_s": ell, "k": k,
                                      "pgf": a, "enumeration": b,
                                      "abs_diff": abs(a - b)})
print("max |pgf - enumeration| =",
      max(v["abs_diff"] for v in res["validation"]))

# --- certificates and simulation per placement
for name, (t, eps) in placements.items():
    doms = [PROVIDER[e] for e in eps]
    for f in (0, 1):
        for term, win in (("no revocation", LEASE + HORIZON_H),
                          ("revoked at 6 h", 6 * HOUR)):
            U, re_, rf = certificate(t, doms, f, win)
            row = {"placement": name, "t": t, "n": len(eps), "f": f,
                   "terminal": term, "bound": U, "per_epoch": re_,
                   "terminal_epoch": rf}
            if term == "no revocation":
                pe, ci = simulate(t, doms, f, win, 20000)
                row.update(simulated=pe, wilson95=ci)
            res["rows"].append(row)
            print(row)

# --- sensitivity of the balanced (3,5) placement and of B4 to the rates
for name in ("P3 (3,5) balanced", "P4 (3,5) AWS-heavy", "B4 single custodian"):
    t, eps = placements[name]
    doms = [PROVIDER[e] for e in eps]
    base = (LAM_NODE, LAM_DOM)
    for mult in (0.5, 1, 2, 4):
        LAM_NODE, LAM_DOM = base[0] * mult, base[1] * mult
        U, _, _ = certificate(t, doms, 0, LEASE + HORIZON_H)
        res["sensitivity"].append({"placement": name, "rate_multiplier": mult,
                                   "bound_f0": U})
    LAM_NODE, LAM_DOM = base

with open(OUT + "/e8_exposure.json", "w") as fh:
    json.dump(res, fh, indent=1)
