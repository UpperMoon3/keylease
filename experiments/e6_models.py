"""E6: analytical and Monte-Carlo models built on the measured data.

(a) unlock latency of custodian placements, from the RTT samples of E5
    (each round is a joint sample of all endpoints) and the CPU time of E4;
(b) placement analysis: how many jurisdictions an adversary must coerce to
    bypass expiry/revocation, and how many must fail to deny unlock;
(c) availability vs. lease-integrity trade-off for all (t, n), independent
    custodian faults;
(d) seizure-timeline model: probability that the adversary recovers the
    stored data as a function of its time-to-compromise;
(e) owner lockout model and daily custody traffic.

Parameters of (d) and (e) are assumptions, stated in the output; the paper
reports them as a sensitivity analysis, not as measurements.
"""
import itertools
import json
import math

import numpy as np

from common import OUT, HOUR, DAY

rng = np.random.default_rng(20261019)
rtt = json.load(open(OUT + "/e5_rtt_samples.json"))
bench = json.load(open(OUT + "/e4_bench.json"))
S = {k: np.array([x if x is not None else np.nan for x in v])
     for k, v in rtt["samples_ms"].items()}
JUR = {"AWS Frankfurt": "DE", "AWS Stockholm": "SE", "AWS UAE": "AE",
       "AWS Mumbai": "IN", "AWS Virginia": "US", "AWS Tokyo": "JP",
       "Hetzner Falkenstein": "DE", "Hetzner Helsinki": "FI",
       "Yandex Moscow": "RU", "Cloudflare anycast": "anycast",
       "Google anycast": "anycast"}
PROV = {k: k.split()[0] for k in JUR}
res = {"rtt_summary": {}}
for k, v in S.items():
    ok = v[~np.isnan(v)]
    res["rtt_summary"][k] = {"median": float(np.median(ok)),
                             "p95": float(np.percentile(ok, 95)),
                             "n": int(len(ok)), "jurisdiction": JUR[k]}

# ----------------------------------------------------------- (a) + (b)
HOME = {"AWS": "US", "Hetzner": "DE", "Yandex": "RU", "Cloudflare": "US",
        "Google": "US"}
# anycast endpoints are excluded from placements: their storage location is
# not pinned to the measured point of presence
PLACEMENTS = {
    "P1 (2,3) three providers": (2, ["AWS Frankfurt", "Hetzner Helsinki",
                                     "Yandex Moscow"]),
    "P2 (3,5) one provider": (3, ["AWS Frankfurt", "AWS Stockholm", "AWS UAE",
                                  "AWS Mumbai", "AWS Virginia"]),
    "P3 (3,5) balanced": (3, ["AWS Frankfurt", "AWS Stockholm",
                              "Hetzner Helsinki", "Hetzner Falkenstein",
                              "Yandex Moscow"]),
    "P4 (3,5) AWS-heavy": (3, ["AWS Frankfurt", "AWS UAE", "AWS Mumbai",
                               "Hetzner Helsinki", "Yandex Moscow"]),
    "P5 (4,7) balanced": (4, ["AWS Frankfurt", "AWS Stockholm", "AWS UAE",
                              "Hetzner Helsinki", "Hetzner Falkenstein",
                              "Yandex Moscow", "AWS Mumbai"]),
    "P6 (5,9) global": (5, ["AWS Frankfurt", "AWS Stockholm", "AWS UAE",
                            "AWS Mumbai", "AWS Tokyo", "AWS Virginia",
                            "Hetzner Helsinki", "Hetzner Falkenstein",
                            "Yandex Moscow"]),
}


def min_groups_to_reach(groups, k):
    """Smallest number of groups (jurisdictions / providers) whose custodians
    together number at least k."""
    sizes = sorted((sum(1 for g in groups if g == x) for x in set(groups)),
                   reverse=True)
    acc = 0
    for i, s in enumerate(sizes, 1):
        acc += s
        if acc >= k:
            return i
    return math.inf


cpu_unlock = {(r["t"], r["n"]): r["unlock_ms"] for r in bench["operations"]
              if r["pq"] and r["history"] == 100}
cpu_unlock[(4, 7)] = None
placements = []
for name, (t, eps) in PLACEMENTS.items():
    n = len(eps)
    M = np.stack([S[e] for e in eps], axis=1)          # rounds x n
    rounds_total = M.shape[0]
    M = M[~np.isnan(M).any(axis=1)]                    # drop rounds with a timeout
    net = np.sort(M, axis=1)[:, t - 1]                 # t-th fastest reply
    jur = [JUR[e] for e in eps]
    prov = [PROV[e] for e in eps]
    home = [HOME[PROV[e]] for e in eps]
    row = {"placement": name, "t": t, "n": n, "endpoints": eps,
           "rounds_used": int(M.shape[0]), "rounds_total": int(rounds_total),
           "net_median_ms": float(np.median(net)),
           "net_p95_ms": float(np.percentile(net, 95)),
           "slowest_needed_median_ms": float(np.median(M.max(axis=1))),
           "cpu_unlock_ms_python": cpu_unlock.get((t, n)),
           "jur_to_bypass_expiry": min_groups_to_reach(jur, t),
           "jur_to_deny_unlock": min_groups_to_reach(jur, n - t + 1),
           "prov_to_bypass_expiry": min_groups_to_reach(prov, t),
           "prov_to_deny_unlock": min_groups_to_reach(prov, n - t + 1),
           "home_to_bypass_expiry": min_groups_to_reach(home, t),
           "home_to_deny_unlock": min_groups_to_reach(home, n - t + 1)}
    row["effective_bypass"] = min(row["jur_to_bypass_expiry"],
                                  row["prov_to_bypass_expiry"],
                                  row["home_to_bypass_expiry"])
    row["effective_deny"] = min(row["jur_to_deny_unlock"],
                                row["prov_to_deny_unlock"],
                                row["home_to_deny_unlock"])
    placements.append(row)
    print(row)
res["placements"] = placements


# ------------------------------------------------------------------ (c)
def binom_tail(n, k, p):
    return sum(math.comb(n, j) * p ** j * (1 - p) ** (n - j)
               for j in range(k, n + 1))


trade = []
for n in range(1, 12, 2):
    for t in range(1, n + 1):
        for u in (1e-2, 1e-3):
            for p in (0.01, 0.05):
                trade.append({"t": t, "n": n, "u": u, "p": p,
                              "unavailable": 1 - binom_tail(n, t, 1 - u),
                              "expiry_bypass": binom_tail(n, t, p)})
res["tradeoff"] = trade

# ------------------------------------------------------------------ (d)
N = 200_000
SEIZURE = {"U_since_last_unlock": "Exp(mean 1 h)",
           "tau": "lognormal, median m, sigma 1.0",
           "owner_revocation": "with prob. q_aware, lognormal median 6 h, "
                               "sigma 1.0"}
U = rng.exponential(1 * HOUR, N)
Z = rng.standard_normal(N)
R = 6 * HOUR * np.exp(rng.standard_normal(N))
aware = rng.random(N)
medians = np.geomspace(0.25 * HOUR, 60 * DAY, 60)
curves = {}
for m in medians:
    tau = m * np.exp(1.0 * Z)
    out = {}
    out["B1 vs AFU tool"] = 1.0
    out["B1 + 72 h reboot vs AFU tool"] = float(np.mean(tau < 72 * HOUR))
    out["B2 vs passcode"] = 1.0
    for Lh in (24, 72, 168):
        for q in (0.0, 0.5):
            rev = aware < q
            ok = (tau < Lh * HOUR - U) & ~(rev & (R < tau))
            out["Lease L=%dh, q=%.1f" % (Lh, q)] = float(np.mean(ok))
    curves[float(m)] = out
points = {}
for mh in (24, 168):                    # exact evaluation at one day / one week
    tau = mh * HOUR * np.exp(1.0 * Z)
    rev = aware < 0.5
    points["%dh" % mh] = {
        "lease72_q0": float(np.mean(tau < 72 * HOUR - U)),
        "lease72_q05": float(np.mean((tau < 72 * HOUR - U) & ~(rev & (R < tau)))),
        "b1_reboot72": float(np.mean(tau < 72 * HOUR))}
res["seizure_points"] = points
print("seizure points", points)
res["seizure_model"] = {"assumptions": SEIZURE,
                        "median_tau_s": [float(m) for m in medians],
                        "curves": curves}

# ------------------------------------------------------------------ (e)
lock = []
for q in (0.005, 0.02, 0.05):
    for Lh in (24, 72, 168):
        k = math.ceil(Lh / 24)
        # a lockout needs k consecutive days without any device unlock
        lock.append({"q_no_unlock_day": q, "lease_h": Lh,
                     "expected_lockouts_per_year": 365 * (1 - q) * q ** k})
res["lockout_model"] = lock

opr = {(r["t"], r["n"], r["pq"]): r for r in bench["operations"]
       if r["history"] == 100}
traffic = []
for (t, n, pq), r in sorted(opr.items()):
    unlock_b = r["unlock_bytes_up"] + r["unlock_bytes_down"]
    for mode, unlocks in (("background", 5), ("strict", 40)):
        renews, rotations = 16, 1
        daily = unlocks * unlock_b + renews * r["renew_bytes"] + \
            rotations * r["rotate_bytes"]
        traffic.append({"t": t, "n": n, "pq": pq, "mode": mode,
                        "unlocks_per_day": unlocks, "renews_per_day": renews,
                        "rotations_per_day": rotations,
                        "unlock_bytes": unlock_b,
                        "renew_bytes": r["renew_bytes"],
                        "rotate_bytes": r["rotate_bytes"],
                        "daily_kib": daily / 1024})
res["daily_traffic"] = traffic
for x in traffic:
    print(x)
with open(OUT + "/e6_models.json", "w") as f:
    json.dump(res, f, indent=1)
