"""Figures of the paper, from the JSON results."""
import json
import os

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from common import OUT, HOUR, DAY

FIG = os.path.join(os.path.dirname(__file__), "..", "..", "paper", "figs")
os.makedirs(FIG, exist_ok=True)
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300",
     "#6250d6", "#e34948"]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({
    "font.family": "serif", "font.size": 8.5, "axes.edgecolor": MUTED,
    "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "legend.frameon": False, "lines.linewidth": 1.6})

m = json.load(open(OUT + "/e6_models.json"))
rtt = json.load(open(OUT + "/e5_rtt_samples.json"))

# ---------------------------------------------------- seizure model
sm = m["seizure_model"]
x = np.array(sm["median_tau_s"]) / HOUR
cur = sm["curves"]
keys = sorted(cur, key=float)
series = [
    ("B1 vs. AFU tool; B2 vs. passcode", "B1 vs AFU tool", MUTED, (0, (4, 2))),
    ("B1 + 72 h inactivity reboot vs. AFU tool",
     "B1 + 72 h reboot vs AFU tool", C[3], (0, (1, 1.5))),
    ("KeyLease, L = 24 h", "Lease L=24h, q=0.0", C[0], "-"),
    ("KeyLease, L = 72 h", "Lease L=72h, q=0.0", C[1], "-"),
    ("KeyLease, L = 7 d", "Lease L=168h, q=0.0", C[2], "-"),
    ("KeyLease, L = 72 h, owner revokes (q = 0.5)", "Lease L=72h, q=0.5",
     C[6], (0, (5, 1.5, 1, 1.5))),
]
fig, ax = plt.subplots(figsize=(6.2, 2.9))
for z, (label, k, col, ls) in enumerate(series):
    ax.plot(x, [cur[kk][k] for kk in keys], color=col, ls=ls, label=label,
            lw=2.6 if z == 1 else 1.6, zorder=10 if z == 1 else 2)
ax.set_xscale("log")
ax.set_xlabel("Median time from seizure to key-store use or passcode, "
              r"$\tau$ (hours)")
ax.set_ylabel("P(adversary recovers data)")
ax.set_ylim(-0.02, 1.04)
ax.set_xticks([1, 6, 24, 72, 168, 720])
ax.set_xticklabels(["1", "6", "24", "72", "168", "720"])
ax.legend(loc="lower left", fontsize=7.3)
fig.tight_layout()
fig.savefig(FIG + "/seizure_model.pdf")

# ---------------------------------------------------- unlock latency CDF
S = {k: np.array([v if v is not None else np.nan for v in vals])
     for k, vals in rtt["samples_ms"].items()}
fig, ax = plt.subplots(figsize=(6.2, 2.6))
for i, row in enumerate(m["placements"]):
    M = np.stack([S[e] for e in row["endpoints"]], axis=1)
    M = M[~np.isnan(M).any(axis=1)]
    lat = np.sort(np.sort(M, axis=1)[:, row["t"] - 1])
    ax.plot(lat, np.arange(1, len(lat) + 1) / len(lat), color=C[i],
            label=row["placement"])
ax.set_xlabel("Network time to the $t$-th custodian reply (ms), measured "
              "RTTs from a client in Kazakhstan")
ax.set_ylabel("CDF over rounds")
ax.legend(loc="lower right", fontsize=7.3)
fig.tight_layout()
fig.savefig(FIG + "/unlock_latency.pdf")

# ---------------------------------------------------- trade-off
fig, axes = plt.subplots(1, 2, figsize=(6.4, 2.7), sharey=True)
for ax, p in zip(axes, (0.01, 0.05)):
    for j, n in enumerate((3, 5, 7, 9, 11)):
        pts = [r for r in m["tradeoff"] if r["n"] == n and r["u"] == 1e-3
               and r["p"] == p]
        xs = [max(r["unavailable"], 1e-16) for r in pts]
        ys = [max(r["expiry_bypass"], 1e-16) for r in pts]
        ax.plot(xs, ys, "-o", color=C[j], ms=3.2, lw=1.0, label="n = %d" % n)
        for r, xx, yy in zip(pts, xs, ys):
            if (r["t"], n) in ((3, 5), (2, 3), (5, 9), (7, 11)):
                ax.annotate("(%d,%d)" % (r["t"], n), (xx, yy), fontsize=6.8,
                            color=INK, xytext=(4, 3), textcoords="offset points")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(1e-16, 1)
    ax.set_ylim(1e-16, 1)
    ax.set_title("custodian compromise p = %.2f" % p, fontsize=8.5)
    ax.set_xlabel("P(unlock unavailable), u = 0.001")
axes[0].set_ylabel("P(lease can be extended\nby colluding custodians)")
axes[1].legend(loc="lower left", fontsize=7)
fig.tight_layout()
fig.savefig(FIG + "/tradeoff.pdf")
print("figures written to", FIG)
