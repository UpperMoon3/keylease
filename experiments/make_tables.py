"""LaTeX tables of the paper, generated from the JSON results."""
import json
import os

from common import OUT

TAB = os.path.join(os.path.dirname(__file__), "..", "..", "paper", "tables")
os.makedirs(TAB, exist_ok=True)


def w(name, s):
    open(os.path.join(TAB, name), "w").write(s)


# ------------------------------------------------------------- E1 matrix
e1 = json.load(open(OUT + "/e1_matrix.json"))
cols = ["B0", "B1", "B2", "B3", "B4", "L-bg", "L-strict"]
lines = []
for r in e1["rows"]:
    cells = []
    for c in cols:
        x = r[c]
        if x["recovered"]:
            cell = r"\textcolor{red!70!black}{\ding{55}}"
        else:
            cell = r"\textcolor{green!45!black}{\ding{51}}"
        if x["audit_entries"]:
            cell += r"\,$^{\ell}$"
        cells.append(cell)
    lines.append("%s & %s & %s\\\\" % (r["id"], r["scenario"].replace(
        "(t-1)", "($t{-}1$)").replace("(t)", "($t$)"), " & ".join(cells)))
w("matrix.tex", "\n".join(lines) + "\n")

# ------------------------------------------------------------- E2 crash
e2 = json.load(open(OUT + "/e2_crash.json"))
lines = []
for r in e2["two_phase"]:
    lines.append("(%d,%d,%d) & %s & %d & %d & %d & %d & %d & %d\\\\" % (
        r["t"], r["n"], r["w"], "all $n$" if r["prior"] == "all" else "$w$ only",
        r["cases"], r["pre"], r["post"], r["fail"], r["mismatch"],
        r["guarantee_violations"]))
tot = sum(r["cases"] for r in e2["two_phase"])
lines.append(r"\midrule")
lines.append(r"\multicolumn{2}{@{}l}{Total} & %d & %d & %d & %d & %d & %d\\" % (
    tot, sum(r["pre"] for r in e2["two_phase"]),
    sum(r["post"] for r in e2["two_phase"]),
    sum(r["fail"] for r in e2["two_phase"]),
    sum(r["mismatch"] for r in e2["two_phase"]),
    sum(r["guarantee_violations"] for r in e2["two_phase"])))
w("crash.tex", "\n".join(lines) + "\n")
naive = {}
for r in e2["naive"]:
    naive.setdefault((r["t"], r["n"], r["w"]), {})[r["order"]] = (
        len(r["lost_with_all_custodians_up"]), r["crash_points"])
lines = []
for (t, n, wq), d in naive.items():
    lines.append("(%d,%d,%d) & %d of %d & %d of %d\\\\" % (
        t, n, wq, d["mask-first"][0], d["mask-first"][1],
        d["quorum-first"][0], d["quorum-first"][1]))
w("naive.tex", "\n".join(lines) + "\n")

# ------------------------------------------------------------- E4 bench
e4 = json.load(open(OUT + "/e4_bench.json"))
p = e4["primitives_ms"]
order = ["Ed25519 sign", "Ed25519 verify", "X25519 exchange",
         "ML-KEM-768 keygen (OpenSSL)", "ML-KEM-768 encaps (OpenSSL)",
         "ML-KEM-768 decaps (OpenSSL)", "ML-DSA-65 sign (OpenSSL)",
         "ML-DSA-65 verify (OpenSSL)", "AES-256-GCM seal 1 KiB",
         "Shamir split 32 B (3,5)", "Shamir combine 32 B (3,5)",
         "Shamir split 32 B (7,11)", "Shamir combine 32 B (7,11)"]
w("prims.tex", "\n".join("%s & %.3f & %.3f--%.3f\\\\" % (
    k.replace("(OpenSSL)", "").strip(), p[k], p[k + "_q1"], p[k + "_q3"])
    for k in order) + "\n")
lines = []
for r in e4["operations"]:
    if r["history"] != 100:
        continue
    iq = lambda k: "%.2f {\\scriptsize[%.2f--%.2f]}" % (r[k], r[k + "_q1"],
                                                       r[k + "_q3"])
    lines.append("(%d,%d) & %s & %s & %s & %s & %s & %s & %s\\\\" % (
        r["t"], r["n"], "hybrid" if r["pq"] else "X25519",
        iq("unlock_ms"), "{:,}".format(r["unlock_bytes_up"] +
                                       r["unlock_bytes_down"]),
        iq("renew_ms"), "{:,}".format(r["renew_bytes"]), iq("rotate_ms"),
        "{:,}".format(r["rotate_bytes"])))
w("ops.tex", "\n".join(lines) + "\n")

# ------------------------------------------------------------- E6
e6 = json.load(open(OUT + "/e6_models.json"))
lines = []
for r in e6["placements"]:
    short = {"AWS Frankfurt": "AWS-FRA", "AWS Stockholm": "AWS-ARN",
             "AWS UAE": "AWS-UAE", "AWS Mumbai": "AWS-BOM",
             "AWS Virginia": "AWS-IAD", "AWS Tokyo": "AWS-NRT",
             "Hetzner Falkenstein": "Hz-FSN", "Hetzner Helsinki": "Hz-HEL",
             "Yandex Moscow": "Ya-MOW"}
    lines.append("%s & %s & %.0f & %.0f & %d / %d / %d & \\textbf{%d} & "
                 "\\textbf{%d}\\\\" % (
                     r["placement"].split(" ", 2)[0] + " " +
                     r["placement"].split(" ", 2)[1],
                     ", ".join(short[e] for e in r["endpoints"]),
                     r["net_median_ms"], r["net_p95_ms"],
                     r["jur_to_bypass_expiry"], r["prov_to_bypass_expiry"],
                     r["home_to_bypass_expiry"], r["effective_bypass"],
                     r["effective_deny"]))
w("placement.tex", "\n".join(lines) + "\n")
lines = []
for k, v in sorted(e6["rtt_summary"].items(), key=lambda kv: kv[1]["median"]):
    lines.append("%s & %s & %.1f & %.1f\\\\" % (k, v["jurisdiction"],
                                               v["median"], v["p95"]))
w("rtt.tex", "\n".join(lines) + "\n")
lk = {}
for r in e6["lockout_model"]:
    lk.setdefault(r["q_no_unlock_day"], {})[r["lease_h"]] = \
        r["expected_lockouts_per_year"]


def fmt(v):
    if v >= 0.1:
        return "%.1f" % v
    if v < 1e-6:
        return "$<10^{-6}$"
    e = int(f"{v:e}".split("e")[1])
    return "$%.1f\\times10^{%d}$" % (v / 10 ** e, e)


w("lockout.tex", "\n".join("%.1f\\%% & %s & %s & %s\\\\" % (
    q * 100, fmt(d[24]), fmt(d[72]), fmt(d[168])) for q, d in lk.items()) + "\n")
lines = []
for r in e6["daily_traffic"]:
    lines.append("(%d,%d) & %s & %s & %.0f\\\\" % (
        r["t"], r["n"], "hybrid" if r["pq"] else "X25519", r["mode"],
        r["daily_kib"]))
w("traffic.tex", "\n".join(lines) + "\n")
# ------------------------------------------------------------- E8
e8 = json.load(open(OUT + "/e8_exposure.json"))
by = {}
for r in e8["rows"]:
    by.setdefault(r["placement"], {})[(r["f"], r["terminal"])] = r


def sci(v):
    if v >= 0.01:
        return "%.3f" % v
    e = int(f"{v:e}".split("e")[1])
    return "$%.1f\\times10^{%d}$" % (v / 10 ** e, e)


lines = []
for name, d in by.items():
    a = d[(0, "no revocation")]
    lo, hi = a["wilson95"]
    lines.append("%s & %s & %s & %s & %s & %s\\\\" % (
        name.replace("B4 single custodian", "B4 (1,1)"),
        sci(a["bound"]), sci(a["simulated"]),
        "[%s, %s]" % (sci(lo), sci(hi)),
        sci(d[(0, "revoked at 6 h")]["bound"]),
        sci(d[(1, "no revocation")]["bound"])))
w("exposure.tex", "\n".join(lines) + "\n")
rows = [l for l in open(os.path.join(TAB, "prims.tex")).read().splitlines()
        if l.strip()]
half = (len(rows) + 1) // 2
right = rows[half:] + [" & & \\\\"]
w("prims2.tex", "\n".join(l.rstrip("\\").rstrip() + " & " +
                          r.rstrip("\\").rstrip() + "\\\\"
                          for l, r in zip(rows[:half], right)) + "\n")
print("tables written to", TAB)

# ------------------------------------------------------------- E9 (device)
k = {x["op"]: x for x in json.load(open(OUT + "/e9_keystore_run2.json"))
     if "op" in x}
ops9 = [("ECDSA P-256 sign, AFU key", "sign (AFU class)"),
        ("ECDSA P-256 sign, presence key", "sign (presence class)"),
        ("AES-256-GCM open $K_{\\mathsf{dev}}$", "AES-256-GCM open K_dev (32 B)"),
        ("AES-256-GCM seal $K_{\\mathsf{dev}}$", "AES-256-GCM seal K_dev (32 B)"),
        ("ECDSA P-256 key generation", "ECDSA P-256 keygen"),
        ("Key generation with attestation", "ECDSA P-256 keygen with attestation")]


def cell(b, suffix):
    for name, x in k.items():
        if name.startswith(b + " ") and (name.endswith(suffix) or
                                         name == b + " " + suffix):
            return "%.1f {\\scriptsize[%.1f--%.1f]}" % (
                x["median_ms"], x["q1_ms"], x["q3_ms"])
    return "---"


lines = ["%s & %s & %s\\\\" % (lab, cell("TEE", s), cell("StrongBox", s))
         for lab, s in ops9]
w("keystore.tex", "\n".join(lines) + "\n")


def med(b, s):
    return [x["median_ms"] for n_, x in k.items()
            if n_.startswith(b + " ") and n_.endswith(s)][0]


derived = []
for b in ("TEE", "StrongBox"):
    open_ = med(b, "open K_dev (32 B)")
    afu, pres = med(b, "sign (AFU class)"), med(b, "sign (presence class)")
    derived.append("%s & %.0f & %.0f & %.0f & %.0f & %.0f\\\\" % (
        b, open_ + 5 * afu, open_ + 5 * pres, open_ + afu, 5 * pres,
        15 * pres))
w("keystore_derived.tex", "\n".join(derived) + "\n")
print("E9 tables written")
